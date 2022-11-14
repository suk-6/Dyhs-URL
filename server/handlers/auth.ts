import { differenceInMinutes, addMinutes, subMinutes } from "date-fns";
import { Handler } from "express";
import passport from "passport";
import bcrypt from "bcryptjs";
import nanoid from "nanoid";
import uuid from "uuid/v4";
import axios from "axios";

import { CustomError } from "../utils";
import * as utils from "../utils";
import * as redis from "../redis";
import * as mail from "../mail";
import query from "../queries";
import env from "../env";

const authenticate = (
  type: "jwt" | "local" | "localapikey",
  error: string,
  isStrict = true
) =>
  async function auth(req, res, next) {
    if (req.user) return next();

    passport.authenticate(type, (err, user) => {
      if (err) return next(err);

      if (!user && isStrict) {
        throw new CustomError(error, 401);
      }

      if (user && isStrict && !user.verified) {
        throw new CustomError(
          "이 이메일은 인증되지 않았습니다. " +
            "회원가입하여 이메일을 인증하세요.",
          400
        );
      }

      if (user && user.banned) {
        throw new CustomError("이 웹 사이트를 사용할 수 없습니다.", 403);
      }

      if (user) {
        req.user = {
          ...user,
          admin: utils.isAdmin(user.email)
        };
        return next();
      }
      return next();
    })(req, res, next);
  };

export const local = authenticate(
  "local",
  "로그인 자격 증명이 잘못되었습니다."
);
export const jwt = authenticate("jwt", "허가되지 않음.");
export const jwtLoose = authenticate("jwt", "허가되지 않음.", false);
export const apikey = authenticate(
  "localapikey",
  "API key가 일치하지 않습니다.",
  false
);

export const cooldown: Handler = async (req, res, next) => {
  if (env.DISALLOW_ANONYMOUS_LINKS) return next();
  const cooldownConfig = env.NON_USER_COOLDOWN;
  if (req.user || !cooldownConfig) return next();

  const ip = await query.ip.find({
    ip: req.realIP.toLowerCase(),
    created_at: [">", subMinutes(new Date(), cooldownConfig).toISOString()]
  });

  if (ip) {
    const timeToWait =
      cooldownConfig - differenceInMinutes(new Date(), new Date(ip.created_at));
    throw new CustomError(
      `제한되었습니다. ${timeToWait}분 기다리시거나, 로그인하세요.`,
      400
    );
  }
  next();
};

export const recaptcha: Handler = async (req, res, next) => {
  if (env.isDev || req.user) return next();
  if (env.DISALLOW_ANONYMOUS_LINKS) return next();
  if (!env.RECAPTCHA_SECRET_KEY) return next();

  const isReCaptchaValid = await axios({
    method: "post",
    url: "https://www.google.com/recaptcha/api/siteverify",
    headers: {
      "Content-type": "application/x-www-form-urlencoded"
    },
    params: {
      secret: env.RECAPTCHA_SECRET_KEY,
      response: req.body.reCaptchaToken,
      remoteip: req.realIP
    }
  });

  if (!isReCaptchaValid.data.success) {
    throw new CustomError(
      "reCAPTCHA가 유효하지 않습니다. 다시 시도하세요.",
      401
    );
  }

  return next();
};

export const admin: Handler = async (req, res, next) => {
  if (req.user.admin) return next();
  throw new CustomError("허가되지 않음.", 401);
};

export const signup: Handler = async (req, res) => {
  const salt = await bcrypt.genSalt(12);
  const password = await bcrypt.hash(req.body.password, salt);

  const user = await query.user.add(
    { email: req.body.email, password },
    req.user
  );

  await mail.verification(user);

  return res.status(201).send({ message: "인증 이메일이 전송되었습니다." });
};

export const token: Handler = async (req, res) => {
  const token = utils.signToken(req.user);
  return res.status(200).send({ token });
};

export const verify: Handler = async (req, res, next) => {
  if (!req.params.verificationToken) return next();

  const [user] = await query.user.update(
    {
      verification_token: req.params.verificationToken,
      verification_expires: [">", new Date().toISOString()]
    },
    {
      verified: true,
      verification_token: null,
      verification_expires: null
    }
  );

  if (user) {
    const token = utils.signToken(user);
    req.token = token;
  }

  return next();
};

export const changePassword: Handler = async (req, res) => {
  const salt = await bcrypt.genSalt(12);
  const password = await bcrypt.hash(req.body.password, salt);

  const [user] = await query.user.update({ id: req.user.id }, { password });

  if (!user) {
    throw new CustomError(
      "비밀번호를 변경할 수 없습니다. 나중에 다시 시도하세요."
    );
  }

  return res
    .status(200)
    .send({ message: "비밀번호가 성공적으로 변경되었습니다." });
};

export const generateApiKey: Handler = async (req, res) => {
  const apikey = nanoid(40);

  redis.remove.user(req.user);

  const [user] = await query.user.update({ id: req.user.id }, { apikey });

  if (!user) {
    throw new CustomError(
      "API 키를 생성할 수 없습니다. 나중에 다시 시도하세요."
    );
  }

  return res.status(201).send({ apikey });
};

export const resetPasswordRequest: Handler = async (req, res) => {
  const [user] = await query.user.update(
    { email: req.body.email },
    {
      reset_password_token: uuid(),
      reset_password_expires: addMinutes(new Date(), 30).toISOString()
    }
  );

  if (user) {
    await mail.resetPasswordToken(user);
  }

  return res.status(200).send({
    message: "비밀번호 재설정 메일이 전송되었습니다."
  });
};

export const resetPassword: Handler = async (req, res, next) => {
  const { resetPasswordToken } = req.params;

  if (resetPasswordToken) {
    const [user] = await query.user.update(
      {
        reset_password_token: resetPasswordToken,
        reset_password_expires: [">", new Date().toISOString()]
      },
      { reset_password_expires: null, reset_password_token: null }
    );

    if (user) {
      const token = utils.signToken(user as UserJoined);
      req.token = token;
    }
  }
  return next();
};

export const signupAccess: Handler = (req, res, next) => {
  if (!env.DISALLOW_REGISTRATION) return next();
  return res.status(403).send({ message: "회원가입이 허용되지 않습니다." });
};

export const changeEmailRequest: Handler = async (req, res) => {
  const { email, password } = req.body;

  const isMatch = await bcrypt.compare(password, req.user.password);

  if (!isMatch) {
    throw new CustomError("비밀번호가 틀립니다.", 400);
  }

  const currentUser = await query.user.find({ email });

  if (currentUser) {
    throw new CustomError("이 이메일 주소를 사용할 수 없습니다.", 400);
  }

  const [updatedUser] = await query.user.update(
    { id: req.user.id },
    {
      change_email_address: email,
      change_email_token: uuid(),
      change_email_expires: addMinutes(new Date(), 30).toISOString()
    }
  );

  redis.remove.user(updatedUser);

  if (updatedUser) {
    await mail.changeEmail({ ...updatedUser, email });
  }

  return res.status(200).send({
    message: "확인 이메일이 전송되었습니다."
  });
};

export const changeEmail: Handler = async (req, res, next) => {
  const { changeEmailToken } = req.params;

  if (changeEmailToken) {
    const foundUser = await query.user.find({
      change_email_token: changeEmailToken
    });

    if (!foundUser) return next();

    const [user] = await query.user.update(
      {
        change_email_token: changeEmailToken,
        change_email_expires: [">", new Date().toISOString()]
      },
      {
        change_email_token: null,
        change_email_expires: null,
        change_email_address: null,
        email: foundUser.change_email_address
      }
    );

    redis.remove.user(foundUser);

    if (user) {
      const token = utils.signToken(user as UserJoined);
      req.token = token;
    }
  }
  return next();
};
