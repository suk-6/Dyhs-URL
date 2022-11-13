import { useFormState } from "react-use-form-state";
import { Flex } from "reflexbox/styled-components";
import React, { FC, useState } from "react";
import axios from "axios";

import { getAxiosConfig } from "../../utils";
import { useMessage } from "../../hooks";
import { TextInput } from "../Input";
import { APIv2 } from "../../consts";
import { Button } from "../Button";
import Text, { H2 } from "../Text";
import { Col } from "../Layout";
import Icon from "../Icon";

const SettingsPassword: FC = () => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useMessage(2000);
  const [formState, { password, label }] = useFormState<{ password: string }>(
    null,
    { withIds: true }
  );

  const onSubmit = async e => {
    e.preventDefault();
    if (loading) return;
    if (!formState.validity.password) {
      return setMessage(formState.errors.password);
    }
    setLoading(true);
    setMessage();
    try {
      const res = await axios.post(
        APIv2.AuthChangePassword,
        formState.values,
        getAxiosConfig()
      );
      formState.clear();
      setMessage(res.data.message, "green");
    } catch (err) {
      setMessage(err?.response?.data?.error || "Couldn't update the password.");
    }
    setLoading(false);
  };

  return (
    <Col alignItems="flex-start" maxWidth="100%">
      <H2 mb={4} bold>
        비밀번호 변경
      </H2>
      <Text mb={4}>새로운 비밀번호를 입력하세요.</Text>
      <Text
        {...label("password")}
        as="label"
        mb={[2, 3]}
        fontSize={[15, 16]}
        bold
      >
        새 비밀번호:
      </Text>
      <Flex as="form" onSubmit={onSubmit}>
        <TextInput
          {...password({
            name: "password",
            validate: value => {
              const val = value.trim();
              if (!val || val.length < 8) {
                return "비밀번호는 최소 8글자여야 합니다.";
              }
            }
          })}
          autocomplete="off"
          placeholder="새 비밀번호를 입력하세요."
          width={[1, 2 / 3]}
          mr={3}
          required
        />
        <Button type="submit" disabled={loading}>
          <Icon name={loading ? "spinner" : "refresh"} mr={2} stroke="white" />
          {loading ? "업데이트 중..." : "업데이트"}
        </Button>
      </Flex>
      <Text color={message.color} mt={3} fontSize={15}>
        {message.text}
      </Text>
    </Col>
  );
};

export default SettingsPassword;
