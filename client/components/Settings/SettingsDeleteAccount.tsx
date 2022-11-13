import { useFormState } from "react-use-form-state";
import React, { FC, useState } from "react";
import getConfig from "next/config";
import Router from "next/router";
import axios from "axios";

import { getAxiosConfig } from "../../utils";
import { Col, RowCenterV, RowCenterH } from "../Layout";
import Text, { H2, Span } from "../Text";
import { useMessage } from "../../hooks";
import { TextInput } from "../Input";
import { APIv2, Colors } from "../../consts";
import { Button } from "../Button";
import Icon from "../Icon";
import Modal from "../Modal";

const { publicRuntimeConfig } = getConfig();

const SettingsDeleteAccount: FC = () => {
  const [message, setMessage] = useMessage(1500);
  const [loading, setLoading] = useState(false);
  const [modal, setModal] = useState(false);
  const [formState, { password, label }] = useFormState<{ accpass: string }>(
    null,
    {
      withIds: true
    }
  );

  const onSubmit = async e => {
    e.preventDefault();
    if (loading) return;
    setModal(true);
  };

  const onDelete = async e => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    try {
      await axios.post(
        `${APIv2.Users}/delete`,
        { password: formState.values.accpass },
        getAxiosConfig()
      );
      Router.push("/logout");
    } catch (error) {
      setMessage(error.response.data.error);
    }
    setLoading(false);
  };

  return (
    <Col alignItems="flex-start" maxWidth="100%">
      <H2 mb={4} bold>
        계정 삭제
      </H2>
      <Text mb={4}>
        {publicRuntimeConfig.SITE_NAME}을 탈퇴하고 계정을 삭제합니다.
      </Text>
      <Text
        {...label("password")}
        as="label"
        mb={[2, 3]}
        fontSize={[15, 16]}
        bold
      >
        비밀번호:
      </Text>
      <RowCenterV as="form" onSubmit={onSubmit}>
        <TextInput
          {...password("accpass")}
          placeholder="비밀번호를 입력하세요"
          autocomplete="off"
          mr={3}
        />
        <Button color="red" type="submit" disabled={loading}>
          <Icon name={loading ? "spinner" : "trash"} mr={2} stroke="white" />
          삭제
        </Button>
      </RowCenterV>
      <Modal
        id="delete-account"
        show={modal}
        closeHandler={() => setModal(false)}
      >
        <>
          <H2 mb={24} textAlign="center" bold>
            계정 삭제
          </H2>
          <Text textAlign="center">
            모든 <b>URL</b>과 <b>통계</b>가 삭제됩니다. 삭제 후 복구는{" "}
            <Span bold>불가능</Span>합니다.
          </Text>
          <RowCenterH mt={44}>
            {loading ? (
              <>
                <Icon name="spinner" size={20} stroke={Colors.Spinner} />
              </>
            ) : message.text ? (
              <Text fontSize={15} color={message.color}>
                {message.text}
              </Text>
            ) : (
              <>
                <Button color="gray" mr={3} onClick={() => setModal(false)}>
                  취소
                </Button>
                <Button color="red" ml={3} onClick={onDelete}>
                  <Icon name="trash" stroke="white" mr={2} />
                  삭제
                </Button>
              </>
            )}
          </RowCenterH>
        </>
      </Modal>
    </Col>
  );
};

export default SettingsDeleteAccount;
