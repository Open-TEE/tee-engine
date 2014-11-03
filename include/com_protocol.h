/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
** Copyright (C) 2014 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#ifndef __COM_PROTOCOL_H__
#define __COM_PROTOCOL_H__

/*!
 * \file com_protocol.h
 * \brief
 *
 * Use com_recv_msg(), com_send_msg(), com_wait_and_recv_msg() functions, because there function
 * will add or remove and check transport information.
 * If message is corrupted, it will be discarted.
 *
 * Protocol format:
 *
 * |------------|---------------|---------------|---------------|
 * | Start bit	| Message	| Checksum	| Payload	|
 * | sequence	| length	| 64 bit	| arbitary	|
 * |  32 bit	| 32 bit	|		| length	|
 * |------------|---------------|---------------|---------------|
 *
 * Start bit sequence: Message starting with pre defined bit sequence
 * Message length: Payyload
 * Checksum: CRC32 checksum is calculated over payload
 * (TODO: calculate checksum: bit seq + msg len + payload)
 * Payload: actual message
 */

#include <stdint.h>
#include <limits.h>

#include "tee_shared_data_types.h"

/* Communication protocol message names */
#define COM_MSG_NAME_RESERVED 0x00 /* Zero is reserved */
#define COM_MSG_NAME_CA_INIT_CONTEXT 0x01
#define COM_MSG_NAME_OPEN_SESSION 0x02
#define COM_MSG_NAME_CREATED_TA 0x03
#define COM_MSG_NAME_INVOKE_CMD 0x04
#define COM_MSG_NAME_CLOSE_SESSION 0x05
#define COM_MSG_NAME_CA_FINALIZ_CONTEXT 0x06
#define COM_MSG_NAME_PROC_STATUS_CHANGE 0x07
#define COM_MSG_NAME_FD_ERR 0x08
#define COM_MSG_NAME_ERROR 0x09

/* Request is used internally */
#define COM_TYPE_QUERY 1
#define COM_TYPE_RESPONSE 0

#define TA_MAX_NAME_LEN 255

/*!
 * \brief The com_sender enum
 * Identify message sender.
 */
enum com_sender {
	com_sender_CA,
	com_sender_TA,
	com_sender_launcher,
	com_sender_manager,
	com_sender_force_enum_size = INT_MAX
};

/*!
 * \brief The com_msg_hdr struct
 * Message header is containing generic information, which is common for all messages
 */
struct com_msg_hdr
{
	uint64_t sess_id;
	enum com_sender sender_type; /* Not used by client nor TA */
	uint8_t msg_name;
	uint8_t msg_type;

} __attribute__((aligned));

/*
 * ## Message section start ##
 */

/*!
 * \brief The com_msg_ca_init_tee_conn struct
 * Register new CA connection to TEE (TEEC_InitializeContext).
 */
struct com_msg_ca_init_tee_conn
{
	struct com_msg_hdr msg_hdr;
	TEE_Result ret;
} __attribute__((aligned));

/*!
 * \brief The com_msg_open_session struct
 * CA is opening new connection to TA (TEEC_OpenSession).
 */
struct com_msg_open_session
{
	struct com_msg_hdr msg_hdr;
	char ta_so_name[TA_MAX_NAME_LEN];
	TEE_UUID uuid;
	TEE_Result return_code_create_entry;
	TEE_Result return_code_open_session;
	uint32_t return_origin;
	uint32_t sess_fd_to_caller;

	/* TODO: parameters */

} __attribute__((aligned));

/*!
 * \brief The com_msg_invoke_cmd struct
 * CA or TA is invoking command from TA (TEEC_InvokeCommand)
 */
struct com_msg_invoke_cmd
{
	struct com_msg_hdr msg_hdr;
	uint64_t session_id;
	TEE_Result return_code;
	uint32_t cmd_id;
	uint32_t return_origin;

	/* TODO: parameters */

} __attribute__((aligned));

/*!
 * \brief The com_msg_ta_created struct
 * Launcher is reporting launched TA PID. If PID is -1, something went wrong with launching
 * for example clone-function call failed.
 */
struct com_msg_ta_created
{
	struct com_msg_hdr msg_hdr;
	pid_t pid;
} __attribute__((aligned));

/*!
 * \brief The com_msg_close_session struct
 * CA or TA closing session (TEEC_CloseSession)
 */
struct com_msg_close_session
{
	struct com_msg_hdr msg_hdr;
	int should_ta_destroy;
} __attribute__((aligned));

/*!
 * \brief The com_msg_ca_finalize_constex struct
 * CA is closing connection to TEE (TEEC_FinalizeContext)
 */
struct com_msg_ca_finalize_constex
{
	struct com_msg_hdr msg_hdr;
	/* Empty */
} __attribute__((aligned));

/*!
 * \brief The com_msg_proc_status_change struct
 * Manager IO thread is reporting  to manager logic thread that some of child process
 * status has been changed.
 */
struct com_msg_proc_status_change
{
	struct com_msg_hdr msg_hdr;
	/* Empty */
} __attribute__((aligned));

/*!
 * \brief The com_msg_fd_err struct
 * Manager IO thread encountered fd error and reporting it to manager logic thread.
 */
struct com_msg_fd_err
{
	struct com_msg_hdr msg_hdr;
	void *proc_ptr;
	int err_no;
} __attribute__((aligned));

/*!
 * \brief The com_msg_gen_err struct
 * Generic error message.
 */
struct com_msg_error
{
	struct com_msg_hdr msg_hdr;
	TEE_Result ret;
	uint32_t ret_origin;
};

/*
 *  ## Message section end ##
 */

/*
 * Function for receiving and  sending messages
*/

/*!
 * \brief com_recv_msg
 * Read message from socket and malloc space for message. Function strip transport info and
 * verifys message. If function is interrupted by EINTR, function recall read function.
 * \param sockfd
 * \param msg Malloced from heap. It must free by function caller
 * \param msg_len Message lenght
 * \return 0 on success. -1 on fd error. 1 if message was partial or corrupted.
 * No space malloced, if return value is no 0
 */
int com_recv_msg(int sockfd, void **msg, int *msg_len);

/*!
 * \brief com_send_msg
 * Send message to socket. Function will add transport information begin of message.
 * \param sockfd
 * \param msg
 * \param msg_len
 * \return
 */
int com_send_msg(int sockfd, void *msg, int msg_len);

/*
 * Get-functions for accessing protocol base functionality.
 */
int com_get_msg_name(void *msg, uint8_t *msg_name);
int com_get_msg_type(void *msg, uint8_t *msg_type);
int com_get_msg_sess_id(void *msg, uint64_t *sess_id);

#endif /* __COM_PROTOCOL_H__ */
