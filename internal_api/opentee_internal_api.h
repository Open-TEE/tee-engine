/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

#ifndef __OPENTEE_INTERNAL_CLIENT_API_H__
#define __OPENTEE_INTERNAL_CLIENT_API_H__

#include <stdint.h>

struct __TEE_ObjectEnumHandle {
	uint32_t ID;
};

#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "com_protocol.h"

/* ta to manager commands */

#define COM_MGR_CMD_ID_TEST_COMM 0x00

#define COM_MGR_CMD_ID_OPEN_PERSISTENT 0x01
#define COM_MGR_CMD_ID_CREATE_PERSISTENT 0x02
#define COM_MGR_CMD_ID_RENAME_PERSISTENT 0x03
#define COM_MGR_CMD_ID_CLOSE_OBJECT 0x04
#define COM_MGR_CMD_ID_CLOSE_AND_DELETE_PERSISTENT 0x05

#define COM_MGR_CMD_ID_OBJ_ENUM_ALLOCATE_PERSIST 0x06
#define COM_MGR_CMD_ID_OBJ_ENUM_FREE_PERSIST 0x07
#define COM_MGR_CMD_ID_OBJ_ENUM_RESET_PERSIST 0x08
#define COM_MGR_CMD_ID_OBJ_ENUM_START 0x09
#define COM_MGR_CMD_ID_OBJ_ENUM_GET_NEXT 0x0A

#define COM_MGR_CMD_ID_READ_OBJ_DATA 0x0B
#define COM_MGR_CMD_ID_WRITE_OBJ_DATA 0x0C
#define COM_MGR_CMD_ID_TRUNCATE_OBJ_DATA 0x0D
#define COM_MGR_CMD_ID_SEEK_OBJ_DATA 0x0E

#define COM_MGR_CMD_ID_WRITE_CREATE_INIT_DATA 0x0F



struct com_mrg_open_persistent {
	uint32_t storageID;
	uint32_t flags;
	char objectID[TEE_OBJECT_ID_MAX_LEN];
	uint32_t objectIDLen;
} __attribute__((aligned));

struct com_mrg_close_persistent {
	void *openHandleOffset;
} __attribute__((aligned));

struct com_mrg_create_persistent {
	uint32_t storageID;
	uint32_t flags;
	char objectID[TEE_OBJECT_ID_MAX_LEN];
	uint32_t objectIDLen;
	void *attributeHandleOffset;
} __attribute__((aligned));

struct com_mrg_rename_persistent {
	char newObjectID[TEE_OBJECT_ID_MAX_LEN];
	uint32_t newObjectIDLen;
	uint32_t newStorageID;
	void *objectHandleOffset;
} __attribute__((aligned));

struct com_mrg_rename_persistent_resp {
	uint32_t newStorageID;
} __attribute__((aligned));

struct com_mrg_transfer_data_persistent {
	uint32_t per_data_pos;
	uint32_t per_data_size;
	size_t dataSize;
	void *dataOffset;
} __attribute__((aligned));

struct com_mrg_enum_command {
	uint32_t ID;
} __attribute__((aligned));

struct com_mrg_enum_command_next {
	uint32_t ID;
	char objectID[TEE_OBJECT_ID_MAX_LEN];
	uint32_t objectIDLen;
	TEE_ObjectInfo info;
} __attribute__((aligned));

/** !brief
 * makes call to manager, with payloads to send and receive
 *
 * commandID - command to manager
 * payload - data to pass to command
 * returnPayload - if payload is returned, caller of this function need to free returnPayload->data
 * returnOrigin - error status from the command executed by manager
 */

TEE_Result TEE_InvokeMGRCommand(uint32_t cancellationRequestTimeout, uint32_t commandID,
				struct com_mgr_invoke_cmd_payload *payload,
				struct com_mgr_invoke_cmd_payload *returnPayload);

#endif /*__OPENTEE_INTERNAL_CLIENT_API_H__*/
