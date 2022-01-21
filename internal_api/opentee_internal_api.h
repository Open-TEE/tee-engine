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

#include "com_protocol.h"
#include "storage/object_handle.h"
#include "tee_data_types.h"
#include "tee_storage_api.h"

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
#define COM_MGR_CMD_ID_OBJECTINFO 0x10

#define COM_MGR_PERSISTENT_DATA_OBJECT 0xCD

struct com_mrg_open_persistent {
	char objectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	struct persistant_object per_object;//[IN]
	TEE_ObjectInfo info;//[OUT]
	uint32_t storageID;//[IN]
	uint32_t flags;//[IN]
	size_t objectIDLen;//[IN]
	uint32_t attrsSize;//[OUT](zeroable)
	//attributes: start at the end of struc (if attrsize > 0)
} __attribute__((aligned));

struct com_mrg_close_persistent {
	char objectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	uint32_t objectIDLen;//[IN]
} __attribute__((aligned));

struct com_mrg_create_persistent {
	uint8_t objectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	TEE_ObjectInfo info;//[OUT](filled)
	struct persistant_object perObj;//[OUT](filled)
	uint32_t keySize;//IN[IN]
	size_t objectIDLen;//[IN]
	uint32_t storageID;//[IN]
	uint32_t flags;//[IN]
	uint32_t initialDataLen;//[IN]
	size_t attributeSize;//[IN]
	size_t initialDataSize;//[IN]
	uint8_t data_object; //[IN]COM_MGR_PERSISTENT_DATA_OBJECT
	//attributes: start at the end of struct
	//initialData: start at the end of attributes
} __attribute__((aligned));

struct com_mrg_rename_persistent {
	uint8_t objectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	size_t objectIDLen;//[IN]
	char newObjectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	size_t newObjectIDLen;//[IN]
} __attribute__((aligned));

struct com_mrg_transfer_data_persistent {
	uint8_t objectID[TEE_OBJECT_ID_MAX_LEN];//[IN]
	size_t objectIDLen;//[IN]
	uint32_t dataPosition;//[IN]
	size_t dataSize;//[IN/OUT]
	//data: start at the end of struct [IN/OUT]
} __attribute__((aligned));

struct com_mrg_enum_command {
	uint32_t ID;
} __attribute__((aligned));

struct com_mrg_enum_command_next {
	uint32_t ID;
	char objectID[TEE_OBJECT_ID_MAX_LEN];
	size_t objectIDLen;
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

TEE_Result TEE_InvokeMGRCommand(uint32_t cancellationRequestTimeout,
				uint32_t commandID,
				struct com_mgr_invoke_cmd_payload *payload,
				struct com_mgr_invoke_cmd_payload *returnPayload);

#endif /*__OPENTEE_INTERNAL_CLIENT_API_H__*/
