/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "tee_panic.h"
#include "tee_storage_api.h"
#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"
#include "com_protocol.h"
#include "opentee_internal_api.h"
#include "tee_time_api.h"

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object,
			      void *buffer,
			      size_t size,
			      size_t *count)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_transfer_data_persistent *transfer_s;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (object == NULL) {
		OT_LOG_ERR("TEE_ReadObjectData panics due object NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (buffer == NULL) {
		OT_LOG_ERR("TEE_ReadObjectData panics due buffer NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (count == NULL) {
		OT_LOG_ERR("TEE_ReadObjectData panics due count NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_ReadObjectData panics due object not persistant object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		//Note: Flag is also forced at the manager! In other word this check is duplicate.
		OT_LOG_ERR("TEE_ReadObjectData panics due missing rights (no TEE_DATA_FLAG_ACCESS_READ)");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	payload.size = sizeof(struct com_mrg_transfer_data_persistent) + size;
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("TEE_ReadObjectData out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	transfer_s = payload.data;
	transfer_s->objectIDLen = object->per_object.obj_id_len;
	memcpy(&((struct com_mrg_transfer_data_persistent *)payload.data)->objectID,
	       &object->per_object.obj_id, object->per_object.obj_id_len);
	transfer_s->dataPosition = object->per_object.data_position;
	transfer_s->dataSize = size;

	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_READ_OBJ_DATA,
				   &payload, &returnPayload);
	if (ret != TEE_SUCCESS) {
		goto err;
	}

	transfer_s = returnPayload.data;
	
	object->per_object.data_position = transfer_s->dataPosition;
	*count = transfer_s->dataSize;
	memcpy(buffer, (uint8_t *)returnPayload.data + sizeof(struct com_mrg_transfer_data_persistent), *count);

 err:
	free(payload.data);
	free(returnPayload.data);
	
	if (ret == TEE_ERROR_ACCESS_DENIED) {
		OT_LOG_ERR("TEE_ReadObjectData panics due access right violation");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		OT_LOG_ERR("TEE_ReadObjectData objectID not found");
		TEE_Panic(TEE_ERROR_ITEM_NOT_FOUND);
	}

	return ret;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object,
			       void *buffer,
			       size_t size)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result ret = TEE_SUCCESS;
	
	if (object == NULL) {
		OT_LOG_ERR("TEE_WriteObjectData panics due object NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (buffer == NULL) {
		OT_LOG_ERR("TEE_WriteObjectData panics due buffer NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_WriteObjectData panics due object not persistant object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	payload.size = sizeof(struct com_mrg_transfer_data_persistent) + size;
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("TEE_WriteObjectData out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	//Fill message
	((struct com_mrg_transfer_data_persistent *)payload.data)->objectIDLen =
		object->per_object.obj_id_len;
	memcpy(&((struct com_mrg_transfer_data_persistent *)payload.data)->objectID,
	       &object->per_object.obj_id, object->per_object.obj_id_len);
	((struct com_mrg_transfer_data_persistent *)payload.data)->dataPosition =
		object->per_object.data_position;
	((struct com_mrg_transfer_data_persistent *)payload.data)->dataSize = size;
	memcpy((uint8_t *)payload.data + sizeof(struct com_mrg_transfer_data_persistent),
	       buffer, size);

	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_WRITE_OBJ_DATA,
				   &payload, &returnPayload);
	if (ret != TEE_SUCCESS) {
		goto err;
	}
	
	object->per_object.data_position =
		((struct com_mrg_transfer_data_persistent *)returnPayload.data)->dataPosition;

 err:
	free(payload.data);
	free(returnPayload.data);
	
	if (ret == TEE_ERROR_ACCESS_DENIED) {
		OT_LOG_ERR("TEE_WriteObjectData panics due access right violation");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		OT_LOG_ERR("TEE_WriteObjectData objectID not found");
		TEE_Panic(TEE_ERROR_ITEM_NOT_FOUND);
	}

	return ret;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object,
				  size_t size)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result ret = TEE_SUCCESS;

	if (object == NULL) {
		OT_LOG_ERR("TEE_TruncateObjectData panics due object NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_TruncateObjectData panics due object not persistant object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	payload.size = sizeof(struct com_mrg_transfer_data_persistent);
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("TEE_TruncateObjectData out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	((struct com_mrg_transfer_data_persistent *)payload.data)->objectIDLen =
		object->per_object.obj_id_len;
	memcpy(&((struct com_mrg_transfer_data_persistent *)payload.data)->objectID,
	       &object->per_object.obj_id, object->per_object.obj_id_len);
	((struct com_mrg_transfer_data_persistent *)payload.data)->dataSize = size;
	((struct com_mrg_transfer_data_persistent *)payload.data)->dataPosition =
		object->per_object.data_position;
	
	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_TRUNCATE_OBJ_DATA,
				   &payload, &returnPayload);

	if (ret != TEE_SUCCESS) {
		goto err;
	}

	object->per_object.data_position =
		((struct com_mrg_transfer_data_persistent *)returnPayload.data)->dataPosition;

 err:
	free(payload.data);
	free(returnPayload.data);
	
	if (ret == TEE_ERROR_ACCESS_DENIED) {
		OT_LOG_ERR("TEE_TruncateObjectData panics due access right violation");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		OT_LOG_ERR("TEE_TruncateObjectData objectID not found");
		TEE_Panic(TEE_ERROR_ITEM_NOT_FOUND);
	}

	return ret;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object,
			      int32_t offset,
			      TEE_Whence whence)
{
	uint32_t begin;
	uint32_t end;
	uint32_t pos;
	TEE_ObjectInfo info;
	TEE_Result ret;
	
	if (object == NULL) {
		OT_LOG_ERR("TEE_SeekObjectData panics due object handle NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}  else if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_SeekObjectData panics due not a persistant object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	//TODO: Extract size query from TEE_GetObjectInfo1
	ret = TEE_GetObjectInfo1(object, &info);
	if (ret != TEE_SUCCESS) {
		return ret;
	}
	
	begin = 0;
	end = info.dataSize;
	pos = info.dataPosition;

	/* if whence is SEEK_CUR should stay as current pos */
	if (whence == TEE_DATA_SEEK_END)
		pos = end;
	else if (whence == TEE_DATA_SEEK_SET)
		pos = begin;

	pos += offset;

	/* check for underflow */
	if (pos < begin)
		pos = begin;

	if (pos > TEE_MAX_DATA_SIZE)
		return TEE_ERROR_OVERFLOW;

	object->per_object.data_position = pos;

	return TEE_SUCCESS;
}
