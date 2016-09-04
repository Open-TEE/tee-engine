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

#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

#include "tee_panic.h"
#include "tee_storage_api.h"
#include "storage_utils.h"
#include "com_protocol.h"
#include "opentee_internal_api.h"
#include "tee_time_api.h"
#include "tee_logging.h"

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator)
{

	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_enum_command *enumParams;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	*objectEnumerator = calloc(1, sizeof(struct __TEE_ObjectEnumHandle));
	if (*objectEnumerator == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	payload.size = 0;

	retVal =
	    TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_OBJ_ENUM_ALLOCATE_PERSIST,
				 &payload, &returnPayload);

	if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
		enumParams = returnPayload.data;
		
		(*objectEnumerator)->ID = enumParams->ID;

		free(returnPayload.data);
	}

	return retVal;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;

	if (objectEnumerator == NULL)
		return;

	payload.size = sizeof(struct com_mrg_enum_command);
	payload.data = calloc(1, payload.size);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_OBJ_ENUM_FREE_PERSIST,
					      &payload, NULL);

		free(payload.data);
	}

	free(objectEnumerator);
	objectEnumerator = NULL;
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;
	
	if (objectEnumerator == NULL)
		return;

	payload.size = sizeof(struct com_mrg_enum_command);
	payload.data = calloc(1, payload.size);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				     COM_MGR_CMD_ID_OBJ_ENUM_RESET_PERSIST,
				     &payload, NULL);

		free(payload.data);
	}
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
					       uint32_t storageID)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	payload.size = sizeof(struct com_mrg_enum_command) + sizeof(storageID);
	payload.data = calloc(1, payload.size);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;
		memcpy((char *)payload.data + sizeof(struct com_mrg_enum_command),
		       &storageID,
		       sizeof(storageID));

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_OBJ_ENUM_START,
					      &payload, NULL);

		free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo,
				       void *objectID,
				       size_t *objectIDLen)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_enum_command_next *enumNext;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL)
		return TEE_ERROR_GENERIC;

	payload.size = sizeof(struct com_mrg_enum_command_next);
	payload.data = calloc(1, payload.size);

	if (payload.data) {
		enumNext = payload.data;
		enumNext->ID = objectEnumerator->ID;

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_OBJ_ENUM_GET_NEXT,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			enumNext = returnPayload.data;

			memcpy(objectID, enumNext->objectID, enumNext->objectIDLen);
			*objectIDLen = enumNext->objectIDLen;

			if (objectInfo)
				memcpy(objectInfo, &enumNext->info, sizeof(TEE_ObjectInfo));

			free(returnPayload.data);
		}

		free(payload.data);
	}

	return retVal;
}
