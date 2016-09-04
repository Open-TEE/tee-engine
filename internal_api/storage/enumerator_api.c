/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
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

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

//#include "../../utils.h"
#include "../tee_panic.h"
#include "../tee_storage_api.h"
#include "storage_utils.h"

struct __TEE_ObjectEnumHandle {
	DIR *dir;
	char *ss_path;
};

static int is_directory_empty(char *dir_path)
{
	struct dirent *entry;
	int file_count = 0;
	DIR *dir;

	dir = opendir(dir_path);
	if (dir == NULL)
		return 1;

	while ((entry = readdir(dir)) != NULL) {
		++file_count;
		if (file_count > 2) {
			closedir(dir);
			return 0;
		}
	}

	closedir(dir);
	return 1;
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator)
{
	if (objectEnumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	*objectEnumerator = (TEE_ObjectEnumHandle)calloc(1, sizeof(struct __TEE_ObjectEnumHandle));
	if (*objectEnumerator == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

//	(*objectEnumerator)->ss_path = get_ss_path((uint32_t *)NULL);

	return TEE_SUCCESS;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	if (objectEnumerator->dir != NULL)
		closedir(objectEnumerator->dir);

	free(objectEnumerator);
	objectEnumerator = (TEE_ObjectEnumHandle)NULL;
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	if (objectEnumerator->dir != NULL)
		closedir(objectEnumerator->dir);

	objectEnumerator->dir = (DIR *)NULL;
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
					       uint32_t storageID)
{
	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (objectEnumerator->dir != NULL)
		TEE_ResetPersistentObjectEnumerator(objectEnumerator);

	if (is_directory_empty(objectEnumerator->ss_path))
		return TEE_ERROR_ITEM_NOT_FOUND;

	objectEnumerator->dir = opendir(objectEnumerator->ss_path);
	if (objectEnumerator->dir == NULL)
		TEE_Panic(TEE_ERROR_GENERIC);

	return TEE_SUCCESS;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo,
				       void *objectID,
				       uint32_t *objectIDLen)
{
	struct ss_object_meta_info object_meta_info = {0};
	char broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	struct dirent *entry;
	FILE *next_object = (FILE *)NULL;
	long end_pos;

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL || *objectIDLen < TEE_OBJECT_ID_MAX_LEN)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (objectEnumerator->dir == NULL)
		return TEE_ERROR_ITEM_NOT_FOUND; /* enumeration not started */

	/* Open next persistant object from storage */
	do {
		while ((entry = readdir(objectEnumerator->dir)) != NULL) {
			if (entry->d_name[0] == '.')
				continue;
			else
				break;
		}

		if (entry == NULL)
			return TEE_ERROR_ITEM_NOT_FOUND;

		snprintf(broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH, "%s/%s", objectEnumerator->ss_path, entry->d_name);

		next_object = fopen(broken_tee_name_with_path, "rb");

		if (next_object == NULL)
			continue;

		if (fread(&object_meta_info, sizeof(struct ss_object_meta_info), 1, next_object) == 1)
			break; /* Found object */

		memset(&object_meta_info, 0, sizeof(struct ss_object_meta_info));
		fclose(next_object);
		next_object = (FILE *)NULL;

	} while (next_object == NULL);

	/* Zero data position */
	object_meta_info.info.dataPosition = 0;
	object_meta_info.info.dataSize = 0;

	/* calculate data size */
	if (fseek(next_object, 0, SEEK_END) != 0)
		TEE_Panic(TEE_ERROR_GENERIC);

	end_pos = ftell(next_object);
	if (end_pos == -1L)
		TEE_Panic(TEE_ERROR_GENERIC);

	object_meta_info.info.dataSize = ftell(next_object) - object_meta_info.data_begin;

	if (next_object != NULL)
		fclose(next_object);

	memcpy(objectID, object_meta_info.obj_id, object_meta_info.obj_id_len);
	*objectIDLen = object_meta_info.obj_id_len;

	if (objectInfo)
		memcpy(objectInfo, &object_meta_info.info, sizeof(TEE_ObjectInfo));

	return TEE_SUCCESS;
}
