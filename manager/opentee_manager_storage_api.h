/*****************************************************************************
** Copyright (C) 2015 Intel Corporation					    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
**									    **
** Licensed under the Apache License, Version 2.0 (the "License");	    **
** you may not use this file except in compliance with the License.	    **
** You may obtain a copy of the License at				    **
**									    **
**	http://www.apache.org/licenses/LICENSE-2.0			    **
**									    **
** Unless required by applicable law or agreed to in writing, software	    **
** distributed under the License is distributed on an "AS IS" BASIS,	    **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and	    **
** limitations under the License.					    **
*****************************************************************************/

#ifndef __OPENTEE_MANAGER_STORAGE_API_H__
#define __OPENTEE_MANAGER_STORAGE_API_H__

#include "tee_internal_api.h"
#include "storage/object_handle.h"

extern TEE_UUID current_TA_uuid;


struct ss_object_meta_info {
	char obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	TEE_ObjectInfo info;
	size_t obj_id_len;
	uint32_t attribute_size;
	uint32_t attr_begin;
	uint32_t data_begin;
	uint32_t data_size;
};

/* object handling */
TEE_Result MGR_TEE_OpenPersistentObject(uint32_t storageID,
					void *objectID,
					size_t objectIDLen,
					uint32_t flags,
					void **attrs, uint32_t *attrSize,
					struct persistant_object *per_obj,
					TEE_ObjectInfo *objectInfo);


void MGR_TEE_CloseObject(void *objectID, uint32_t objectIDLen);

TEE_Result MGR_TEE_CreatePersistentObject(uint32_t storageID,
					  void *objectID,
					  size_t objectIDLen,
					  uint32_t flags,
					  void *attrs,
					  uint32_t attrSize,
					  uint8_t persistent_type,
					  TEE_ObjectInfo *info,
					  struct persistant_object *per_obj,
					  void *initialData,
					  size_t initialDataLen);


TEE_Result MGR_TEE_RenamePersistentObject(void *objectID, size_t objectIDLen,
					  void *newObjectID, size_t newObjectIDLen);

TEE_Result MGR_TEE_CloseAndDeletePersistentObject(void *objectID, size_t objectIDLen);

/* object data handling */
TEE_Result MGR_TEE_ReadObjectData(void *objectID, size_t objectIDLen,
				  void *buffer, size_t size,
				  uint32_t *count, size_t *pos);
TEE_Result MGR_TEE_WriteObjectData(void *objectID, size_t objectIDLen, void *buffer, size_t size, size_t *pos);
TEE_Result MGR_TEE_TruncateObjectData(void *objectID, size_t objectIDLen, size_t size, size_t *pos);
TEE_Result MGR_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence);

/* object enumeration */
TEE_Result MGR_TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator);
void MGR_TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);
void MGR_TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);
TEE_Result MGR_TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
						   uint32_t storageID);
TEE_Result MGR_TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
					   TEE_ObjectInfo *objectInfo, void *objectID,
					   size_t *objectIDLen);

TEE_Result MGR_TEE_GetObjectInfo1(void *objectID, size_t objectIDLen, uint32_t *dataSize);

#endif /*__OPENTEE_MANAGER_STORAGE_API_H__*/
