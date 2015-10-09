/*****************************************************************************
** Copyright (C) 2015 Intel Corporation                                     **
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

#ifndef __OPENTEE_MANAGER_STORAGE_API_H__
#define __OPENTEE_MANAGER_STORAGE_API_H__

#include "tee_storage_api.h"
#include "tee_object_handle.h"

extern TEE_UUID current_TA_uuid;

/* object handling */
TEE_Result MGR_TEE_OpenPersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
					uint32_t flags, TEE_ObjectHandle *object);
void MGR_TEE_CloseObject(TEE_ObjectHandle object);
TEE_Result MGR_TEE_CreatePersistentObject(uint32_t storageID, void *objectID, uint32_t objectIDLen,
					  uint32_t flags, TEE_ObjectHandle attributes,
					  void *initialData, size_t initialDataLen,
					  TEE_ObjectHandle *object);
TEE_Result MGR_TEE_RenamePersistentObject(TEE_ObjectHandle object,
					  void *newObjectID,
					  uint32_t newObjectIDLen);
void MGR_TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object);

/* object data handling */
TEE_Result MGR_TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size,
				  uint32_t *count);
TEE_Result MGR_TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size, uint8_t write_type);
TEE_Result MGR_TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size);
TEE_Result MGR_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence);

/* object enumeration */
TEE_Result MGR_TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator);
void MGR_TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);
void MGR_TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);
TEE_Result MGR_TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
						   uint32_t storageID);
TEE_Result MGR_TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
					   TEE_ObjectInfo *objectInfo, void *objectID,
					   uint32_t *objectIDLen);

#endif /*__OPENTEE_MANAGER_STORAGE_API_H__*/
