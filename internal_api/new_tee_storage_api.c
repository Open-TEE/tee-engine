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

#include "tee_panic.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_storage_api.h"


void TEE_GetObjectInfo1(TEE_ObjectHandle object,
						TEE_ObjectInfo *objectInfo)
{
	if (object == NULL || objectInfo == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	memset(objectInfo, 0, sizeof(TEE_ObjectInfo));
	memcpy(objectInfo, &object->objectInfo, sizeof(TEE_ObjectInfo));

	/* keySize */
	if (object->objectInfo.objectType != TEE_TYPE_DATA && object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)
		objectInfo->keySize = BYTE2BITS(object->key->key_lenght);
	else
		objectInfo->keySize = 0;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		objectInfo->maxObjectSize = objectInfo->keySize;
		objectInfo->dataPosition = object->per_object.data_position - object->per_object.data_begin;
		objectInfo->dataSize = object->per_object.data_size - object->per_object.data_begin;
	}
}

void TEE_RestrictObjectUsage1(TEE_ObjectHandle object,
							  uint32_t objectUsage)
{
	/* Not used by PKCS11TA */

	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					uint32_t attributeID,
					void *buffer,
					uint32_t *size)
{
	/* Not used by PKCS11TA */

	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID,
				       uint32_t *a,
				       uint32_t *b)
{
	/* Not used by PKCS11TA */

	return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;
/*
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		release_ss_file(object->per_object.file, (void *)object->per_object.obj_id, object->per_object.obj_id_len);
*/
	free_object_handle(object);
}
