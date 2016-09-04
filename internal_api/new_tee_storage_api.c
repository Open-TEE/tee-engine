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

#include <string.h>

#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_logging.h"
#include "tee_storage_api.h"
#include "tee_panic.h"


static TEE_Attribute *get_attr_from_arr(struct gp_attributes *gp_attrs,
					uint32_t attributeID)
{
	uint32_t i;

	for (i = 0; i < gp_attrs->attrs_count; ++i) {
		if (gp_attrs->attrs[i].attributeID == attributeID)
			return &gp_attrs->attrs[i];
	}

	return NULL;
}

static TEE_Result check_attribute_rights(TEE_ObjectHandle object,
					 uint32_t attributeID)
{
	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Object not initialized\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (!(attributeID & TEE_ATTR_FLAG_PUBLIC) &&
	    !(object->objectInfo.objectUsage & TEE_USAGE_EXTRACTABLE)) {
		OT_LOG(LOG_ERR, "Not axtractable attribute\n");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
			      TEE_ObjectInfo *objectInfo)
{
	if (object == NULL || objectInfo == NULL) {
		OT_LOG_ERR("Panicking due object or objectInfo NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	memset(objectInfo, 0, sizeof(TEE_ObjectInfo));
	memcpy(objectInfo, &object->objectInfo, sizeof(TEE_ObjectInfo));

	/* keySize */
	if (object->objectInfo.objectType != TEE_TYPE_DATA && object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		objectInfo->keySize = BYTE2BITS(object->key->key_lenght);
	} else {
		objectInfo->keySize = 0;
	}
	
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		objectInfo->maxObjectSize = objectInfo->keySize;

		//TODO: Fetch data position. Manager will keep track about position
		
		objectInfo->dataPosition = object->per_object.data_position - object->per_object.data_begin;
		objectInfo->dataSize = object->per_object.data_size - object->per_object.data_begin;
	}
}

TEE_Result TEE_RestrictObjectUsage1(TEE_ObjectHandle object,
			      uint32_t objectUsage)
{
	if (object == NULL) {
		return;
	}
	
	object->objectInfo.objectUsage &= objectUsage;
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					uint32_t attributeID,
					void *buffer,
					uint32_t *size)
{
	TEE_Result gp_rv = TEE_SUCCESS;
	TEE_Attribute *attr = NULL;

	/* Check input parameters */
	if (object == NULL || is_value_attribute(attributeID) || size == NULL) {
		OT_LOG(LOG_ERR, "Object handle NULL or Size is NULL or not a buffer attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	gp_rv = check_attribute_rights(object, attributeID);
	if (gp_rv != TEE_SUCCESS) {
		TEE_Panic(gp_rv); //Error msg log
	}

	attr = get_attr_from_arr(&object->key->gp_attrs, attributeID);
	if (attr == NULL) {
		OT_LOG_ERR("Attribute not found [%u]\n", attributeID);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	
	if (attr->content.ref.length > *size || attr->content.ref.buffer == NULL) {
		OT_LOG_STR("Attribute size is [%u]\n", attr->content.ref.length);
		*size = attr->content.ref.length;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Checks done and ok. Copy stuff */
	memcpy(buffer, attr->content.ref.buffer, attr->content.ref.length);
	*size = attr->content.ref.length;

	return gp_rv;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID,
				       uint32_t *a,
				       uint32_t *b)
{
	TEE_Result gp_rv = TEE_SUCCESS;
	TEE_Attribute *attr = NULL;

	/* Check input parameters */
	if (object == NULL || !is_value_attribute(attributeID)) {
		OT_LOG(LOG_ERR, "Object handle NULL or not a value attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	gp_rv = check_attribute_rights(object, attributeID);
	if (gp_rv != TEE_SUCCESS) {
		TEE_Panic(gp_rv); //Error logged
	}
	
	attr = get_attr_from_arr(&object->key->gp_attrs, attributeID);
	if (attr == NULL) {
		OT_LOG_ERR("Attribute not found [%u]\n", attributeID);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	
	/* Attribute found */

	if (a != NULL) {
		*a = attr->content.value.a;
	}
	
	if (b != NULL) {
		*b = attr->content.value.b;
	}
	
	return gp_rv;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		release_ss_file(object->per_object.storage_blob_id);

	free_object_handle(object);
}
