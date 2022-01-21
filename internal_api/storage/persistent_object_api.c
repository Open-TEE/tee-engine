/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.					    **
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/operation_handle.h"
#include "opentee_internal_api.h"
#include "tee_time_api.h"
#include "tee_panic.h"
#include "tee_storage_api.h"
#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"

static void inc_offset(unsigned char **mem_in, size_t offset)
{
	if (*mem_in != NULL) {
		*mem_in += offset;
	}
}

static size_t memcpy_ret_n(void *dest, void *src, size_t n)
{
	if (dest != NULL){
		memcpy(dest, src, n);
	}

	return n;
}

static TEE_Result deserialize_gp_attribute(unsigned char *mem_in,
					   struct gp_attributes *attributes)
{
	uint32_t n = 0;
	TEE_Attribute attr = {0};

	//Counter part: serialize_gp_attribute

	//Function will malloc gp_attribute buffers.
	//NOTE!!! NOT GP COMPLIENT. Buffer sizes are not maxObjectSizes!

	if (attributes == NULL && mem_in == NULL) {
		return TEE_SUCCESS;
	}
	
	memcpy_ret_n(&attributes->attrs_count, mem_in, sizeof(attributes->attrs_count));
	mem_in += sizeof(attributes->attrs_count);

	if (attributes->attrs_count == 0) {
		return TEE_SUCCESS;
	}

	attributes->attrs = calloc(attributes->attrs_count, sizeof(TEE_Attribute));
	if (attributes->attrs == NULL) {
		goto err;
	}

	for (n = 0; n < attributes->attrs_count; ++n) {
		memcpy_ret_n(&attributes->attrs[n].attributeID, mem_in, sizeof(attr.attributeID));
		mem_in += sizeof(attr.attributeID);
		
		if (is_value_attribute(attr.attributeID)) {
			memcpy_ret_n(&attributes->attrs[n].content.value.a, mem_in, sizeof(attr.content.value.a));
			mem_in += sizeof(attr.content.value.a);

			memcpy_ret_n(&attributes->attrs[n].content.value.b, mem_in, sizeof(attr.content.value.b));
			mem_in += sizeof(attr.content.value.b);
		} else {
			memcpy_ret_n(&attributes->attrs[n].content.ref.length, mem_in, sizeof(attr.content.ref.length));
			mem_in += sizeof(attr.content.ref.length);

			attributes->attrs[n].content.ref.buffer = calloc(1, attributes->attrs[n].content.ref.length);
			if (attributes->attrs[n].content.ref.buffer == NULL) {
				goto err;
			}

			memcpy_ret_n(attributes->attrs[n].content.ref.buffer,
				     mem_in, attributes->attrs[n].content.ref.length);
			mem_in += attributes->attrs[n].content.ref.length;
		}
	}

	return TEE_SUCCESS;
 err:
	free_gp_attributes(attributes);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static size_t serialize_gp_attribute(struct gp_attributes *attributes,
				     unsigned char *mem_in)
{
	TEE_Attribute *attr = NULL;
	uint32_t n = 0;
	size_t offset = 0;

	//If mem_in is NULL, functio serialization size
	//Note: using offset variable rather pointer arithmetic.

	//Strategy
	//
	// What (size of what)
	//################################
	//# attr count (sizeof)
	//#---------------------------------
	//# attrID     (sizeof)
	//#----------------------------------
	//# (if VALUE     else REF
	//#  a (sizeof)    |  lenght (sizeof)
	//#-----------------------
	//#  b (sizeof)    |  buffer (lenght)
	//#-----------------------------------
	//# attrID.. (as many as attr count)
	//#--...
	
	if (attributes == NULL) {
		return offset;
	}

	if (attributes->attrs_count == 0) {
		return offset;
	}

	offset += memcpy_ret_n(mem_in, &attributes->attrs_count, sizeof(attributes->attrs_count));
	inc_offset(&mem_in, sizeof(attributes->attrs_count));
	
	for (n = 0; n < attributes->attrs_count; ++n) {

		attr = &attributes->attrs[n];

		offset += memcpy_ret_n(mem_in, &attr->attributeID, sizeof(attr->attributeID));
		inc_offset(&mem_in, sizeof(attributes->attrs_count));

		if (is_value_attribute(attr->attributeID)) {
			offset += memcpy_ret_n(mem_in, &attr->content.value.a, sizeof(attr->content.value.a));
			inc_offset(&mem_in, sizeof(attr->content.value.a));

			offset += memcpy_ret_n(mem_in, &attr->content.value.b, sizeof(attr->content.value.b));
			inc_offset(&mem_in, sizeof(attr->content.value.b));
		} else {
			offset += memcpy_ret_n(mem_in, &attr->content.ref.length, sizeof(attr->content.ref.length));
			inc_offset(&mem_in, sizeof(attr->content.ref.length));

			offset += memcpy_ret_n(mem_in, attr->content.ref.buffer, attr->content.ref.length);
			inc_offset(&mem_in, attr->content.ref.length);
		}
	}

	return offset;
}

static TEE_Result create_persistent_handle(TEE_ObjectHandle *new_object,
					   TEE_ObjectHandle attributes,
					   uint32_t flags)
{
	uint32_t objectType = TEE_TYPE_DATA, maxObjectSize = 0;
	TEE_Result ret;

	if (attributes) {
		objectType = attributes->objectInfo.objectType;
		maxObjectSize = BYTE2BITS(attributes->key->key_lenght);
	}

	ret = TEE_AllocateTransientObject(objectType, maxObjectSize, new_object);
	if (ret != TEE_SUCCESS) {
		return ret;
	}

	if (attributes) {

		ret = TEE_PopulateTransientObject(*new_object,
						  attributes->key->gp_attrs.attrs,
						  attributes->key->gp_attrs.attrs_count);
		if (ret != TEE_SUCCESS) {
			goto err;
		}
	}

	/* Void operations like ss_file to new object. Change object to persisten object */
	if (attributes) {
		(*new_object)->objectInfo.objectUsage = attributes->objectInfo.objectUsage;
	}

	(*new_object)->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	return TEE_SUCCESS;

err:
	free_object_handle(*new_object);
	(*new_object) = (TEE_ObjectHandle)NULL;
	return ret;
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID,
				    void *objectID,
				    size_t objectIDLen,
				    uint32_t flags,
				    TEE_ObjectHandle *object)
{
	struct com_mrg_open_persistent *retOpenParams = NULL;
	struct com_mgr_invoke_cmd_payload payload = {}, returnPayload = {};
	TEE_ObjectHandle new_object = (TEE_ObjectHandle)NULL;
	struct gp_attributes ss_file_gp_attributes = {0};
	TEE_Result ret = TEE_SUCCESS;
	
	if (object == NULL || objectID == NULL || objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG_ERR("TEE_OpenPersistentObject: Object null OR objectID null OR objectIDLen too big\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (storageID != TEE_STORAGE_PRIVATE) {
		OT_LOG_ERR("TEE_OpenPersistentObject: Only supported storageID is TEE_STORAGE_PRIVATE\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Open object from storage to get the object info. Then we know object type */
	payload.size = sizeof(struct com_mrg_open_persistent);
	payload.data = calloc(1, payload.size);

	if (payload.data == NULL) {
		OT_LOG_ERR("Panicking due out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Create message: Fill and send (no init data) */
	((struct com_mrg_open_persistent *)payload.data)->storageID = storageID;
	((struct com_mrg_open_persistent *)payload.data)->flags = flags;
	((struct com_mrg_open_persistent *)payload.data)->objectIDLen = objectIDLen;
	memcpy(&((struct com_mrg_open_persistent *)payload.data)->objectID, (uint8_t *)objectID, objectIDLen);

	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_OPEN_PERSISTENT,
				   &payload, &returnPayload);
	if (ret != TEE_SUCCESS) {
		goto out;
	}

	retOpenParams = returnPayload.data;

	ret = TEE_AllocateTransientObject(retOpenParams->info.objectType,
					  retOpenParams->info.keySize, &new_object);
	if (ret != TEE_SUCCESS) {
		OT_LOG_ERR("TEE_OpenPersistentObject: Object alloc failed\n");
		goto out;
	}

	/* Might be a data object */
	if (retOpenParams->attrsSize > 0) {
		
		if (TEE_SUCCESS != deserialize_gp_attribute((uint8_t *)returnPayload.data +
							    sizeof(struct com_mrg_open_persistent),
							    &ss_file_gp_attributes)) {
			goto err;
		}

		// Function copies attributes to object buffers.
		ret = TEE_PopulateTransientObject(new_object,
						  ss_file_gp_attributes.attrs,
						  ss_file_gp_attributes.attrs_count);

		//Need to free due error handling simplicity.
		//Alloc done in deserialize_gp_attribute
		free_gp_attributes(&ss_file_gp_attributes);

		if (ret != TEE_SUCCESS) {
			OT_LOG_ERR("TEE_OpenPersistentObject: Object alloc failed\n");
			goto out;
		}
	}

	memcpy(&new_object->per_object, &retOpenParams->per_object, sizeof(struct persistant_object));
	memcpy(&new_object->objectInfo, &retOpenParams->info, sizeof(TEE_ObjectInfo));

	*object = new_object;
	goto out;

 err:
	close_persistan_object(objectID, objectIDLen);
	free_object_handle(new_object);
	*object = NULL;
 out:
	free(payload.data);
	free(returnPayload.data);

	return ret;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID,
				      void *objectID,
				      size_t objectIDLen,
				      uint32_t flags,
				      TEE_ObjectHandle attributes,
				      void *initialData,
				      uint32_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	/* serialize to manager */
	size_t messageSize = 0, attirbuteSize = 0;
	struct com_mgr_invoke_cmd_payload payload = {0}, returnPayload = {0};
	struct com_mrg_create_persistent *createParams, *respMsg;
	TEE_ObjectHandle tempHandle = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint8_t *mem_write_start = NULL;
	
	if (storageID != TEE_STORAGE_PRIVATE) {
		OT_LOG_ERR("Only supported storageID is TEE_STORAGE_PRIVATE\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	} else if (initialData == NULL && initialDataLen > 0) {
		OT_LOG_ERR("Initial data lenght greater than zero, but initalData pointer null\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

        /* Only vital checks */
        if (objectID == NULL) {
                OT_LOG_ERR("Panicking due objectID is NULL");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        } else if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
                OT_LOG_ERR("Panicking due objectID len too big");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        } else if (attributes && !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
                OT_LOG_ERR("Panicking due object not initilized");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        } else if (attributes && (attributes->objectInfo.objectType == TEE_TYPE_CORRUPTED_OBJECT)) {
                OT_LOG_ERR("Panicking due object corrupted");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);	
	} else if (attributes && (attributes->objectInfo.objectType == TEE_TYPE_DATA)) {
		OT_LOG_ERR("TEE_CreatePersistentObject panicking due attributes object is type TEE_TYPE_DATA\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	//Create message: Size
	messageSize = sizeof(struct com_mrg_create_persistent);
	messageSize += initialDataLen;
	if (attributes) {
		attirbuteSize = serialize_gp_attribute(&attributes->key->gp_attrs, NULL);
	}
	messageSize += attirbuteSize;
	
	//Create message: Malloc
	payload.size = messageSize;
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("TEE_CreatePersistentObject panic due out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}
	
	//Create message: Fill
	createParams = payload.data;

	((struct com_mrg_create_persistent *)payload.data)->attributeSize = attirbuteSize;
	((struct com_mrg_create_persistent *)payload.data)->storageID = storageID;
	((struct com_mrg_create_persistent *)payload.data)->flags = flags;
	((struct com_mrg_create_persistent *)payload.data)->objectIDLen = objectIDLen;
	memcpy(&((struct com_mrg_create_persistent *)payload.data)->objectID, (uint8_t *)objectID, objectIDLen);
	
	if (attributes) {
		mem_write_start = (uint8_t *)payload.data + sizeof(struct com_mrg_create_persistent);
		memcpy(&((struct com_mrg_create_persistent *)payload.data)->info, &attributes->objectInfo, sizeof(TEE_ObjectInfo));
		serialize_gp_attribute(&attributes->key->gp_attrs, mem_write_start);
	} else {
		createParams->data_object = COM_MGR_PERSISTENT_DATA_OBJECT;
	}

	if (initialData) {
		mem_write_start = (uint8_t *)payload.data + sizeof(struct com_mrg_create_persistent) + attirbuteSize;
		memcpy(mem_write_start, initialData, initialDataLen);
		createParams->initialDataLen = initialDataLen;
	} else {
		createParams->initialDataLen = 0;
	}
	
	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_CREATE_PERSISTENT,
				   &payload, &returnPayload);
				
	if (ret != TEE_SUCCESS) {
		goto out; //ret is TEE_ERROR_XXX
	}

	if (object == NULL) {
		close_persistan_object(objectID, objectIDLen);
		goto out; //ret == TEE_SUCCESS
	}

	//Resp message: Get
	respMsg = returnPayload.data;

	// Needed for initdata write or for return object */
	ret = create_persistent_handle(&tempHandle, attributes, flags);
	if (ret != TEE_SUCCESS) {
		//TODO: We do not have handle. Need to close file
		//TEE_CloseAndDeletePersistentObject1(tempHandle);
		goto out; //Ret some ERROR
	}

	memcpy(&tempHandle->per_object, &respMsg->perObj, sizeof(struct persistant_object));

	*object = tempHandle;

 out:
	free(returnPayload.data);
	free(payload.data);

	return ret;
}


TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result ret = TEE_ERROR_GENERIC;
	
	if (object == NULL) {
		return TEE_SUCCESS;
	}

	//Flags check will be forced by manager
	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_CloseAndDeletePersistentObject1 panics due not a persistan object");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG_ERR("TEE_CloseAndDeletePersistentObject1 panics due not opened with TEE_DATA_FLAG_ACCESS_WRITE_META");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	payload.size = sizeof(struct com_mrg_close_persistent);
	payload.data = calloc(1, payload.size);
	if (payload.data == NULL) {
		OT_LOG_ERR("TEE_CloseAndDeletePersistentObject1 panics due out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	((struct com_mrg_close_persistent *)payload.data)->objectIDLen = object->per_object.obj_id_len;
	memcpy(&((struct com_mrg_close_persistent *)payload.data)->objectID, &object->per_object.obj_id, object->per_object.obj_id_len);

	//TODO: Check return value;
	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_CLOSE_AND_DELETE_PERSISTENT, &payload,
				   &returnPayload);
	free(payload.data);
	
	free_object_handle(object);

	return ret;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
				      void *newObjectID,
				      size_t newObjectIDLen)
{
	struct com_mgr_invoke_cmd_payload payload = {}, returnPayload = {};	
	TEE_Result ret;

	// Only vital checks
        if (object == NULL) {
                OT_LOG_ERR("TEE_RenamePersistentObject panics due object is NULL");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        } else if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
                OT_LOG_ERR("TEE_RenamePersistentObject panics due newObjectIDLen len too big");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (newObjectID == NULL) {
		OT_LOG_ERR("TEE_RenamePersistentObject panics due newObjectID NULL");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG_ERR("TEE_RenamePersistentObject panics due object is not persistant");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG_ERR("TEE_RenamePersistentObject panics due object does not "
			   "sufficient permissions (missing TEE_DATA_FLAG_ACCESS_WRITE_META)");
                TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	payload.size = sizeof(struct com_mrg_rename_persistent);
	payload.data = calloc(1, payload.size);

	if (payload.data == NULL) {
		OT_LOG_ERR("Panicking due out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	// Create message: Fill and send (no init data)
	((struct com_mrg_rename_persistent *)payload.data)->objectIDLen =
		object->per_object.obj_id_len;
	memcpy(&((struct com_mrg_rename_persistent *)payload.data)->objectID,
	       &object->per_object.obj_id, object->per_object.obj_id_len);
	((struct com_mrg_rename_persistent *)payload.data)->newObjectIDLen = newObjectIDLen;
	memcpy(&((struct com_mrg_rename_persistent *)payload.data)->newObjectID,
	       newObjectID, newObjectIDLen);
	
	ret = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				   COM_MGR_CMD_ID_RENAME_PERSISTENT,
				   &payload, &returnPayload);
	if (ret != TEE_SUCCESS) {
		goto out;
	}
	
	memset(&object->per_object.obj_id, 0, TEE_OBJECT_ID_MAX_LEN);
	memcpy(&object->per_object.obj_id, newObjectID, newObjectIDLen);
	object->per_object.obj_id_len = newObjectIDLen;
 out:
	free(payload.data);
	
	return ret;
}
