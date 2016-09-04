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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../crypto/operation_handle.h"
#include "../internal_api/opentee_internal_api.h"
#include "../internal_api/tee_time_api.h"
#include "../tee_panic.h"
#include "../tee_storage_api.h"
#include "object_handle.h"
#include "storage_utils.h"
#include "tee_logging.h"
#include "../opentee_storage_common.h"



static TEE_Result create_persistent_handle(TEE_ObjectHandle *new_object,
					   TEE_ObjectHandle attributes,
					   uint32_t initial_data_len,
					   uint32_t flags,
					   void *objectID,
					   size_t objectIDLen,
					   uint32_t new_blob_id)
{
	uint32_t objectType = TEE_TYPE_DATA, maxObjectSize = 0;
	TEE_Result ret;

	if (attributes) {
		objectType = attributes->objectInfo.objectType;
		maxObjectSize = BYTE2BITS(attributes->key->key_lenght);
	}

	ret = TEE_AllocateTransientObject(objectType, maxObjectSize, new_object);
	if (ret != TEE_SUCCESS)
		return ret;

	if (attributes) {

		ret = TEE_PopulateTransientObject(*new_object,
						  attributes->key->gp_attrs.attrs,
						  attributes->key->gp_attrs.attrs_count);
		if (ret != TEE_SUCCESS)
			goto err;
	}

	/* Void operations like ss_file to new object. Change object to persisten object */
	if (attributes)
		(*new_object)->objectInfo.objectUsage = attributes->objectInfo.objectUsage;

	(*new_object)->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);
	(*new_object)->per_object.data_begin = (*new_object)->per_object.data_position - initial_data_len;
	(*new_object)->per_object.data_size = (*new_object)->per_object.data_position;
	memcpy((*new_object)->per_object.obj_id, objectID, objectIDLen);
	(*new_object)->per_object.obj_id_len = objectIDLen;
	(*new_object)->per_object.storage_blob_id = new_blob_id;

	return TEE_SUCCESS;

err_generic:
	ret = TEE_ERROR_GENERIC;
err:
	free_object_handle(*new_object);
	(*new_object) = (TEE_ObjectHandle)NULL;
	return ret;
}

static int serialize_attributes_to_storage(TEE_Attribute *attrs,
					   uint32_t attrsCount,
					   FILE *ss_file)
{
	size_t i;

	/* Write attributes to storage (if there is attributes)
	 * Serilization strategy: for (i = 0; i < attributes count in obj; ++i)
	 *				write TEE_Attribute (struct) to file
	 *				if TEE_Attribute != value attribute
	 *					write attribute buffer to file
	 *
	 * if write should fail -> delete a whole file
	 * Note: load_attribute will deserialize from SS
	 */

	for (i = 0; i < attrsCount; i++) {

		if (fwrite(&attrs[i], sizeof(TEE_Attribute), 1, ss_file) != 1)
			return 1;

		if (is_value_attribute(attrs[i].attributeID))
			continue;

		if (fwrite(attrs[i].content.ref.buffer, attrs[i].content.ref.length, 1, ss_file) != 1)
			return 1;
	}

	return 0;
}

static TEE_Result load_attributes(struct gp_attributes *gp_attrs,
				  uint32_t gp_attrs_count,
				  FILE *ss_file)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t i;

	gp_attrs->attrs_count = gp_attrs_count;

	if (gp_attrs->attrs_count == 0) {
		gp_attrs->attrs = (TEE_Attribute *)NULL;
		return TEE_SUCCESS;
	}

	/* Alloc memory for attributes (pointers) */
	gp_attrs->attrs = (TEE_Attribute *)calloc(1, gp_attrs->attrs_count * sizeof(TEE_Attribute));
	if (gp_attrs->attrs == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < gp_attrs->attrs_count; ++i) {
		if (fread(&gp_attrs->attrs[i], sizeof(TEE_Attribute), 1, ss_file) != 1)
			goto err_generic;

		if (is_value_attribute(gp_attrs->attrs[i].attributeID))
			continue;

		gp_attrs->attrs[i].content.ref.buffer = calloc(1, gp_attrs->attrs[i].content.ref.length);
		if (gp_attrs->attrs[i].content.ref.buffer == NULL)
			goto err_out_of_mem;

		if (fread(gp_attrs->attrs[i].content.ref.buffer, gp_attrs->attrs[i].content.ref.length, 1, ss_file) != 1)
			goto err_generic;
	}

	return TEE_SUCCESS;

err_out_of_mem:
	ret = TEE_ERROR_OUT_OF_MEMORY;
err_generic:
	free_gp_attributes(gp_attrs);
	free(gp_attrs->attrs);
	return ret;
}

static uint32_t object_attribute_size(struct gp_attributes *gp_attrs)
{
	uint32_t object_attr_size = 0, i = 0;

	if (gp_attrs == NULL)
		return object_attr_size;

	for (i = 0; i < gp_attrs->attrs_count; ++i) {
		if (!is_value_attribute(gp_attrs->attrs[i].attributeID))
			object_attr_size += gp_attrs->attrs[i].content.ref.length;
	}

	return object_attr_size + gp_attrs->attrs_count * sizeof(TEE_Attribute);
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID,
				    void *objectID,
				    uint32_t objectIDLen,
				    uint32_t flags,
				    TEE_ObjectHandle *object)
{
	/*
	TEE_ObjectHandle new_object = (TEE_ObjectHandle)NULL;
	struct ss_object_meta_info object_meta_info = {0};
	TEE_Result ret = TEE_SUCCESS;
	FILE *ss_file = (FILE *)NULL;
	struct gp_attributes ss_file_gp_attributes = {0};

	if (object == NULL || objectID == NULL || objectIDLen > TEE_OBJECT_ID_MAX_LEN)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	ret = request_ss_file(&ss_file, objectID, objectIDLen, flags, NOT_CREATE_SS_FILE);
	if (ret != TEE_SUCCESS)
		return ret;

	/* Access granted.
	 * Read persistant object file meta info from storage
	if (fread(&object_meta_info, sizeof(struct ss_object_meta_info), 1, ss_file) != 1) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	ret = TEE_AllocateTransientObject(object_meta_info.info.objectType, object_meta_info.info.keySize, &new_object);
	if (ret != TEE_SUCCESS)
		goto err;

	/* Load object attributes
	if (object_meta_info.attribute_count) {

		ret = load_attributes(&ss_file_gp_attributes, object_meta_info.attribute_count, ss_file);
		if (ret != TEE_SUCCESS)
			goto err;

		ret = TEE_PopulateTransientObject(new_object, ss_file_gp_attributes.attrs, ss_file_gp_attributes.attrs_count);
		if (ret != TEE_SUCCESS)
			goto err_and_free_gp_attrs;

		free_gp_attributes(&ss_file_gp_attributes);
	}

	/* Initialization/calculation of data position, size and data begin variables
	new_object->per_object.data_begin = ftell(ss_file);
	if (new_object->per_object.data_begin == -1L) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_position = new_object->per_object.data_begin;
	if (fseek(ss_file, 0, SEEK_END) != 0) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_size = ftell(ss_file);
	if (fseek(ss_file, new_object->per_object.data_begin, SEEK_SET) != 0) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Void operations like ss_file to new object
	new_object->per_object.file = ss_file;
	memcpy(&new_object->objectInfo, &object_meta_info.info, sizeof(TEE_ObjectInfo));
	new_object->per_object.obj_id_len = object_meta_info.obj_id_len;
	memcpy(new_object->per_object.obj_id, object_meta_info.obj_id, object_meta_info.obj_id_len);

	new_object->objectInfo.handleFlags = 0; /* reset flags
	new_object->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	*object = new_object;

	return ret;

err_and_free_gp_attrs:
	free_gp_attributes(&ss_file_gp_attributes);
err:
	release_ss_file(ss_file, objectID, objectIDLen);
	free_object_handle(new_object);
	*object = (TEE_ObjectHandle)NULL;
	return ret;
	*/
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID,
				      void *objectID,
				      uint32_t objectIDLen,
				      uint32_t flags,
				      TEE_ObjectHandle attributes,
				      void *initialData,
				      uint32_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	/* serialize to manager */
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	struct com_mgr_invoke_cmd_payload payload = {0}, returnPayload = {0};
	size_t messageSize = offsetof(struct com_mrg_create_persistent, attributeHandleOffset);
	TEE_ObjectHandle tempHandle = NULL;
	struct com_mrg_create_persistent *createParams;
	struct ss_object_meta_info object_meta_info = {0};
	uint32_t object_attrs_size = 0;
	TEE_Result ret;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL ||
	    objectIDLen > TEE_OBJECT_ID_MAX_LEN ||
	    attributes && !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) ||
	    attributes && attributes->objectInfo.objectType == TEE_TYPE_CORRUPTED_OBJECT)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* Pre-check if object fits to storage: GP defines position in 32bit.. */
	if (attributes)
		object_attrs_size = object_attribute_size(&attributes->key->gp_attrs);

	if (initialDataLen > (TEE_MAX_DATA_SIZE - object_attrs_size))
		TEE_Panic(TEE_ERROR_OVERFLOW);

	if (attributes)
		messageSize += calculate_object_handle_size2(attributes);

	payload.size = messageSize;
	payload.data = calloc(1, payload.size);

	if (payload.data) {

		createParams = payload.data;
		createParams->storageID = storageID;
		createParams->flags = flags;
		memcpy(createParams->objectID, objectID, objectIDLen);
		createParams->objectIDLen = objectIDLen;
		if (attributes) {
			createParams->attrs_count = attributes->key->gp_attrs.attrs_count;
			pack_object_attrs(attributes, &createParams->attributeHandleOffset);
		} else {
			createParams->data_object = COM_MGR_PERSISTENT_DATA_OBJECT;
		}

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_CREATE_PERSISTENT,
					      &payload, &returnPayload);

		return TEE_SUCCESS;

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {

//			unpack_and_alloc_object_handle(&tempHandle, returnPayload.data);

			if (initialDataLen > 0) {

				/* TODO: should we check if succeeds or not */
//				retVal = write_object_data(tempHandle,
//							   initialData,
//							   initialDataLen,
//							   COM_MGR_CMD_ID_WRITE_CREATE_INIT_DATA);
			}

			if (object)
				*object = tempHandle;
			else
				TEE_CloseObject(tempHandle);

			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}

	if (object != NULL) {

		//ret = create_persistent_handle(object, attributes, initialDataLen, flags, objectID, objectIDLen, 0);
		if (ret != TEE_SUCCESS)
			goto err;

	}
//	/* Meta info is filled. Write meta info to storage */
//	if (fwrite(&object_meta_info, sizeof(struct ss_object_meta_info), 1, ss_file) != 1)
//		goto err_generic;

//	/* store attributes */
//	if (attributes != NULL) {
//		if (serialize_attributes_to_storage(attributes->key->gp_attrs.attrs, attributes->key->gp_attrs.attrs_count, ss_file))
//			goto err_generic;
//	}

	/* Create persistent handle if needed */

	/* Call data stream api for writing init data */

//	if (initialData != NULL) {
//		if (fwrite(initialData, initialDataLen, 1, ss_file) != 1)
//			goto err_generic;
//	}

//	if (fflush(ss_file) != 0)
//		goto err_generic;

	if (object != NULL) {

//		ret = create_persistent_handle(object, attributes, initialDataLen, flags, objectID, objectIDLen, ss_file);
//		if (ret != TEE_SUCCESS)
//			goto err;

	} else {
//		release_ss_file(ss_file, objectID, objectIDLen);
	}

	return TEE_SUCCESS;

//err_generic:
	//ret = TEE_ERROR_GENERIC;
err:
//	release_and_delete_ss_file(ss_file, objectID, objectIDLen);
	return ret;
}


TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
	if (object == NULL ||
	    !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
	    !(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

//	release_and_delete_ss_file(object->per_object.file, object->per_object.obj_id, object->per_object.obj_id_len);
	free_object_handle(object);
	return TEE_SUCCESS;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
				      void *newObjectID,
				      uint32_t newObjectIDLen)
{
	/*
	struct ss_object_meta_info object_meta_info = {0};
	char new_broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	char old_broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	TEE_Result ret;

	if (object == NULL ||
	    newObjectIDLen > TEE_OBJECT_ID_MAX_LEN ||
	    !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
	    !(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* Check if new ID is availible
	ret = get_broken_tee_ss_file_name_with_path(newObjectID, newObjectIDLen, new_broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH);
	if (ret != TEE_SUCCESS)
		return ret;

	if (access(new_broken_tee_name_with_path, F_OK) != -1)
		return TEE_ERROR_ACCESS_CONFLICT;

	/* Check if new ID is availible
	ret = get_broken_tee_ss_file_name_with_path(object->per_object.obj_id, object->per_object.obj_id_len,
					     old_broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH);
	if (ret != TEE_SUCCESS)
		return ret;

	fseek(object->per_object.file, 0, SEEK_SET);

	if (fread(&object_meta_info, sizeof(struct ss_object_meta_info), 1, object->per_object.file) != 1)
		goto err;

	memcpy(object_meta_info.obj_id, newObjectID, newObjectIDLen);
	object_meta_info.obj_id_len = newObjectIDLen;

	fseek(object->per_object.file, 0, SEEK_SET);

	/* TODO: If flowing fails -> ss file corrupted
	if (fwrite(&object_meta_info, sizeof(struct ss_object_meta_info), 1, object->per_object.file) != 1)
		goto err;

	/* TODO: If flowing fails -> ss file corrupted
	if (fflush(object->per_object.file) != 0)
		goto err;

	/* TODO: If flowing fails -> ss file corrupted
	if (fseek(object->per_object.file, object->per_object.data_position, SEEK_SET) != 0)
		return TEE_ERROR_GENERIC;

	/* TODO: If flowing fails -> ss file corrupted
	if (rename(old_broken_tee_name_with_path, new_broken_tee_name_with_path) != 0)
		return TEE_ERROR_GENERIC;

	memcpy(object->per_object.obj_id, newObjectID, newObjectIDLen);
	object->per_object.obj_id_len = newObjectIDLen;

	return TEE_SUCCESS;

err:
	fseek(object->per_object.file, object->per_object.data_position, SEEK_SET);
	return TEE_ERROR_GENERIC;
	*/
}
