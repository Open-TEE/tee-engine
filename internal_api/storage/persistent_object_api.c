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
#include <unistd.h>

#include "../../utils.h"
#include "../crypto/operation_handle.h"
#include "../tee_panic_api.h"
#include "../tee_storage_api.h"
#include "object_handle.h"
#include "storage_utils.h"

static TEE_Result request_ss_file(FILE **ss_file,
				  void *objectID,
				  size_t objectIDLen,
				  size_t flags,
				  uint8_t create_ss_file)
{
	char broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	TEE_Result tee_ret;
	int ret;

	/* TODO:
	 * Implementing these flags is needing "centralized" controll. There might
	 * different options for implementing these.
	 *
	 * One possibility might be use fctl() file locking. Those locks are "advisory"
	 * types.
	 *
	 * For TR, return NULL == TEE_ERROR_ACCESS_CONFLICT */
	if (flags & (TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE))
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Note (about TR): Same process can open multiple handles to same file, which
	 * should not be possbile! */

	/* Note (about TR): TEE_DATA_FLAG_WRITE_META is not also checked! */

	tee_ret = get_broken_tee_ss_file_name_with_path(objectID, objectIDLen, broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH);
	if (tee_ret != TEE_SUCCESS)
		return tee_ret;

	if (create_ss_file == CREATE_SS_FILE) {

		ret = access(broken_tee_name_with_path, F_OK);
		if (ret == 0 && !(flags & TEE_DATA_FLAG_OVERWRITE))
			return TEE_ERROR_ACCESS_CONFLICT;

		if (ret == 0 && remove(broken_tee_name_with_path) < 0)
			return TEE_ERROR_GENERIC;

		*ss_file = fopen(broken_tee_name_with_path, "w+b");
	} else {
		*ss_file = fopen(broken_tee_name_with_path, "rb+");
	}

	if (*ss_file == NULL)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
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
	uint32_t object_attr_size = 0;
	size_t i;

	if (gp_attrs == NULL)
		return object_attr_size;

	for (i = 0; i < gp_attrs->attrs_count; ++i) {
		if (!is_value_attribute(gp_attrs->attrs[i].attributeID))
			object_attr_size += gp_attrs->attrs[i].content.ref.length;
	}

	return object_attr_size + gp_attrs->attrs_count * sizeof(TEE_Attribute);
}

static TEE_Result create_persistent_handle(TEE_ObjectHandle *new_object,
					   TEE_ObjectHandle attributes,
					   uint32_t initial_data_len,
					   uint32_t flags,
					   void *objectID,
					   size_t objectIDLen,
					   FILE *ss_file)
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

		ret = TEE_PopulateTransientObject(*new_object, attributes->key->gp_attrs.attrs, attributes->key->gp_attrs.attrs_count);
		if (ret != TEE_SUCCESS)
			goto err;
	}

	(*new_object)->per_object.data_position = ftell(ss_file);
	if ((*new_object)->per_object.data_position == -1L)
		goto err_generic;

	/* Void operations like ss_file to new object. Change object to persisten object */
	if (attributes)
		(*new_object)->objectInfo.objectUsage = attributes->objectInfo.objectUsage;

	(*new_object)->objectInfo.handleFlags |= (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);
	(*new_object)->per_object.data_begin = (*new_object)->per_object.data_position - initial_data_len;
	//(*new_object)->per_object.data_size = initial_data_len + (*new_object)->per_object.data_begin;
	(*new_object)->per_object.data_size = (*new_object)->per_object.data_position;
	memcpy((*new_object)->per_object.obj_id, objectID, objectIDLen);
	(*new_object)->per_object.obj_id_len = objectIDLen;
	(*new_object)->per_object.file = ss_file;

	return TEE_SUCCESS;

err_generic:
	ret = TEE_ERROR_GENERIC;
err:
	free_object_handle(*new_object);
	(*new_object) = (TEE_ObjectHandle)NULL;
	return ret;
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID,
				    void *objectID,
				    uint32_t objectIDLen,
				    uint32_t flags,
				    TEE_ObjectHandle *object)
{
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
	 * Read persistant object file meta info from storage */
	if (fread(&object_meta_info, sizeof(struct ss_object_meta_info), 1, ss_file) != 1) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	ret = TEE_AllocateTransientObject(object_meta_info.info.objectType, object_meta_info.info.keySize, &new_object);
	if (ret != TEE_SUCCESS)
		goto err;

	/* Load object attributes */
	if (object_meta_info.attribute_count) {

		ret = load_attributes(&ss_file_gp_attributes, object_meta_info.attribute_count, ss_file);
		if (ret != TEE_SUCCESS)
			goto err;

		ret = TEE_PopulateTransientObject(new_object, ss_file_gp_attributes.attrs, ss_file_gp_attributes.attrs_count);
		if (ret != TEE_SUCCESS)
			goto err_and_free_gp_attrs;

		free_gp_attributes(&ss_file_gp_attributes);
	}

	/* Initialization/calculation of data position, size and data begin variables */
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

	/* Void operations like ss_file to new object */
	new_object->per_object.file = ss_file;
	memcpy(&new_object->objectInfo, &object_meta_info.info, sizeof(TEE_ObjectInfo));
	new_object->per_object.obj_id_len = object_meta_info.obj_id_len;
	memcpy(new_object->per_object.obj_id, object_meta_info.obj_id, object_meta_info.obj_id_len);

	new_object->objectInfo.handleFlags = 0; /* reset flags */
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
	struct ss_object_meta_info object_meta_info = {0};
	uint32_t object_attrs_size = 0;
	TEE_Result ret;
	FILE *ss_file;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL ||
	    objectIDLen > TEE_OBJECT_ID_MAX_LEN ||
	    attributes && !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) ||
	    attributes && attributes->objectInfo.objectType == TEE_TYPE_CORRUPTED_OBJECT)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (attributes)
		object_attrs_size = object_attribute_size(&attributes->key->gp_attrs);

	if (initialDataLen > (TEE_MAX_DATA_SIZE - object_attrs_size))
		TEE_Panic(TEE_ERROR_OVERFLOW);

	ret = request_ss_file(&ss_file, objectID, objectIDLen, flags, CREATE_SS_FILE);
	if (ret != TEE_SUCCESS)
		return ret;

	object_meta_info.data_begin = sizeof(struct ss_object_meta_info);

	if (attributes != NULL) {
		memcpy(&object_meta_info.info, &attributes->objectInfo, sizeof(TEE_ObjectInfo));
		object_meta_info.attribute_count = attributes->key->gp_attrs.attrs_count;
		object_meta_info.info.keySize = BYTE2BITS(attributes->key->key_lenght);
		object_meta_info.data_begin += object_attrs_size;
	} else {
		object_meta_info.info.objectType = TEE_TYPE_DATA;
	}

	memcpy(object_meta_info.obj_id, objectID, objectIDLen);
	object_meta_info.obj_id_len = objectIDLen;

	/* Meta info is filled. Write meta info to storage */
	if (fwrite(&object_meta_info, sizeof(struct ss_object_meta_info), 1, ss_file) != 1)
		goto err_generic;

	/* store attributes */
	if (attributes != NULL) {
		if (serialize_attributes_to_storage(attributes->key->gp_attrs.attrs, attributes->key->gp_attrs.attrs_count, ss_file))
			goto err_generic;
	}

	if (initialData != NULL) {
		if (fwrite(initialData, initialDataLen, 1, ss_file) != 1)
			goto err_generic;
	}

	if (fflush(ss_file) != 0)
		goto err_generic;

	if (object != NULL) {

		ret = create_persistent_handle(object, attributes, initialDataLen, flags, objectID, objectIDLen, ss_file);
		if (ret != TEE_SUCCESS)
			goto err;

	} else {
		release_ss_file(ss_file, objectID, objectIDLen);
	}

	return TEE_SUCCESS;

err_generic:
	ret = TEE_ERROR_GENERIC;
err:
	release_and_delete_ss_file(ss_file, objectID, objectIDLen);
	return ret;
}


TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
	if (object == NULL ||
	    !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
	    !(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	release_and_delete_ss_file(object->per_object.file, object->per_object.obj_id, object->per_object.obj_id_len);
	free_object_handle(object);
	return TEE_SUCCESS;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
				      void *newObjectID,
				      size_t newObjectIDLen)
{
	struct ss_object_meta_info object_meta_info = {0};
	char new_broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	char old_broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	TEE_Result ret;

	if (object == NULL ||
	    newObjectIDLen > TEE_OBJECT_ID_MAX_LEN ||
	    !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
	    !(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* Check if new ID is availible */
	ret = get_broken_tee_ss_file_name_with_path(newObjectID, newObjectIDLen, new_broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH);
	if (ret != TEE_SUCCESS)
		return ret;

	if (access(new_broken_tee_name_with_path, F_OK) != -1)
		return TEE_ERROR_ACCESS_CONFLICT;

	/* Check if new ID is availible */
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

	/* TODO: If flowing fails -> ss file corrupted */
	if (fwrite(&object_meta_info, sizeof(struct ss_object_meta_info), 1, object->per_object.file) != 1)
		goto err;

	/* TODO: If flowing fails -> ss file corrupted */
	if (fflush(object->per_object.file) != 0)
		goto err;

	/* TODO: If flowing fails -> ss file corrupted */
	if (fseek(object->per_object.file, object->per_object.data_position, SEEK_SET) != 0)
		return TEE_ERROR_GENERIC;

	/* TODO: If flowing fails -> ss file corrupted */
	if (rename(old_broken_tee_name_with_path, new_broken_tee_name_with_path) != 0)
		return TEE_ERROR_GENERIC;

	memcpy(object->per_object.obj_id, newObjectID, newObjectIDLen);
	object->per_object.obj_id_len = newObjectIDLen;

	return TEE_SUCCESS;

err:
	fseek(object->per_object.file, object->per_object.data_position, SEEK_SET);
	return TEE_ERROR_GENERIC;
}
