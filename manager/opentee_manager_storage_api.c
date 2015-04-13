/*****************************************************************************
** Copyright (C) 2015 Intel                                                 **
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

#define _GNU_SOURCE

#include <string.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "tee_storage_api.h"
#include "tee_memory.h"
#include "tee_storage_common.h"
#include "tee_object_handle.h"
#include "tee_logging.h"
#include "tee_time_api.h" /*TEE_TIMEOUT_INFINITE*/
#include "com_protocol.h" /*MGR CMD IDs*/
#include "tee_internal_client_api.h"

#include "opentee_internal_api.h"
#include "opentee_storage_common.h"
#include "opentee_manager_storage_api.h"
#include "ext_storage_stream_api.h"

#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "tee_panic.h"
#include "tee_memory.h"
#include "tee_storage_common.h"
#include "tee_logging.h"

#include "tee_list.h"

TEE_UUID current_TA_uuid;

struct secure_storage_element {
	struct list_head list;
	uint32_t storage_blob_id;
	uint32_t opening_flags;
	uint32_t ref_count;
	uint32_t is_valid;
};

static struct list_head storage_element_head;


static void __attribute__((constructor)) storage_init()
{
	INIT_LIST(&storage_element_head);
}

static void add_storage_blob_id(uint32_t storage_blob_id, uint32_t flags)
{
	struct secure_storage_element *current = calloc(1, sizeof(struct secure_storage_element));
	current->storage_blob_id = storage_blob_id;
	current->opening_flags = flags;
	current->ref_count = 1;
	current->is_valid = 1;
	list_add_after(&current->list, &storage_element_head);
}


static struct secure_storage_element *get_storage_blob_element(uint32_t storage_blob_id)
{
	struct list_head *pos;
	struct secure_storage_element *current_element;

	LIST_FOR_EACH(pos, &storage_element_head)
	{
		current_element = LIST_ENTRY(pos, struct secure_storage_element, list);
		if (storage_blob_id == current_element->storage_blob_id)
			return current_element;
	}

	return NULL;
}

static void add_storage_blob_ref(uint32_t storage_blob_id)
{
	struct secure_storage_element *current_element = get_storage_blob_element(storage_blob_id);

	if (current_element)
		current_element->ref_count++;
}

static void remove_storage_blob_ref(uint32_t storage_blob_id)
{
	struct secure_storage_element *current_element = get_storage_blob_element(storage_blob_id);

	if (current_element) {
		current_element->ref_count--;
		if (current_element->ref_count == 0) {
			list_unlink(&current_element->list);
			if (current_element->is_valid)
				ext_close_storage_blob(current_element->storage_blob_id);
			free(current_element);
			return;
		}
	}
}

TEE_Result validate_object_handle(TEE_ObjectHandle object)
{
	TEE_Result result = TEE_SUCCESS;
	struct secure_storage_element *current_element;

	current_element = get_storage_blob_element(object->per_object.storage_blob_id);

	if (!current_element ||
	    !current_element->is_valid) {

		OT_LOG(LOG_ERR,	"Not a proper persistent object. Closed, returning corrupt\n");
		MGR_TEE_CloseObject(object);

		result = TEE_ERROR_CORRUPT_OBJECT;
	}
	return result;
}

static TEE_Result load_attributes(TEE_ObjectHandle obj)
{
	size_t i;

	if (obj == NULL || !IS_VALID_STORAGE_BLOB(obj->per_object.storage_blob_id)) {
		OT_LOG(LOG_ERR, "Something went wrong with persistent object attribute loading\n");
		return TEE_ERROR_GENERIC;
	}

	if (obj->attrs_count == 0) {
		obj->attrs = NULL;
		return TEE_SUCCESS;
	}

	/* Alloc memory for attributes (pointers) */
	obj->attrs = calloc(obj->attrs_count, sizeof(TEE_Attribute));
	if (obj->attrs == NULL) {
		OT_LOG(LOG_ERR, "Cannot load attributes, because out of memory\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (i = 0; i < obj->attrs_count; ++i) {
		if (ext_read_stream(obj->per_object.storage_blob_id, obj->per_object.data_begin,
				    &obj->attrs[i], sizeof(TEE_Attribute))
		    != sizeof(TEE_Attribute))
			goto err_at_read;

		obj->per_object.data_begin += sizeof(TEE_Attribute);

		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			obj->attrs[i].content.ref.buffer = calloc(1, obj->maxObjSizeBytes);
			if (obj->attrs[i].content.ref.buffer == NULL) {
				free_attrs(obj);
				free(obj->attrs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			if (ext_read_stream(obj->per_object.storage_blob_id,
					    obj->per_object.data_begin,
					    obj->attrs[i].content.ref.buffer,
					    obj->attrs[i].content.ref.length)
			    != obj->attrs[i].content.ref.length)
				goto err_at_read;

			obj->per_object.data_begin += obj->attrs[i].content.ref.length;
		}
	}

	return TEE_SUCCESS;

err_at_read:
	OT_LOG(LOG_ERR, "Error at fread\n");
	free_attrs(obj);
	free(obj->attrs);
	return TEE_ERROR_GENERIC;
}

static bool serialize_attributes_to_storage(TEE_ObjectHandle object,
					    uint32_t storage_blob_id, size_t *offset)
{
	size_t i;

	if (object == NULL)
		return true;

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id))
		return false;

	/* Write attributes to storage (if there is attributes)
	 * Serilization strategy: for (i = 0; i < attributes count in obj; ++i)
	 *				write TEE_Attribute (struct) to file
	 *				if TEE_Attribute != value attribute
	 *					write attribute buffer to file
	 *
	 * if write should fail -> delete a whole file
	 */

	for (i = 0; i < object->attrs_count; ++i) {
		if (ext_write_stream(storage_blob_id,
				     *offset, &object->attrs[i], sizeof(TEE_Attribute))
		    != sizeof(TEE_Attribute))
			return false;
		(*offset) +=  sizeof(TEE_Attribute);

		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (ext_write_stream(storage_blob_id, *offset,
					     object->attrs[i].content.ref.buffer,
					     object->attrs[i].content.ref.length)
			    != object->attrs[i].content.ref.length)
				return false;

			(*offset) +=  object->attrs[i].content.ref.length;
		}
	}

	return true;
}

static TEE_Result deep_copy_object(TEE_ObjectHandle *dst_obj, TEE_ObjectHandle src_obj)
{
	TEE_Result tee_ret = TEE_ERROR_OUT_OF_MEMORY;
	TEE_ObjectHandle cpy_obj;
	int attr_count;

	if (dst_obj == NULL)
		return TEE_ERROR_GENERIC;

	/* malloc for object handler and cpy that */
	cpy_obj = calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (cpy_obj == NULL)
		goto err_out_of_mem_1;

	/* Attributes are copied, if object is containing attributes. This is done, because
	 * pure data object is not containing attributes */
	if (src_obj != NULL && src_obj->attrs_count > 0) {
		attr_count = valid_obj_type_and_attr_count(src_obj->objectInfo.objectType);
		if (attr_count == -1) {
			tee_ret = TEE_ERROR_GENERIC;
			goto err_out_of_mem_2;
		}

		memcpy(cpy_obj, src_obj, sizeof(struct __TEE_ObjectHandle));

		/* Move single function*/
		/* Malloc for attribute pointers */
		cpy_obj->attrs = calloc(src_obj->attrs_count, sizeof(TEE_Attribute));
		if (cpy_obj->attrs == NULL)
			goto err_out_of_mem_2;

		/* Malloc space for attributes (attribute buffers) */
		switch (src_obj->objectInfo.objectType) {
		case TEE_TYPE_AES:
		case TEE_TYPE_DES:
		case TEE_TYPE_DES3:
		case TEE_TYPE_HMAC_MD5:
		case TEE_TYPE_HMAC_SHA1:
		case TEE_TYPE_HMAC_SHA224:
		case TEE_TYPE_HMAC_SHA256:
		case TEE_TYPE_HMAC_SHA384:
		case TEE_TYPE_HMAC_SHA512:
		case TEE_TYPE_GENERIC_SECRET:
		case TEE_TYPE_RSA_KEYPAIR:
                case TEE_TYPE_RSA_PUBLIC_KEY:
		case TEE_TYPE_DSA_PUBLIC_KEY:
		case TEE_TYPE_DSA_KEYPAIR:
			if (!malloc_for_attrs(cpy_obj, attr_count))
				goto err_out_of_mem_3;
			break;

		case TEE_TYPE_DH_KEYPAIR:
			/* -1, because DH contains one value attribute */
			if (!malloc_for_attrs(cpy_obj, attr_count - 1))
				goto err_out_of_mem_3;
			break;

		default:
			/* Should never get here */
			tee_ret = TEE_ERROR_GENERIC;
			goto err_out_of_mem_3;
		}

		copy_all_attributes(src_obj, cpy_obj);
	}

	*dst_obj = cpy_obj;

	return TEE_SUCCESS;

err_out_of_mem_3:
	free_object(cpy_obj);
err_out_of_mem_2:
	free(cpy_obj);
err_out_of_mem_1:
	OT_LOG(LOG_ERR, "Cannot malloc space for object\n");
	return tee_ret;
}

/************************************************************************************************
*												 *
*												 *
*												 *
*												 *
* ############################################################################################# *
* #											       # *
* #  ---------------------------------------------------------------------------------------  # *
* #  |										            |  # *
* #  | #    #   #  # ## I n t e r n a l   A P I   f u n c t i o n s ## #  #   #    #     # |  # *
* #  |										            |  # *
* #  ---------------------------------------------------------------------------------------  # *
* #											       # *
* ############################################################################################# *
*												 *
*												 *
*												 *
*												 *
************************************************************************************************/

void MGR_TEE_CloseObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		remove_storage_blob_ref(object->per_object.storage_blob_id);

	free_object(object);
	return;
}

TEE_Result MGR_TEE_OpenPersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
					uint32_t flags, TEE_ObjectHandle *object)
{
	TEE_ObjectHandle new_object = NULL;
	struct storage_obj_meta_data meta_info_from_storage;
	TEE_Result ret_val = TEE_SUCCESS;
	uint32_t storage_blob_id = 0;
	uint32_t original_opening_flags;
	struct secure_storage_element *current_element;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL\n");
		return TEE_ERROR_GENERIC;
	}

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	/* is already open, check that it is allowed to share */
	if (IS_VALID_STORAGE_BLOB(storage_blob_id)) {

		current_element = get_storage_blob_element(storage_blob_id);
		if (!current_element)
			return TEE_ERROR_GENERIC;

		original_opening_flags = current_element->opening_flags;

		if (flags == 0) {
			OT_LOG(LOG_ERR, "Open: (flags == 0) allowed only on first open\n");
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		if (original_opening_flags == 0) {
			OT_LOG(LOG_ERR, "Open: already open without flags\n");
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		if (original_opening_flags & TEE_DATA_FLAG_ACCESS_WRITE_META) {
			OT_LOG(LOG_ERR, "Open: already open with WRITE_META\n");
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		if ((flags & TEE_DATA_FLAG_ACCESS_READ) &&
		    !(flags & original_opening_flags & TEE_DATA_FLAG_SHARE_READ)) {
			OT_LOG(LOG_ERR, "Open: already open without SHARE_READ\n");
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		if ((flags & TEE_DATA_FLAG_ACCESS_WRITE) &&
		    !(flags & original_opening_flags & TEE_DATA_FLAG_SHARE_WRITE)) {
			OT_LOG(LOG_ERR, "Open: already open without SHARE_WHIRE\n");
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		add_storage_blob_ref(storage_blob_id);

	} else {
		/* not open yet, opening now */
		storage_blob_id = ext_open_storage_blob(objectID, objectIDLen, false);

		if (!IS_VALID_STORAGE_BLOB(storage_blob_id)) {
			/*OT_LOG(LOG_ERR, "Open: Access denied\n");*/
			return TEE_ERROR_ITEM_NOT_FOUND;
		}

		add_storage_blob_id(storage_blob_id, flags);
	}

	/* Access granted. Malloc space for new object handler */
	new_object = calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (new_object == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for object handler\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Read persistent object file meta info from storage and fill it new object */
	memset(&meta_info_from_storage, 0, sizeof(struct storage_obj_meta_data));

	if (ext_read_stream(storage_blob_id,
			    0, &meta_info_from_storage, sizeof(struct storage_obj_meta_data))
	    != sizeof(struct storage_obj_meta_data)) {
		OT_LOG(LOG_ERR, "Cannot read object meta data\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* also load_attributes(new_object) increases this */
	new_object->per_object.data_begin = sizeof(struct storage_obj_meta_data);

	if (meta_info_from_storage.obj_id_len > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "meta_info_from_storage.obj_id_len length too big\n");
		goto err;
	}

	memcpy(&new_object->objectInfo, &meta_info_from_storage.info, sizeof(TEE_ObjectInfo));
	new_object->attrs_count = meta_info_from_storage.attrs_count;
	new_object->per_object.obj_id_len = meta_info_from_storage.obj_id_len;
	memcpy(new_object->per_object.obj_id, meta_info_from_storage.obj_id,
	       meta_info_from_storage.obj_id_len);

	/* Reproduct/fill rest of object parameters */
	new_object->per_object.storage_blob_id = storage_blob_id;
	new_object->maxObjSizeBytes = keysize_in_bits(new_object->objectInfo.maxObjectSize);


	/* Load object attributes */
	ret_val = load_attributes(new_object);
	if (ret_val != TEE_SUCCESS)
		goto err;

	/* Initialization/calculation of data position, size and data begin variables */
	new_object->per_object.data_position = 0;


	new_object->per_object.data_size =
			ext_get_storage_blob_size(new_object->per_object.storage_blob_id)
			- new_object->per_object.data_begin;

	/* Handler flags update */
	new_object->objectInfo.handleFlags = 0; /* reset flags */
	new_object->objectInfo.handleFlags |=
	    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	*object = new_object;

	return ret_val;

err:
	remove_storage_blob_ref(storage_blob_id);

	free_object(new_object);
	*object = NULL;
	return ret_val;
}

TEE_Result MGR_TEE_CreatePersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
					  uint32_t flags, TEE_ObjectHandle attributes,
					  void *initialData, size_t initialDataLen,
					  TEE_ObjectHandle *object)
{
	struct storage_obj_meta_data meta_info_to_storage;
	TEE_Result result;
	uint32_t storage_blob_id;
	size_t begin = 0;
	struct secure_storage_element *current_element;

	TEE_ObjectHandle new_object;

	result = MGR_TEE_OpenPersistentObject(storageID, objectID, objectIDLen, flags, &new_object);

	if (result == TEE_SUCCESS) {

		MGR_TEE_CloseObject(new_object);
		if (!(flags & (TEE_DATA_FLAG_OVERWRITE | TEE_DATA_FLAG_EXCLUSIVE))) {
			/* it is already existing, we don't have right to over write */
			return TEE_ERROR_ACCESS_CONFLICT;
		}

		storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);
		current_element = get_storage_blob_element(storage_blob_id);
		if (current_element)
			current_element->is_valid = 0;

		ext_delete_storage_blob(storage_blob_id, objectID, objectIDLen);

	} else if (result != TEE_ERROR_ITEM_NOT_FOUND) {
		return result;
	}

	storage_blob_id = ext_open_storage_blob(objectID, objectIDLen, true);
	add_storage_blob_id(storage_blob_id, flags);

	if (attributes != NULL &&
	    !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "CAnnot create a persistent object from uninitialised object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Access has been granted. Fill needed info for object storing */
	memset(&meta_info_to_storage, 0, sizeof(struct storage_obj_meta_data));

	if (attributes != NULL) {
		memcpy(&meta_info_to_storage.info, &attributes->objectInfo, sizeof(TEE_ObjectInfo));
		meta_info_to_storage.attrs_count = attributes->attrs_count;
	} else {
		meta_info_to_storage.attrs_count = 0;
	}

	meta_info_to_storage.meta_size =
	    sizeof(struct storage_obj_meta_data) + object_attribute_size(attributes);

	memcpy(meta_info_to_storage.obj_id, objectID, objectIDLen);
	meta_info_to_storage.obj_id_len = objectIDLen;

	/* Meta info is filled. Write meta info to storage */
	if (ext_write_stream(storage_blob_id,
			     begin, &meta_info_to_storage, sizeof(meta_info_to_storage))
	    != sizeof(meta_info_to_storage))
		goto err_at_meta_or_init_data_write;
	begin += sizeof(meta_info_to_storage);

	/* store attributes */
	if (!serialize_attributes_to_storage(attributes, storage_blob_id, &begin))
		goto err_at_meta_or_init_data_write;



	if (initialData != NULL) {
		if (ext_write_stream(storage_blob_id,
				     begin, initialData, initialDataLen) != initialDataLen)
			goto err_at_meta_or_init_data_write;
	}

	if (object != NULL) {
		result = deep_copy_object(object, attributes);
		if (result != TEE_SUCCESS)
			goto err_at_obj_alloc;

		/* update current state to allocated handle */
		(*object)->objectInfo.handleFlags = 0; /* reset flags */
		(*object)->objectInfo.handleFlags |=
		    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

		(*object)->per_object.data_position = initialDataLen;

		(*object)->per_object.data_begin = begin;

		(*object)->per_object.data_size = initialDataLen;

		/* Cpy obj ID to alloceted object */
		memcpy((*object)->per_object.obj_id, objectID, objectIDLen);
		(*object)->per_object.obj_id_len = objectIDLen;

		/* sign storage "location"(=file) */
		(*object)->per_object.storage_blob_id = storage_blob_id;

	} else {
		remove_storage_blob_ref(storage_blob_id);
		ext_close_storage_blob(storage_blob_id);
	}

	return TEE_SUCCESS;

err_at_meta_or_init_data_write:
	OT_LOG(LOG_ERR, "Error with write\n");
	ext_delete_storage_blob(storage_blob_id, objectID, objectIDLen);
	return TEE_ERROR_STORAGE_NO_SPACE;

err_at_obj_alloc:
	OT_LOG(LOG_ERR, "Cannot alloc object\n");
	ext_delete_storage_blob(storage_blob_id, objectID, objectIDLen);
	(*object) = NULL;
	if (result == TEE_ERROR_OUT_OF_MEMORY)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_ERROR_GENERIC;
}

TEE_Result MGR_TEE_RenamePersistentObject(TEE_ObjectHandle object, void *newObjectID,
					  size_t newObjectIDLen)
{
	struct storage_obj_meta_data meta_info_to_storage;
	TEE_Result result;
	size_t bytes;

	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL or not persistent object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "TEE_RenamePerObj: No rights\n");
		return TEE_ERROR_BAD_STATE;
	}
	result = validate_object_handle(object);

	if (result != TEE_SUCCESS)
		return result;


	if (!ext_change_object_ID(object->per_object.storage_blob_id,
				  object->per_object.obj_id, object->per_object.obj_id_len,
				  newObjectID, newObjectIDLen)) {
		OT_LOG(LOG_ERR, "Access conflict: ID exists\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	bytes = ext_read_stream(object->per_object.storage_blob_id,
				0, &meta_info_to_storage, sizeof(meta_info_to_storage));
	if (bytes != sizeof(meta_info_to_storage)) {
		OT_LOG(LOG_ERR, "rename done: not able to read metadata\n");
		return TEE_ERROR_GENERIC;
	}
	memset(meta_info_to_storage.obj_id, 0, sizeof(meta_info_to_storage.obj_id));
	memcpy(meta_info_to_storage.obj_id, newObjectID, newObjectIDLen);
	meta_info_to_storage.obj_id_len = newObjectIDLen;
	bytes = ext_write_stream(object->per_object.storage_blob_id,
				 0, &meta_info_to_storage, sizeof(meta_info_to_storage));
	if (bytes != sizeof(meta_info_to_storage)) {
		OT_LOG(LOG_ERR, "rename done: not able to write metadata\n");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

void MGR_TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	struct secure_storage_element *current_element;

	if (object == NULL)
		return;

	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "Not a persistent object\n");
		return;
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "TEE_CloAndDelPerObj: No rights\n");
		return;
	}

	if (validate_object_handle(object)) {
		OT_LOG(LOG_ERR, "TEE_CloAndDelPerObj: Close and delete for corrupted handle\n");
		return;
	}

	current_element = get_storage_blob_element(object->per_object.storage_blob_id);
	if (current_element)
		current_element->is_valid = 0;

	remove_storage_blob_ref(object->per_object.storage_blob_id);
	ext_delete_storage_blob(object->per_object.storage_blob_id,
				object->per_object.obj_id, object->per_object.obj_id_len);

	free_object(object);
}

TEE_Result MGR_TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator)
{
	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	*objectEnumerator = calloc(1, sizeof(struct __TEE_ObjectEnumHandle));
	if (*objectEnumerator == NULL)
		goto error;

	if (!ext_alloc_for_enumerator(&(*objectEnumerator)->ID))
		goto error;

	return TEE_SUCCESS;

error:
	free(*objectEnumerator);
	*objectEnumerator = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
}

void MGR_TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	ext_free_enumerator(objectEnumerator->ID);

	free(objectEnumerator);
	objectEnumerator = NULL;
}

void MGR_TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	ext_reset_enumerator(objectEnumerator->ID);
}

TEE_Result MGR_TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
						   uint32_t storageID)
{
	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	if (!ext_start_enumerator(objectEnumerator->ID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
					   TEE_ObjectInfo *objectInfo, void *objectID,
					   size_t *objectIDLen)
{
	struct storage_obj_meta_data recv_per_obj;

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL)
		return TEE_ERROR_GENERIC;

	if (!ext_get_next_obj_from_enumeration(objectEnumerator->ID, &recv_per_obj))
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Generate/copy info to provided parameters */
	/* Overflow err possibility, but no way of checking that */
	memcpy(objectID, recv_per_obj.obj_id, recv_per_obj.obj_id_len);
	*objectIDLen = recv_per_obj.obj_id_len;

	if (objectInfo != NULL)
		memcpy(objectInfo, &recv_per_obj.info, sizeof(TEE_ObjectInfo));

	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size,
				  uint32_t *count)
{
	TEE_Result result;

	if (object == NULL || buffer == NULL || count == NULL)
		return TEE_ERROR_GENERIC;

	*count = 0;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		OT_LOG(LOG_ERR, "Can not read persistent object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	result = validate_object_handle(object);
	if (result != TEE_SUCCESS)
		return result;

	if (object->per_object.data_position >= object->per_object.data_size) {
		/* if creater or equal, need to return 0 read and set the position to end */
		object->per_object.data_position = object->per_object.data_size;
		return TEE_SUCCESS;
	}

	*count = ext_read_stream(object->per_object.storage_blob_id,
				 object->per_object.data_begin + object->per_object.data_position,
				 buffer, size);
	object->per_object.data_position += *count;

	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size)
{
	TEE_Result result;
	size_t write_bytes;

	if (object == NULL || buffer == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		OT_LOG(LOG_ERR, "Can not write persistent object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	result = validate_object_handle(object);
	if (result != TEE_SUCCESS)
		return result;

	if (object->per_object.data_position > object->per_object.data_size) {
		result = MGR_TEE_TruncateObjectData(object, object->per_object.data_position);
		if (result != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "Could not increase file size before writing\n");
			return result;
		}
	}


	write_bytes = ext_write_stream(object->per_object.storage_blob_id,
				       object->per_object.data_begin +
				       object->per_object.data_position,
				       buffer, size);

	if (write_bytes != size) {
		OT_LOG(LOG_DEBUG, "Stream write error has been occurred\n");
		return TEE_ERROR_GENERIC;
	}

	if ((write_bytes + object->per_object.data_position) > object->per_object.data_size)
		object->per_object.data_size = object->per_object.data_position + write_bytes;

	object->per_object.data_position += write_bytes;

	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	TEE_Result result = TEE_SUCCESS;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		OT_LOG(LOG_ERR, "Can not write persistent object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	result = validate_object_handle(object);
	if (result != TEE_SUCCESS)
		return result;

	result = ext_truncate_storage_blob(object->per_object.storage_blob_id,
					      object->per_object.data_begin + size);
	if (result != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Could not truncate\n");
		return result;
	}

	object->per_object.data_size = size;

	return result;
}

TEE_Result MGR_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	TEE_Result result;
	int64_t begin;
	int64_t end;
	int64_t pos;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	result = validate_object_handle(object);
	if (result != TEE_SUCCESS)
		return result;

	begin = 0;
	end = object->per_object.data_size;
	pos = object->per_object.data_position;

	/* if whence is SEEK_CUR should stay as current pos */
	if (whence == TEE_DATA_SEEK_END)
		pos = end;
	else if (whence == TEE_DATA_SEEK_SET)
		pos = begin;

	pos += (int64_t)offset;

	/* check for underflow */
	if (pos < begin)
		pos = begin;

	if (pos > TEE_DATA_MAX_POSITION)
		return TEE_ERROR_OVERFLOW;

	object->per_object.data_position = pos;

	return TEE_SUCCESS;
}
