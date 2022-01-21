/*****************************************************************************
** Copyright (C) 2015 Intel						    **
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

#include <string.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "tee_memory.h"
#include "tee_logging.h"
#include "tee_time_api.h" /*TEE_TIMEOUT_INFINITE*/
#include "com_protocol.h" /*MGR CMD IDs*/
#include "tee_internal_client_api.h"
#include "opentee_internal_api.h"
#include "opentee_manager_storage_api.h"
#include "ext_storage_stream_api.h"
#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "tee_memory.h"
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

	//TODO: Calloc might fail!


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

/************************************************************************************************
*												 *
*												 *
*												 *
*												 *
* #############################################################################################  *
* #											      #  *
* #  ---------------------------------------------------------------------------------------  #  *
* #  |											    | #  *
* #  | #    #	#  # ## I n t e r n a l	  A P I	  f u n c t i o n s ## #  #   #	   #	 # |  #  *
* #  |											    | #  *
* #  ---------------------------------------------------------------------------------------  #  *
* #											      #  *
* #############################################################################################  *
*												 *
*												 *
*												 *
*												 *
************************************************************************************************/

void MGR_TEE_CloseObject(void *objectID, uint32_t objectIDLen)
{
	uint32_t storage_blob_id = 0;

	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);
	remove_storage_blob_ref(storage_blob_id);
}

TEE_Result MGR_TEE_OpenPersistentObject(uint32_t storageID,
					void *objectID,
					size_t objectIDLen,
					uint32_t flags,
					void **attrs, uint32_t *attrSize,
					struct persistant_object *per_obj,
					TEE_ObjectInfo *objectInfo)
{
	TEE_Result ret_val = TEE_SUCCESS;
	uint32_t storage_blob_id = 0;
	uint32_t original_opening_flags;
	struct secure_storage_element *current_element;
	struct ss_object_meta_info object_meta_info = {0};

	storageID = storageID;

	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	if (IS_VALID_STORAGE_BLOB(storage_blob_id)) {
		// is already open, check that it is allowed to share
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

	if (sizeof(struct ss_object_meta_info) !=
	    ext_read_stream(storage_blob_id, 0, &object_meta_info,
			    sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "Cannot read object meta data\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err_1;
	}

	if (object_meta_info.attribute_size > 0) {
		//Load attributes
		*attrs = calloc(1, object_meta_info.attribute_size);
		if (*attrs == NULL) {
			ret_val = TEE_ERROR_OUT_OF_MEMORY;
			goto err_1;
		}
		
		if (object_meta_info.attribute_size !=
		    ext_read_stream(storage_blob_id,
				    object_meta_info.attr_begin,
				    *attrs, object_meta_info.attribute_size)) {
			OT_LOG(LOG_ERR, "Cannot read object meta data\n");
			ret_val = TEE_ERROR_GENERIC;
			goto err_2;
		}
	}

	//All return vales
	*attrSize = object_meta_info.attribute_size;
	per_obj->data_begin = object_meta_info.data_begin;
	per_obj->data_position = 0;
	per_obj->data_size = object_meta_info.data_size;
	per_obj->obj_id_len = object_meta_info.obj_id_len;
	memcpy(&per_obj->obj_id, &object_meta_info.obj_id, object_meta_info.obj_id_len);

	//TODO: Object info :/
	objectInfo->dataPosition = 0;
	objectInfo->dataSize = object_meta_info.data_size;
	objectInfo->keySize = object_meta_info.info.keySize;
	objectInfo->maxObjectSize = object_meta_info.info.keySize;
	objectInfo->objectType = object_meta_info.info.objectType;
	objectInfo->objectUsage = object_meta_info.info.objectUsage;
	
	objectInfo->handleFlags = 0; // reset flags
	objectInfo->handleFlags |=
		(TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	return ret_val;
 err_2:
	free(*attrs);

 err_1:
	remove_storage_blob_ref(storage_blob_id);
	return ret_val;
}

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
					  size_t initialDataLen)
{
	struct secure_storage_element *current_element = NULL;
	struct ss_object_meta_info object_meta_info = {0};
	char *file_name_with_path = NULL;
	int ret;
	uint32_t ss_id;

	storageID = storageID; // Not used

	// TODO:
	// Pre-check if object fits to storage: GP defines position in 32bit..
	//if (attributes)
	//	object_attrs_size = object_attribute_size(&attributes->key->gp_attrs);

	//if (initialDataLen > (TEE_MAX_DATA_SIZE - object_attrs_size))
	//	TEE_Panic(TEE_ERROR_OVERFLOW);


	// Check if object already exist
	// TODO (improvement): Not a correct way. We could use internal
	//   data structures. Would be more consistent

	if (alloc_storage_path(objectID, objectIDLen, &file_name_with_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters or random error");
		return TEE_ERROR_GENERIC;
	}

	ret = access(file_name_with_path, F_OK);
	free(file_name_with_path);

	if (ret != -1) {

		/* File exist */
		if (!(flags & (TEE_DATA_FLAG_OVERWRITE | TEE_DATA_FLAG_EXCLUSIVE))) {
			/* it is already existing, we don't have right to over write */
			return TEE_ERROR_ACCESS_CONFLICT;
		}
	}

	/* is already open, check that it is allowed to share */
	ss_id = ext_object_id_to_storage_id(objectID, objectIDLen);
	if (IS_VALID_STORAGE_BLOB(ss_id)) {

		/* It is open, lets close it */
		//*ss_id = ext_object_id_to_storage_id(objectID, objectIDLen);
		current_element = get_storage_blob_element(ss_id);
		if (current_element) {
			current_element->is_valid = 0;
		}

		ext_delete_storage_blob(ss_id, objectID, objectIDLen);
	}

	//TODO: Not checking return value (for some odd reason)
	ss_id = ext_open_storage_blob(objectID, objectIDLen, true);
	add_storage_blob_id(ss_id, flags);

	// Metainfo: Fill | General
	object_meta_info.attr_begin = sizeof(struct ss_object_meta_info);
	object_meta_info.data_begin = sizeof(struct ss_object_meta_info) + attrSize;
	object_meta_info.data_size = initialDataLen;
	object_meta_info.attribute_size = attrSize;
	memcpy(object_meta_info.obj_id, objectID, objectIDLen);
	object_meta_info.obj_id_len = objectIDLen;

	// Metainfo: Fill | Object info
	if (persistent_type == COM_MGR_PERSISTENT_DATA_OBJECT) {
		object_meta_info.info.objectType = TEE_TYPE_DATA;
		object_meta_info.info.keySize = 0;
	} else {

		//TODO: ObjectInfo
		//Does not contain info..
		memcpy(&object_meta_info.info, info, sizeof(TEE_ObjectInfo));
		//object_meta_info.info.keySize = BYTE2BITS(attributes->key->key_lenght);
		//object_meta_info.data_begin += object_attrs_size;
	}

	// Metainfo: Write
	if (sizeof(struct ss_object_meta_info) !=
	    ext_write_stream(ss_id, 0, &object_meta_info, sizeof(struct ss_object_meta_info))) {
		goto err;
	}

	// store attributes
	if (object_meta_info.attribute_size > 0) {
		if (object_meta_info.attribute_size !=
		    ext_write_stream(ss_id, object_meta_info.attr_begin, attrs, object_meta_info.attribute_size)) {
			goto err;
		}
	}

	// write initi data
	if (initialData) {
		if (initialDataLen != ext_write_stream(ss_id,
						       object_meta_info.data_begin,
						       initialData, initialDataLen)) {
			OT_LOG_ERR("InitialData write failed\n");
			goto err;
		}
	}

	//Returned
	per_obj->data_begin = object_meta_info.data_begin;
	per_obj->data_position = 0;
	per_obj->data_size = initialDataLen;
	per_obj->obj_id_len = objectIDLen;
	memcpy(&per_obj->obj_id, objectID, objectIDLen);

	return TEE_SUCCESS;

err:
	ext_delete_storage_blob(ss_id, objectID, objectIDLen);
	return TEE_ERROR_GENERIC;
}

TEE_Result MGR_TEE_RenamePersistentObject(void *objectID, size_t objectIDLen,
					  void *newObjectID, size_t newObjectIDLen)
{
	struct secure_storage_element *current_element = NULL;
	struct ss_object_meta_info object_meta_info = {0};
	size_t bytes;
	uint32_t ss_id;

	if (objectID == NULL || newObjectID == NULL) {
		//Sanity check
		OT_LOG_ERR("Object objecjtID or newObjectID NULL");
		return TEE_ERROR_GENERIC;
	}
	
	ss_id = ext_object_id_to_storage_id(objectID, objectIDLen);
	if (IS_VALID_STORAGE_BLOB(ss_id)) {
		current_element = get_storage_blob_element(ss_id);
		if (!current_element->is_valid) {
			OT_LOG_ERR("Not a valid storage element");
			return TEE_ERROR_GENERIC;
		}

		if (!(current_element->opening_flags & TEE_DATA_FLAG_EXCLUSIVE)) {
			OT_LOG_ERR("Unable to rename due opened with TEE_DATA_FLAG_EXCLUSIVE");
			return TEE_ERROR_GENERIC;
		}
	} else {
		OT_LOG_ERR("Internal error: Cant rename object which is not open");
		return TEE_ERROR_GENERIC;
	}

	if (!ext_change_object_ID(ss_id,
				  objectID, objectIDLen,
				  newObjectID, newObjectIDLen)) {
		OT_LOG(LOG_ERR, "Access conflict: ID exists");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	bytes = ext_read_stream(ss_id, 0, &object_meta_info, sizeof(struct ss_object_meta_info));
	if (bytes != sizeof(struct ss_object_meta_info)) {
		OT_LOG(LOG_ERR, "Unable to read object meta info");
		return TEE_ERROR_GENERIC;
	}
	
	memset(object_meta_info.obj_id, 0, TEE_OBJECT_ID_MAX_LEN);
	memcpy(object_meta_info.obj_id, newObjectID, newObjectIDLen);
	object_meta_info.obj_id_len = newObjectIDLen;
	
	bytes = ext_write_stream(ss_id, 0, &object_meta_info, sizeof(struct ss_object_meta_info));
	if (bytes != sizeof(struct ss_object_meta_info)) {
		//TODO: Delete and close object. Can't used anymore due meta corrupted.
		OT_LOG(LOG_ERR, "Object corrupted");
		return TEE_ERROR_CORRUPT_OBJECT;
	}

	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_CloseAndDeletePersistentObject(void *objectID, size_t objectIDLen)
{
	struct secure_storage_element *current_element;
	uint32_t storage_blob_id = 0;

	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	current_element = get_storage_blob_element(storage_blob_id);
	if (current_element == NULL) {		
		OT_LOG(LOG_ERR, "Unable find element");
		return TEE_ERROR_GENERIC;
	}
	
	//Enforce flag
	if (!(current_element->opening_flags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "Opened with wrong flags");
		return TEE_ERROR_GENERIC;
	}
	
	current_element->is_valid = 0;
	remove_storage_blob_ref(storage_blob_id);
	if (ext_delete_storage_blob(storage_blob_id, objectID, objectIDLen)) {
		return TEE_ERROR_GENERIC;
	}


	return TEE_SUCCESS;
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
					   TEE_ObjectInfo *objectInfo,
					   void *objectID,
					   size_t *objectIDLen)
{
	struct ss_object_meta_info recv_per_obj;

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

TEE_Result MGR_TEE_ReadObjectData(void *objectID, size_t objectIDLen,
				  void *buffer, size_t size,
				  uint32_t *count,
				  size_t *pos)
{
	//TODO: property api
	
	uint32_t storage_blob_id;
	struct ss_object_meta_info object_meta_info;
	struct secure_storage_element *ss_element;
	
	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id)) {
		//TODO: Check if valid blob
		OT_LOG_ERR("TEE_ReadObjectData objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	ss_element = get_storage_blob_element(storage_blob_id);

	if (!ss_element->is_valid) {
		OT_LOG_ERR("TEE_ReadObjectData objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	
	if (!(ss_element->opening_flags & TEE_DATA_FLAG_ACCESS_READ)) {
		OT_LOG_ERR("TEE_ReadObjectData unable read due missing"
			   " access right (missing TEE_DATA_FLAG_ACCESS_READ)");
		return TEE_ERROR_ACCESS_DENIED;
	}

	// It is a valid object and it is open
	if (sizeof(struct ss_object_meta_info) !=
	    ext_read_stream(storage_blob_id, 0, &object_meta_info,
			    sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "TEE_ReadObjectData generic read error");
		return TEE_ERROR_GENERIC;
	}

	*count = 0;

	if (*pos >= object_meta_info.data_size) {
		//if creater or equal, need to return 0 read and set the position to end
		*pos = object_meta_info.data_size;
		return TEE_SUCCESS;
	}

	*count = ext_read_stream(storage_blob_id,
				 object_meta_info.data_begin + *pos,
				 buffer, size);
	
	*pos += *count;
	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_WriteObjectData(void *objectID, size_t objectIDLen,
				   void *buffer, size_t size,
				   size_t *pos)
{
	TEE_Result rv;
	size_t ss_cur_total_size, ss_pos_total_size, write_bytes = 0;
	uint32_t storage_blob_id;
	struct ss_object_meta_info object_meta_info;
	struct secure_storage_element *ss_element;

	//TODO: Overflow check
	
	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id)) {
		//TODO: Check if valid blob
		OT_LOG_ERR("TEE_WriteObjectData objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	ss_element = get_storage_blob_element(storage_blob_id);

	if (!ss_element->is_valid) {
		OT_LOG_ERR("TEE_WriteObjectData objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}
	
	if (!(ss_element->opening_flags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		OT_LOG_ERR("TEE_WriteObjectData unable write due missing access "
			   "right (missing TEE_DATA_FLAG_ACCESS_WRITE)");
		return TEE_ERROR_ACCESS_DENIED;
	}
	
	// It is a valid object and it is open
	if (sizeof(struct ss_object_meta_info) !=
	    ext_read_stream(storage_blob_id, 0, &object_meta_info,
			    sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "TEE_WriteObjectData generic read error");
		return TEE_ERROR_GENERIC;
	}

	//Total size includes meta and attributes
 	ss_cur_total_size = object_meta_info.data_size;
	ss_pos_total_size = *pos + size;
		
	if (*pos > object_meta_info.data_size) {
		//TODO/NOTE: Is this a problem? Just to be
		//caution and handling it as an error.
		OT_LOG_ERR("TEE_WriteObjectData write pos greater"
			   " than data size (pos[%lu]; dataSize[%u])",
			   *pos, object_meta_info.data_size);
		return TEE_ERROR_GENERIC;
	}

	if (ss_pos_total_size > ss_cur_total_size) {
		//Note: Truncate will also update object meta data!
		rv = MGR_TEE_TruncateObjectData(objectID, objectIDLen, ss_pos_total_size, NULL);
		if (rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_WriteObjectData object truncate failed");
			return rv;
		}
	}

	write_bytes = ext_write_stream(storage_blob_id,
				       object_meta_info.data_begin + *pos,
				       buffer, size);
	if (write_bytes != size) {
		OT_LOG(LOG_DEBUG, "TEE_WriteObjectData write failed. Object data corrupted!");
		//TODO: Handle error. File is corrupted so we need to delete!?
		return TEE_ERROR_GENERIC;
	}

	*pos += write_bytes;
	
	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_TruncateObjectData(void *objectID, size_t objectIDLen, size_t size, size_t *pos)
{
	TEE_Result rv;
	uint32_t storage_blob_id;
	struct ss_object_meta_info object_meta_info;
	struct secure_storage_element *ss_element;
	
	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id)) {
		OT_LOG_ERR("TEE_TruncateObjectData objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	ss_element = get_storage_blob_element(storage_blob_id);

	if (!ss_element->is_valid) {
		OT_LOG_ERR("TEE_TruncateObjectData objectID not found");
		return TEE_ERROR_CORRUPT_OBJECT;
	}
	
	if (!(ss_element->opening_flags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		OT_LOG_ERR("TEE_TruncateObjectData unable write due missing"
			   " access right (missing TEE_DATA_FLAG_ACCESS_WRITE)");
		return TEE_ERROR_ACCESS_DENIED;
	}
	
	// It is a valid object and it is open
	if (sizeof(struct ss_object_meta_info) !=
	    ext_read_stream(storage_blob_id, 0, &object_meta_info,
			    sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "TEE_TruncateObjectData generic read error");
		return TEE_ERROR_GENERIC;
	}

	rv = ext_truncate_storage_blob(storage_blob_id,
				       object_meta_info.data_begin + size);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_TruncateObjectData failed with 0x%x\n", rv);
		//TODO: Handle error. File is corrupted so we need to delete!?
		return rv;
	}

	object_meta_info.data_size = size;

	if (sizeof(struct ss_object_meta_info) !=
	    ext_write_stream(storage_blob_id, 0, &object_meta_info,
			     sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "TEE_TruncateObjectData generic write failure");
		//TODO: Delete and close object. Can't used anymore due meta corrupted.
		return TEE_ERROR_CORRUPT_OBJECT;
	}

	if (pos != NULL && *pos > size) {
		*pos = size;
	}
	
	return rv;
}

TEE_Result MGR_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	object = object;
	offset = offset;
	whence = whence;

	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result MGR_TEE_GetObjectInfo1(void *objectID, size_t objectIDLen, uint32_t *dataSize)
{
	uint32_t storage_blob_id;
	struct ss_object_meta_info object_meta_info;
	struct secure_storage_element *ss_element;
	
	storage_blob_id = ext_object_id_to_storage_id(objectID, objectIDLen);

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id)) {
		OT_LOG_ERR("MGR_TEE_GetObjectInfo1 objectID not found");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	ss_element = get_storage_blob_element(storage_blob_id);
	
	if (!ss_element->is_valid) {
		OT_LOG_ERR("MGR_TEE_GetObjectInfo1 objectID not found");
		return TEE_ERROR_CORRUPT_OBJECT;
	}
	
	// It is a valid object and it is open
	if (sizeof(struct ss_object_meta_info) !=
	    ext_read_stream(storage_blob_id, 0, &object_meta_info,
			    sizeof(struct ss_object_meta_info))) {
		OT_LOG(LOG_ERR, "TEE_TruncateObjectData generic read error");
		return TEE_ERROR_GENERIC;
	}
	
	*dataSize = object_meta_info.data_size;
	return TEE_SUCCESS;
}
