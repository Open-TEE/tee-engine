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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
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




#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "tee_panic.h"
#include "tee_memory.h"
#include "tee_storage_common.h"
#include "tee_logging.h"

#define TEE_OBJ_ID_LEN_HEX (TEE_OBJECT_ID_MAX_LEN * 2 + 1)
#define TEE_UUID_LEN_HEX (sizeof(TEE_UUID) * 2 + 1)
#define ADD_NULL_CHAR_END_TO_HEX(obj_id_len) ((obj_id_len * 2) + 1)
static uint32_t next_enum_ID; /* provide unique ID for enumerators */
static char *secure_storage_path;

static struct storage_enumerator *enumerators_head;

struct storage_enumerator {
	struct storage_enumerator *next;
	DIR *dir;
	uint32_t ID;
};

static void ext_delete_file(FILE *object_file, void *objectID, size_t objectIDLen);
static void ext_release_file(FILE *object_file, void *objectID, size_t objectIDLen);
static bool ext_change_object_ID(void *objectID, size_t objectIDLen, void *new_objectID,
			  size_t new_objectIDLen);
static bool ext_alloc_for_enumerator(uint32_t *ID);
static void ext_free_enumerator(uint32_t free_enum_ID);
static void ext_reset_enumerator(uint32_t reset_enum_ID);
static bool ext_start_enumerator(uint32_t start_enum_ID);
static bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
				       struct storage_obj_meta_data *recv_data_to_caller);

static bool __attribute__((constructor)) storage_ext_init()
{
	char *home = getenv("HOME");

	if (asprintf(&secure_storage_path, "%s/%s", home, ".TEE_secure_storage/") == -1) {
		OT_LOG(LOG_ERR, "Failed to malloc secure storage path\n");
		return false;
	}

	return true;
}

static void __attribute__((destructor)) storage_ext_cleanup()
{
	free(secure_storage_path);
}

/*!
 * \brief get_uuid
 * Retrieve TAs UUID
 * \param uuid is filled with TAs uuid. UUID is converted to HEX format and containing NULL
 * character.
 * Use TEE_UUID_LEN_HEX for buffer size reservation.
 * \return
 */
static bool get_uuid(char *uuid)
{
	char UUID_test[] = "1234567890123456789012345678901234567890";
	size_t i;

	if (uuid == NULL)
		return false;

	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(uuid + i * 2, "%02x", *((unsigned char *)UUID_test + i));

	uuid[TEE_UUID_LEN_HEX] = '\0';

	memcpy(uuid, UUID_test, TEE_UUID_LEN_HEX);

	return true;
}

static TEE_Result alloc_storage_path(void *objectID,
				     size_t objectIDLen,
				     char **name_with_dir_path,
				     char **return_dir_path)
{
	size_t i;
	char hex_ID[TEE_OBJ_ID_LEN_HEX] = {0};
	char UUID[TEE_UUID_LEN_HEX];
	char *dir_path;

	if ((objectIDLen > TEE_OBJECT_ID_MAX_LEN) ||
	    (objectID == NULL) ||
	    (!get_uuid(UUID)) ||
	    (name_with_dir_path == NULL && return_dir_path == NULL))
		return TEE_ERROR_BAD_PARAMETERS;


	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char *)objectID + i));

	if (asprintf(&dir_path, "%s%s/", secure_storage_path, UUID) == -1)
		return TEE_ERROR_OUT_OF_MEMORY;


	if (name_with_dir_path) {
		if (asprintf(name_with_dir_path, "%s%s", dir_path, hex_ID) == -1) {
			free(dir_path);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	if (return_dir_path)
		*return_dir_path = dir_path;
	else
		free(dir_path);

	return TEE_SUCCESS;
}

static bool is_directory_empty(char *dir_path)
{
	struct dirent *entry;
	int file_count = 0;

	if (dir_path == NULL) {
		OT_LOG(LOG_ERR, "Dir path is NULL\n");
		return false;
	}

	DIR *dir = opendir(dir_path);
	if (dir == NULL)
		return false;

	while ((entry = readdir(dir)) != NULL) {
		++file_count;
		if (file_count > 2) {
			closedir(dir);
			return false;
		}
	}

	closedir(dir);
	return true;
}

static void ext_delete_file(FILE *object_file, void *objectID, size_t objectIDLen)
{
	char *name_with_dir_path;
	char *dir_path;

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, &dir_path)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return;
	}

	/* TODO: Check that correct file is closed and removed! FILE == objectID */

	if (fclose(object_file) != 0) {
		OT_LOG(LOG_ERR, "Something went wrong with file closening\n");
		return;
	}

	if (remove(name_with_dir_path) < 0)
		OT_LOG(LOG_ERR, "Failed to remove file: %s", name_with_dir_path);

	if (is_directory_empty(dir_path))
		rmdir(dir_path);

	free(name_with_dir_path);
	free(dir_path);
}

static void ext_release_file(FILE *object_file, void *objectID, size_t objectIDLen)
{
	/* xattr */
	objectID = objectID;
	objectIDLen = objectIDLen;

	if (object_file == NULL)
		return;

	/* TODO: Check that correct file is closed! FILE == objectID */

	if (fclose(object_file) != 0) {
		OT_LOG(LOG_ERR, "Something went wrong with file closening\n");
		return;
	}
}

static FILE *request_file(char *file_name_with_path, size_t request_access)
{
	FILE *test_exist;
	/* TODO: Check if TA is granted for this per obj */

	if (request_access & TEE_DATA_FLAG_ACCESS_WRITE_META ||
	    request_access & TEE_DATA_FLAG_ACCESS_WRITE) {
		test_exist = fopen(file_name_with_path, "rb+");

		if (test_exist == NULL)
			return fopen(file_name_with_path, "w+b");

		return test_exist;

	} else if (request_access & TEE_DATA_FLAG_ACCESS_READ) {
		return fopen(file_name_with_path, "rb");

	} else {
		OT_LOG(LOG_ERR, "Cannot open file\n");
		return NULL;
	}
}


static bool ext_change_object_ID(void *objectID, size_t objectIDLen, void *new_objectID,
			  size_t new_objectIDLen)
{
	char *name_with_dir_path;
	char *new_name_with_dir_path;

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return false;
	}

	if (alloc_storage_path(new_objectID, new_objectIDLen, &new_name_with_dir_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		free(name_with_dir_path);
		return false;
	}

	/* TODO: Check if TA can change object ID */

	if (access(new_name_with_dir_path, F_OK) == 0) {
		OT_LOG(LOG_ERR, "Cannot change object ID, because new ID is in use\n");
		return false;
	}

	if (rename(name_with_dir_path, new_name_with_dir_path) != 0) {
		OT_LOG(LOG_ERR, "Rename function failed\n");
		return false;
	}

	free(name_with_dir_path);
	free(new_name_with_dir_path);
	return true;
}

static bool ext_alloc_for_enumerator(uint32_t *ID)
{
	struct storage_enumerator *new_enumerator;

	if (ID == NULL)
		return false;

	/* MAlloc for handle and fill */
	new_enumerator = calloc(sizeof(struct storage_enumerator), 1);
	if (new_enumerator == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc for enumerator: Out of memory\n");
		return false;
	}

	new_enumerator->ID = next_enum_ID;
	++next_enum_ID; /* check if ID free */

	/* Add new enumerator end of list */
	if (enumerators_head == NULL) {
		enumerators_head = new_enumerator;
	} else {
		new_enumerator->next = enumerators_head;
		enumerators_head = new_enumerator;
	}

	*ID = new_enumerator->ID;
	return true;
}

static void ext_free_enumerator(uint32_t free_enum_ID)
{
	struct storage_enumerator *del_enum, *prev_enum;

	if (enumerators_head == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Not a valid enumerator\n");
		/*TEE_Panic(TEE_ERROR_GENERIC)*/
		return;
	}

	del_enum = enumerators_head;
	prev_enum = del_enum;

	if (enumerators_head->ID == free_enum_ID) {
		del_enum = enumerators_head;
		enumerators_head = enumerators_head->next;
		goto free_and_close;
	}

	while (del_enum) {
		if (del_enum->ID == free_enum_ID) {
			prev_enum->next = del_enum->next;
			goto free_and_close;
		}
		prev_enum = del_enum;
		del_enum = del_enum->next;
	}

	/* should never end up here */
	OT_LOG(LOG_ERR, "Enumerator: Something went wrong with file closening\n");
	return;

free_and_close:
	if (del_enum->dir != NULL)
		closedir(del_enum->dir);
	free(del_enum);
}

static struct storage_enumerator *get_enum(uint32_t ID)
{
	struct storage_enumerator *iter_enum = enumerators_head;

	while (iter_enum != NULL) {
		if (iter_enum->ID == ID)
			return iter_enum;

		iter_enum = iter_enum->next;
	}

	return NULL;
}

static bool ext_start_enumerator(uint32_t start_enum_ID)
{
	char *dir_path = NULL;
	char UUID[TEE_UUID_LEN_HEX];
	struct storage_enumerator *start_enum;

	if (!get_uuid(UUID))
		return false;

	if (asprintf(&dir_path, "%s%s/", secure_storage_path, UUID) == -1) {
		/* TEE_ERROR_OUT_OF_MEMORY */
		return false;
	}

	start_enum = get_enum(start_enum_ID);
	if (start_enum == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Enumerator not valid\n");
		return false;
	}

	if (start_enum->dir != NULL)
		ext_reset_enumerator(start_enum_ID);

	start_enum->dir = opendir(dir_path);
	if (start_enum->dir == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Something went wrong (dirent failure)\n");
		return false; /* NULL == directory empty */
	}

	if (is_directory_empty(dir_path)) {
		free(dir_path);
		return false; /* FALSE == directory empty -> tee_error_item_not_found */
	}

	free(dir_path);
	return true;
}


static void ext_reset_enumerator(uint32_t reset_enum_ID)
{
	struct storage_enumerator *reset_enum;

	if (enumerators_head == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Not a valid enumerator\n");
		return /*TEE_ERROR_GENERIC*/;
	}

	reset_enum = get_enum(reset_enum_ID);
	if (reset_enum == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Enumerator not valid\n");
		return; /*(TEE_ERROR_GENERIC);*/
	}

	/* stop enumeration if needed */
	if (reset_enum->dir != NULL)
		closedir(reset_enum->dir);

	reset_enum->dir = NULL;

	ext_start_enumerator(reset_enum_ID);
}


static bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
				       struct storage_obj_meta_data *recv_data_to_caller)
{
	char *name_with_path = NULL;
	char UUID[TEE_UUID_LEN_HEX];
	struct storage_enumerator *get_from_enum;
	struct dirent *entry;
	FILE *next_object = NULL;
	long end_pos;

	if (!get_uuid(UUID))
		return false;

	get_from_enum = get_enum(get_next_ID);
	if (get_from_enum == NULL) {
		OT_LOG(LOG_ERR, "Enumerator: Enumerator not valid\n");
		return false;
	}

	if (get_from_enum->dir == NULL)
		return false; /* enumeration not started */

	/* Init struct where next object to be read */
	memset(recv_data_to_caller, 0, sizeof(struct storage_obj_meta_data));

	/* Open next persistant object from storage */
	do {
		while ((entry = readdir(get_from_enum->dir)) != NULL) {
			if (entry->d_name[0] == '.')
				continue;
			else
				break;
		}

		if (entry == NULL) {
			/* Enumeration has reached end */
			return false;
		}

		if (asprintf(&name_with_path, "%s%s/%s", secure_storage_path, UUID,
			     entry->d_name) == -1) {
			OT_LOG(LOG_ERR, "Enumerator: Out of memory\n");
			return false; /* TEE_ERROR_GENERIC */
		}

		next_object = fopen(name_with_path, "rb");

		free(name_with_path);

		if (next_object == NULL)
			continue;

		if (fread(recv_data_to_caller, sizeof(struct storage_obj_meta_data), 1,
			  next_object) != 1) {
			OT_LOG(LOG_ERR, "Error at read file (enumeration); errno: %i\n", errno);
			memset(recv_data_to_caller, 0, sizeof(struct storage_obj_meta_data));
			fclose(next_object); /* Skip to next object */
			next_object = NULL;
			continue;
		}

		/* meta size - object meta info == attributes (structs) + buffers == all Attrs */
		recv_data_to_caller->info.objectSize =
		    recv_data_to_caller->meta_size - sizeof(struct storage_obj_meta_data);

		/* calculate data size */
		if (fseek(next_object, 0, SEEK_END) != 0)
			OT_LOG(LOG_ERR, "fseek error at get next enumeration; errno: %i\n", errno);

		end_pos = ftell(next_object);
		if (end_pos == -1L)
			OT_LOG(LOG_ERR, "ftell error at get next enumeration; errno: %i\n", errno);

		if (end_pos - recv_data_to_caller->meta_size > UINT32_MAX)
			recv_data_to_caller->info.dataSize = UINT32_MAX;
		else
			recv_data_to_caller->info.dataSize =
			    ftell(next_object) - recv_data_to_caller->meta_size;

		/* Zero data position */
		recv_data_to_caller->info.dataPosition = 0;

	} while (next_object == NULL);

	if (next_object != NULL)
		fclose(next_object);

	return true;
}


static TEE_Result load_attributes(TEE_ObjectHandle obj)
{
	size_t i;

	if (obj == NULL || obj->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Something went wrong with persistant object attribute loading\n");
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
		if (fread(&obj->attrs[i], sizeof(TEE_Attribute), 1, obj->per_object.object_file) !=
		    1)
			goto err_at_read;

		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			obj->attrs[i].content.ref.buffer = calloc(1, obj->maxObjSizeBytes);
			if (obj->attrs[i].content.ref.buffer == NULL) {
				free_attrs(obj);
				free(obj->attrs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			if (fread(obj->attrs[i].content.ref.buffer,
				  obj->attrs[i].content.ref.length, 1,
				  obj->per_object.object_file) != 1)
				goto err_at_read;
		}
	}

	return TEE_SUCCESS;

err_at_read:
	OT_LOG(LOG_ERR, "Error at fread\n");
	free_attrs(obj);
	free(obj->attrs);
	return TEE_ERROR_GENERIC;
}

static bool serialize_attributes_to_storage(TEE_ObjectHandle object, FILE *storage)
{
	size_t i;

	if (object == NULL)
		return true;

	if (storage == NULL)
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
		if (fwrite(&object->attrs[i], sizeof(TEE_Attribute), 1, storage) != 1)
			return false;

		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (fwrite(object->attrs[i].content.ref.buffer,
				   object->attrs[i].content.ref.length, 1, storage) != 1)
				return false;
		}
	}

	return true;
}

static void release_file(TEE_ObjectHandle object, FILE *obj_file, void *objectID,
			 size_t objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	/* TODO: File closing may fail at the manager end -> user should be inform,
	 * but close functions return values are void */

	if (object != NULL) {
		ext_release_file(object->per_object.object_file, object->per_object.obj_id,
				 object->per_object.obj_id_len);
		object->per_object.object_file = NULL;
	} else {
		ext_release_file(obj_file, objectID, objectIDLen);
		obj_file = NULL;
	}
}

static void delete_file(TEE_ObjectHandle object, FILE *obj_file, void *objectID, size_t objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	/* TODO: File closing may fail at the manager end -> user should be inform,
	 * but close functions return values are void */

	if (object != NULL) {
		ext_delete_file(object->per_object.object_file, object->per_object.obj_id,
				object->per_object.obj_id_len);
		object->per_object.object_file = NULL;
	} else {
		ext_delete_file(obj_file, objectID, objectIDLen);
		obj_file = NULL;
	}
}



static FILE *request_for_open(void *objectID, size_t objectIDLen, size_t request_access)
{
	FILE *per_obj_file = NULL;
	char *name_with_dir_path;

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return NULL;
	}

	if (access(name_with_dir_path, F_OK) != 0) {
		OT_LOG(LOG_ERR, "Access conflict: File not exists\n");
		goto ret;
	}

	per_obj_file = request_file(name_with_dir_path, request_access);

ret:
	free(name_with_dir_path);
	return per_obj_file;
}

static FILE *request_for_create(void *objectID, size_t objectIDLen, size_t request_access)
{
	FILE *per_obj_file = NULL;
	char *name_with_dir_path;
	char *dir_path;
	int ret_mkdir;

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, &dir_path)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return NULL;
	}

	if ((request_access & TEE_DATA_FLAG_EXCLUSIVE) && (access(name_with_dir_path, F_OK) == 0)) {
		OT_LOG(LOG_ERR, "Access conflict: File exists\n");
		goto ret;
	}

	ret_mkdir = mkdir(secure_storage_path, 0777);
	if (ret_mkdir != 0 && errno != EEXIST) {
		OT_LOG(LOG_ERR, "Cannot create Secure Storage directory: %s\n", strerror(errno));
		goto ret;
	}
	ret_mkdir = mkdir(dir_path, 0777);
	if (ret_mkdir != 0 && errno != EEXIST) {
		OT_LOG(LOG_ERR, "Cannot create UUID directory: %s\n", strerror(errno));
		goto ret;
	}

	per_obj_file = request_file(name_with_dir_path, request_access);
	if (per_obj_file == NULL)
		is_directory_empty(dir_path);

ret:
	free(name_with_dir_path);
	free(dir_path);
	return per_obj_file;
}

static bool change_object_ID(TEE_ObjectHandle object, void *new_objectID, size_t new_objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	if (!ext_change_object_ID(object->per_object.obj_id, object->per_object.obj_id_len,
				  new_objectID, new_objectIDLen))
		return false;

	/* change ID in object */
	memcpy(object->per_object.obj_id, new_objectID, new_objectIDLen);
	object->per_object.obj_id_len = new_objectIDLen;

	/* Begin: Move this to manager (add error handling if there is IO error) */

	struct storage_obj_meta_data renamed_meta_data;

	rewind(object->per_object.object_file);
	memset(&renamed_meta_data, 0, sizeof(struct storage_obj_meta_data));

	if (fread(&renamed_meta_data, sizeof(struct storage_obj_meta_data), 1,
		  object->per_object.object_file) != 1) {
		OT_LOG(LOG_ERR, "Read error at renaming\n");
		return false;
	}

	memcpy(renamed_meta_data.obj_id, new_objectID, new_objectIDLen);
	renamed_meta_data.obj_id_len = new_objectIDLen;

	rewind(object->per_object.object_file);

	if (fwrite(&renamed_meta_data, sizeof(struct storage_obj_meta_data), 1,
		   object->per_object.object_file) != 1) {
		OT_LOG(LOG_ERR, "Write error at renaming\n");
	}

	if (fflush(object->per_object.object_file) != 0)
		OT_LOG(LOG_ERR, "Fflush error at renaming\n");

	if (fseek(object->per_object.object_file, object->per_object.data_position, SEEK_SET) != 0)
		OT_LOG(LOG_ERR, "Fseek error at renaming\n");

	/* End */

	return true;
}

static TEE_Result deep_copy_object(TEE_ObjectHandle *dst_obj, TEE_ObjectHandle src_obj)
{
	TEE_ObjectHandle cpy_obj;
	int attr_count;

	if (dst_obj == NULL)
		return TEE_ERROR_GENERIC;

	/* malloc for object handler and cpy that */
	cpy_obj = calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (cpy_obj == NULL)
		goto err_out_of_mem;

	if (src_obj != NULL) {
		attr_count = valid_obj_type_and_attr_count(src_obj->objectInfo.objectType);
		if (attr_count == -1)
			return TEE_ERROR_GENERIC;

		memcpy(cpy_obj, src_obj, sizeof(struct __TEE_ObjectHandle));

		/* Move single function*/
		/* Malloc for attribute pointers */
		cpy_obj->attrs = calloc(src_obj->attrs_count, sizeof(TEE_Attribute));
		if (cpy_obj->attrs == NULL)
			goto err_out_of_mem;

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
				goto err_out_of_mem;
			break;

		case TEE_TYPE_DH_KEYPAIR:
			/* -1, because DH contains one value attribute */
			if (!malloc_for_attrs(cpy_obj, attr_count - 1))
				goto err_out_of_mem;
			break;

		default:
			/* Should never get here */
			goto err_out_of_mem;
			break;
		}

		copy_all_attributes(src_obj, cpy_obj);
	}

	*dst_obj = cpy_obj;

	return TEE_SUCCESS;

err_out_of_mem:
	OT_LOG(LOG_ERR, "Cannot malloc space for object\n");
	free_object(cpy_obj);
	*dst_obj = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
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
		release_file(object, NULL, NULL, 0);

	free_object(object);
	return;
}

TEE_Result MGR_TEE_OpenPersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
					uint32_t flags, TEE_ObjectHandle *object)
{
	TEE_ObjectHandle new_object = NULL;
	struct storage_obj_meta_data meta_info_from_storage;
	TEE_Result ret_val = TEE_SUCCESS;
	FILE *per_storage_file = NULL;

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

	per_storage_file = request_for_open(objectID, objectIDLen, flags);
	if (per_storage_file == NULL) {
		OT_LOG(LOG_ERR, "Open: Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Access granted. Malloc space for new object handler */
	new_object = calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (new_object == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for object handler\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Read persistant object file meta info from storage and fill it new object */
	memset(&meta_info_from_storage, 0, sizeof(struct storage_obj_meta_data));

	if (fread(&meta_info_from_storage, sizeof(struct storage_obj_meta_data), 1,
		  per_storage_file) != 1) {
		OT_LOG(LOG_ERR, "Cannot read object meta data\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

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
	new_object->per_object.object_file = per_storage_file;
	per_storage_file = NULL;
	new_object->maxObjSizeBytes = keysize_in_bits(new_object->objectInfo.maxObjectSize);

	/* Load object attributes */
	ret_val = load_attributes(new_object);
	if (ret_val != TEE_SUCCESS)
		goto err;

	/* Initialization/calculation of data position, size and data begin variables */
	new_object->per_object.data_begin = ftell(new_object->per_object.object_file);
	if (new_object->per_object.data_begin == -1L) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_position = new_object->per_object.data_begin;
	if (fseek(new_object->per_object.object_file, 0, SEEK_END) != 0) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_size =
	    ftell(new_object->per_object.object_file) - new_object->per_object.data_begin;
	if (fseek(new_object->per_object.object_file, new_object->per_object.data_begin,
		  SEEK_SET) != 0) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Handler flags update */
	new_object->objectInfo.handleFlags = 0; /* reset flags */
	new_object->objectInfo.handleFlags |=
	    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	*object = new_object;

	return ret_val;

err:
	if (per_storage_file == NULL)
		release_file(new_object, NULL, objectID, objectIDLen);
	else
		release_file(NULL, per_storage_file, objectID, objectIDLen);

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
	FILE *obj_storage_file;
	TEE_Result ret_obj_alloc;

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

	if (attributes != NULL &&
	    !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "CAnnot create a persistant object from unitialized object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	obj_storage_file = request_for_create(objectID, objectIDLen, flags);
	if (obj_storage_file == NULL) {
		OT_LOG(LOG_ERR, "Create: Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
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
	if (fwrite(&meta_info_to_storage, sizeof(struct storage_obj_meta_data), 1,
		   obj_storage_file) != 1)
		goto err_at_meta_or_init_data_write;

	/* store attributes */
	if (!serialize_attributes_to_storage(attributes, obj_storage_file))
		goto err_at_meta_or_init_data_write;

	if (initialData != NULL) {
		if (fwrite(initialData, initialDataLen, 1, obj_storage_file) != 1)
			goto err_at_meta_or_init_data_write;
	}

	if (fflush(obj_storage_file) != 0)
		goto err_at_meta_or_init_data_write;

	if (object != NULL) {
		ret_obj_alloc = deep_copy_object(object, attributes);
		if (ret_obj_alloc != TEE_SUCCESS)
			goto err_at_obj_alloc;

		/* update current state to allocated handle */
		(*object)->objectInfo.handleFlags = 0; /* reset flags */
		(*object)->objectInfo.handleFlags |=
		    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

		(*object)->per_object.data_position = ftell(obj_storage_file);
		if ((*object)->per_object.data_position == -1L)
			goto err_at_obj_alloc;
		(*object)->per_object.data_begin =
		    (*object)->per_object.data_position - initialDataLen;

		(*object)->per_object.data_size = initialDataLen;

		/* Cpy obj ID to alloceted object */
		memcpy((*object)->per_object.obj_id, objectID, objectIDLen);
		(*object)->per_object.obj_id_len = objectIDLen;

		/* sign storage "location"(=file) */
		(*object)->per_object.object_file = obj_storage_file;

	} else {
		release_file(NULL, obj_storage_file, objectID, objectIDLen);
	}

	return TEE_SUCCESS;

err_at_meta_or_init_data_write:
	OT_LOG(LOG_ERR, "Error with fwrite or fflush\n");
	delete_file(NULL, obj_storage_file, objectID, objectIDLen);
	if (obj_storage_file != NULL && errno == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;

err_at_obj_alloc:
	OT_LOG(LOG_ERR, "Cannot alloc object\n");
	delete_file(NULL, obj_storage_file, objectID, objectIDLen);
	(*object) = NULL;
	if (ret_obj_alloc == TEE_ERROR_OUT_OF_MEMORY)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_ERROR_GENERIC;
}

TEE_Result MGR_TEE_RenamePersistentObject(TEE_ObjectHandle object, void *newObjectID,
					  size_t newObjectIDLen)
{
	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "TEE_RenamePerObj: No rights or not valid object\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (!change_object_ID(object, newObjectID, newObjectIDLen)) {
		OT_LOG(LOG_ERR, "Access conflict: ID exists\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	return TEE_SUCCESS;
}

void MGR_TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "Not a persistant object\n");
		return;
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "TEE_CloAndDelPerObj: No rights or not valid object\n");
		return;
	}

	delete_file(object, NULL, NULL, 0);
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
	if (object == NULL || buffer == NULL || count == NULL)
		return TEE_ERROR_GENERIC;

	*count = 0;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		OT_LOG(LOG_ERR, "Can not read persistant object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (feof(object->per_object.object_file)) {
		OT_LOG(LOG_ERR, "Can't read: end of file\n");
		goto ret;
	}

	*count = fread(buffer, 1, size, object->per_object.object_file);
	object->per_object.data_position += *count;

ret:
	return TEE_SUCCESS;
}

TEE_Result MGR_TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size)
{
	size_t write_bytes;
	int err_no = 0;
	uint32_t end;
	uint32_t	 pos;

	if (object == NULL || buffer == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags &
	     (TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META))) {
		OT_LOG(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (fflush(object->per_object.object_file) != 0) {
		OT_LOG(LOG_ERR, "Cannot flush before write\n");
		goto error;
	}

	end = object->per_object.data_begin + object->per_object.data_size;
	pos = object->per_object.data_position;

	write_bytes = fwrite(buffer, 1, size, object->per_object.object_file);

	if (write_bytes != size) {
		OT_LOG(LOG_DEBUG, "Stream write error has been occured\n");
		goto error;
	}

	if (fflush(object->per_object.object_file) != 0) {
		OT_LOG(LOG_ERR, "Cannot flush after write\n");
		goto error;
	}

	if ((write_bytes + pos) > end)
		object->per_object.data_size += pos + write_bytes - end;

	object->per_object.data_position += write_bytes;

	return TEE_SUCCESS;

error:
	err_no = errno;
	/* TODO: atomic write. For now a cheap solution: set file handler as it was before write */
	if (fseek(object->per_object.object_file, object->per_object.data_position, SEEK_SET) != 0)
		OT_LOG(LOG_ERR, "fseek error at write object data\n");
	if (err_no == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;
}

TEE_Result MGR_TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	uint32_t pos;
	uint32_t begin;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		return TEE_ERROR_ACCESS_DENIED;
	}

	pos = object->per_object.data_position;
	begin = object->per_object.data_begin;

	if (ftruncate(fileno(object->per_object.object_file), begin + size) != 0)
		goto error;

	if (pos > (size + begin)) {
		/* TODO: If fseek fail -> kabum, so some solution is needed */
		if (fseek(object->per_object.object_file, size + begin, SEEK_SET) != 0) {
			OT_LOG(LOG_ERR, "fseek error at truncate object data\n");
			goto error;
		}
		object->per_object.data_position = size + begin;
	}

	object->per_object.data_size = size;

	return TEE_SUCCESS;

error:
	if (errno == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;
}

TEE_Result MGR_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	long begin;
	long end;
	long pos;

	if (object == NULL || object->per_object.object_file == NULL)
		return TEE_ERROR_GENERIC;

	begin = object->per_object.data_begin;
	end = object->per_object.data_begin + object->per_object.data_size;
	pos = object->per_object.data_position;

	/* if whence is SEEK_CUR should stay as current pos */
	if (whence == TEE_DATA_SEEK_END)
		pos = end;
	else if (whence == TEE_DATA_SEEK_SET)
		pos = begin;

	pos += offset;

	/* check for overflow or underflow */
	if (pos > end)
		pos = end;
	else if (pos < begin)
		pos = begin;

	object->per_object.data_position = pos;

	/* TODO: If fseek fail -> kabum, so some solution is needed */
	if (fseek(object->per_object.object_file, pos, SEEK_SET) != 0) {
		OT_LOG(LOG_ERR, "Fseek failed at seek data\n");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
