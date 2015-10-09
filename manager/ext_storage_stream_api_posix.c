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
#include "tee_list.h"

#include "ext_storage_stream_api.h"

#include "opentee_manager_storage_api.h"
#include "core_control_resources.h"


struct storage_element {
	struct list_head list;
	uint32_t storage_blob_id;
	char objectid[TEE_OBJECT_ID_MAX_LEN];
	size_t objectid_len;
	FILE *file;
};

#define MAX_EXT_PATH_NAME MAX_PATH_NAME

#define TEE_OBJ_ID_LEN_HEX (TEE_OBJECT_ID_MAX_LEN * 2 + 1)
#define TEE_UUID_LEN_HEX (sizeof(TEE_UUID) * 2 + 1)
#define ADD_NULL_CHAR_END_TO_HEX(obj_id_len) ((obj_id_len * 2) + 1)
static uint32_t next_enum_ID; /* provide unique ID for enumerators */
static char secure_storage_path[MAX_EXT_PATH_NAME] = {0};

static uint32_t next_storage_id = 1;

static struct storage_enumerator *enumerators_head;

struct storage_enumerator {
	struct storage_enumerator *next;
	DIR *dir;
	uint32_t ID;
};

static struct list_head elements_head;


static bool __attribute__((constructor)) storage_ext_init()
{
	char *tee_storage_dir = getenv("OPENTEE_STORAGE_PATH");
	int res;

	if (tee_storage_dir != NULL) {
		/* if it doesn't end with a backslash, add it */
		char *pathspec = (tee_storage_dir[strlen(tee_storage_dir) - 1] != '/') ? "%s/" : "%s" ;
		res = snprintf(secure_storage_path, MAX_EXT_PATH_NAME, pathspec, tee_storage_dir);
	} else {
		/* fallback to $HOME or /data if OPENTEE_STORAGE_PATH isn't defined */
		#ifndef ANDROID
		tee_storage_dir = getenv("HOME");
		#else
		tee_storage_dir = "/data";
		#endif
		res = snprintf(secure_storage_path, MAX_EXT_PATH_NAME, "%s/%s", tee_storage_dir, ".TEE_secure_storage/");
	}

	if (res == MAX_EXT_PATH_NAME) {
		OT_LOG(LOG_ERR, "Failed to malloc secure storage path\n");
		return false;
	}

	OT_LOG(LOG_ERR, "storage path(%s)\n", secure_storage_path);
	INIT_LIST(&elements_head);

	return true;
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
	size_t i;

	if (uuid == NULL)
		return false;

	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(uuid + i * 2, "%02x", *((unsigned char *)&current_TA_uuid + i));

	uuid[TEE_UUID_LEN_HEX] = '\0';

	return true;
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

static uint32_t add_file_to_list(FILE *file, char *objectid, size_t objectid_len)
{
	struct storage_element *new_element = calloc(1, sizeof(struct storage_element));
	new_element->file = file;
	new_element->storage_blob_id = next_storage_id++;
	new_element->objectid_len = objectid_len;
	memcpy(new_element->objectid, objectid, new_element->objectid_len);
	list_add_after(&new_element->list, &elements_head);
	return new_element->storage_blob_id;
}

static FILE *storage_id_to_file(uint32_t storage_blob_id)
{
	struct list_head *pos;
	struct storage_element *current_element;

	LIST_FOR_EACH(pos, &elements_head) {
		current_element = LIST_ENTRY(pos, struct storage_element, list);
		if (storage_blob_id == current_element->storage_blob_id)
			return current_element->file;
	}
	return NULL;
}

static void close_object(uint32_t storage_blob_id, void *objectID, size_t objectIDLen)
{
	struct list_head *pos;
	struct storage_element *current_element = NULL;

	if (!IS_VALID_STORAGE_BLOB(storage_blob_id))
		return;


	LIST_FOR_EACH(pos, &elements_head) {
		current_element = LIST_ENTRY(pos, struct storage_element, list);
		if (storage_blob_id == current_element->storage_blob_id)
			break;
	}

	if (current_element) {

		list_unlink(&current_element->list);

		if (memcmp(objectID, current_element->objectid, objectIDLen))
			OT_LOG(LOG_ERR,
			       "objectID does not match internal object id, closing file anyways\n");


		if (current_element->file && fclose(current_element->file) != 0)
			OT_LOG(LOG_ERR, "Something went wrong with file closing\n");

		free(current_element);
	}
}

TEE_Result alloc_storage_path(void *objectID,
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

	dir_path = calloc(1, MAX_EXT_PATH_NAME);
	if (dir_path == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (snprintf(dir_path, MAX_EXT_PATH_NAME, "%s%s/", secure_storage_path, UUID)
	    == MAX_EXT_PATH_NAME){
		OT_LOG(LOG_ERR, "secure storage dir path is too long\n");
		free(dir_path);
		return TEE_ERROR_OVERFLOW;
	}


	if (name_with_dir_path) {
		*name_with_dir_path = calloc(1, MAX_EXT_PATH_NAME);
		if (*name_with_dir_path == NULL) {
			free(dir_path);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		for (i = 0; i < objectIDLen; ++i)
			sprintf(hex_ID + i * 2, "%02x", *((unsigned char *)objectID + i));

		if (snprintf(*name_with_dir_path, MAX_EXT_PATH_NAME, "%s%s", dir_path, hex_ID)
		    == MAX_EXT_PATH_NAME) {
			OT_LOG(LOG_ERR, "secure storage name path is too long\n");
			free(dir_path);
			free(*name_with_dir_path);
			*name_with_dir_path = NULL;
			return TEE_ERROR_OVERFLOW;
		}
	}

	if (return_dir_path)
		*return_dir_path = dir_path;
	else
		free(dir_path);

	return TEE_SUCCESS;
}

uint32_t ext_object_id_to_storage_id(char *objectid, size_t objectid_len)
{
	struct list_head *pos;
	struct storage_element *current_element;

	LIST_FOR_EACH(pos, &elements_head) {
		current_element = LIST_ENTRY(pos, struct storage_element, list);
		if (objectid_len == current_element->objectid_len &&
		    !memcmp(objectid, current_element->objectid, objectid_len)) {
			return current_element->storage_blob_id;
		}
	}
	return 0;
}

void ext_delete_storage_blob(uint32_t storage_blob_id, void *objectID, size_t objectIDLen)
{
	char *name_with_dir_path;
	char *dir_path;
	FILE *object_file;

	object_file = storage_id_to_file(storage_blob_id);

	if (object_file)
		close_object(storage_blob_id, objectID, objectIDLen);

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, &dir_path)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return;
	}

	/* TODO: Check that correct file is closed and removed! FILE == objectID */

	if (remove(name_with_dir_path) < 0)
		OT_LOG(LOG_ERR, "Failed to remove file: %s", name_with_dir_path);

	if (is_directory_empty(dir_path))
		rmdir(dir_path);

	free(name_with_dir_path);
	free(dir_path);
}

void ext_close_storage_blob(uint32_t storage_blob_id)
{
	close_object(storage_blob_id, NULL, 0);
}

uint32_t ext_open_storage_blob(char *objectID, size_t objectIDlen, bool create_if_not_exist)
{
	FILE *opened_file = NULL;
	char *file_name_with_path = NULL;
	char *dir_path = NULL;
	uint32_t return_storage_blob = 0;
	int ret_mkdir;

	if (alloc_storage_path(objectID, objectIDlen, &file_name_with_path, &dir_path)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		return 0;
	}

	/* test if exists */
	opened_file = fopen(file_name_with_path, "rb+");

	if (create_if_not_exist && opened_file == NULL) {
		/* not existing, open new */
		opened_file = fopen(file_name_with_path, "w+b");

		if (opened_file == NULL) {
			/* might fail if secure storage path not exist */
			ret_mkdir = mkdir(secure_storage_path, 0777);
			if (ret_mkdir != 0 && errno != EEXIST) {
				OT_LOG(LOG_ERR, "Cannot create Secure Storage directory: %s\n",
						strerror(errno));
				goto ret;
			}
			ret_mkdir = mkdir(dir_path, 0777);
			if (ret_mkdir != 0 && errno != EEXIST) {
				OT_LOG(LOG_ERR, "Cannot create UUID directory: %s\n",
						strerror(errno));
				goto ret;
			}

			opened_file = fopen(file_name_with_path, "w+b");

			if (is_directory_empty(dir_path))
				rmdir(dir_path);

		}
	}

	if (opened_file)
		return_storage_blob = add_file_to_list(opened_file, objectID, objectIDlen);

ret:
	free(dir_path);
	free(file_name_with_path);

	return return_storage_blob;
}

size_t ext_get_storage_blob_size(uint32_t storage_blob_id)
{
	FILE *file = storage_id_to_file(storage_blob_id);
	struct stat st;
	if (file) {
		if (fstat(fileno(file), &st))
			return 0; /* some error occured */
		return st.st_size;
	}
	return 0;
}

bool ext_change_object_ID(uint32_t storage_blob_id,
			  void *objectID,
			  uint32_t objectIDLen,
			  void *new_objectID,
			  uint32_t new_objectIDLen)
{
	struct list_head *pos;
	struct storage_element *current_element;

	char *name_with_dir_path = NULL;
	char *new_name_with_dir_path = NULL;

	bool ret_val = true;

	if (alloc_storage_path(objectID, objectIDLen, &name_with_dir_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		ret_val = false;
		goto exit;
	}

	if (alloc_storage_path(new_objectID, new_objectIDLen, &new_name_with_dir_path, NULL)) {
		OT_LOG(LOG_ERR, "Bad parameters\n");
		ret_val = false;
		goto exit;
	}

	/* TODO: Check if TA can change object ID */

	if (access(new_name_with_dir_path, F_OK) == 0) {
		OT_LOG(LOG_ERR, "Cannot change object ID, because new ID is in use\n");
		ret_val = false;
		goto exit;
	}

	if (rename(name_with_dir_path, new_name_with_dir_path) != 0) {
		OT_LOG(LOG_ERR, "Rename function failed\n");
		ret_val = false;
		goto exit;
	}

	/* update info */
	LIST_FOR_EACH(pos, &elements_head) {
		current_element = LIST_ENTRY(pos, struct storage_element, list);
		if (storage_blob_id == current_element->storage_blob_id) {
			current_element->objectid_len = new_objectIDLen;
			memcpy(current_element->objectid,
			       new_objectID,
			       current_element->objectid_len);
			break;
		}
	}

exit:

	free(name_with_dir_path);
	free(new_name_with_dir_path);
	return ret_val;
}

uint32_t ext_read_stream(uint32_t storage_blob_id, uint32_t offset, void *data, size_t datalen)
{
	FILE *file = storage_id_to_file(storage_blob_id);
	uint32_t readed = 0;

	if (fseek(file, offset, SEEK_SET) != 0) {
		OT_LOG(LOG_ERR, "fseek failed\n");
		return readed;
	}

	readed = fread(data, 1, datalen, file);
	return readed;
}


uint32_t ext_write_stream(uint32_t storage_blob_id, uint32_t offset, void *data, size_t datalen)
{
	FILE *file = storage_id_to_file(storage_blob_id);
	uint32_t written = 0;

	if (fseek(file, offset, SEEK_SET) != 0) {
		OT_LOG(LOG_ERR, "fseek failed\n");
		return written;
	}

	written = fwrite(data, 1, datalen, file);

	if (fflush(file)) {
		OT_LOG(LOG_ERR, "file flush failed after read\n");
	}
	return written;
}

TEE_Result ext_truncate_storage_blob(uint32_t storage_blob_id, uint32_t size)
{
	FILE *file = storage_id_to_file(storage_blob_id);

	if (!file) {
		OT_LOG(LOG_ERR, "trying to truncate non-existing storage blob\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (ftruncate(fileno(file), size) != 0) {
		if (errno == ENOSPC)
			return TEE_ERROR_STORAGE_NO_SPACE;
		return TEE_ERROR_GENERIC;

	}
	return TEE_SUCCESS;
}

bool ext_alloc_for_enumerator(uint32_t *ID)
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

void ext_free_enumerator(uint32_t free_enum_ID)
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

bool ext_start_enumerator(uint32_t start_enum_ID)
{
	char dir_path[MAX_EXT_PATH_NAME] = {0};
	char UUID[TEE_UUID_LEN_HEX];
	struct storage_enumerator *start_enum;

	if (!get_uuid(UUID))
		return false;

	if (snprintf(dir_path, MAX_EXT_PATH_NAME, "%s%s/", secure_storage_path, UUID)
	    == MAX_EXT_PATH_NAME) {
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
		return false; /* FALSE == directory empty -> tee_error_item_not_found */
	}

	return true;
}


void ext_reset_enumerator(uint32_t reset_enum_ID)
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


bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
				       struct storage_obj_meta_data *recv_data_to_caller)
{
	char name_with_path[MAX_EXT_PATH_NAME] = {0};
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

		if (snprintf(name_with_path, MAX_EXT_PATH_NAME, "%s%s/%s",
			     secure_storage_path, UUID, entry->d_name) == MAX_EXT_PATH_NAME) {

			OT_LOG(LOG_ERR, "Enumerator: name path size overflow\n");
			return false; /* TEE_ERROR_GENERIC */
		}

		next_object = fopen(name_with_path, "rb");

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


