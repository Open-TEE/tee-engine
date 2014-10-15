/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
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
#include <stdio.h>
#include <syslog.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "tee_panic.h"
#include "tee_memory.h"
#include "tee_storage_common.h"
#include "storage_key_apis_external_funcs.h"


#define SECURE_STORAGE_PATH "/home/dettenbo/TEE_secure_storage/"
#define TEE_OBJ_ID_LEN_HEX TEE_OBJECT_ID_MAX_LEN * 2 + 1
#define TEE_UUID_LEN_HEX sizeof(TEE_UUID) * 2 + 1
#define ADD_NULL_CHAR_END_TO_HEX(obj_id_len) ((obj_id_len * 2) + 1)
static uint32_t next_enum_ID = 0; /* provide unique ID for enumerators */

static struct storage_enumerator *enumerators_head;

struct storage_enumerator {
	struct storage_enumerator *next;
	DIR *dir;
	uint32_t ID;
};

/*!
 * \brief get_uuid
 * Retrieve TAs UUID
 * \param uuid is filled with TAs uuid. UUID is converted to HEX format and containing NULL character.
 * Use TEE_UUID_LEN_HEX for buffer size reservation.
 * \return
 */
static bool get_uuid(char *uuid)
{
	char UUID_test[] = "1234567890123456789012345678901234567890";
	size_t i;

	//TODO: name should end with NULL character!
	if (uuid == NULL)
		return false;

	for (i = 0; i < sizeof(TEE_UUID); ++i)
		sprintf(uuid + i * 2, "%02x", *((unsigned char*)UUID_test + i));

	uuid[TEE_UUID_LEN_HEX] = '\0';

	memcpy(uuid, UUID_test, TEE_UUID_LEN_HEX);

	return true;
}

static bool is_directory_empty(char *dir_path)
{
	struct dirent *entry;
	int file_count = 0;

	if (dir_path == NULL) {
		syslog(LOG_ERR, "Dir path is NULL\n");
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

void ext_delete_file(FILE *object_file, void *objectID, size_t objectIDLen)
{
	char *name_with_dir_path;
	char *dir_path;
	size_t i;
	char hex_ID[TEE_OBJ_ID_LEN_HEX];
	char UUID[TEE_UUID_LEN_HEX];

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN || objectID == NULL || !get_uuid(UUID))
		return;

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	hex_ID[ADD_NULL_CHAR_END_TO_HEX(objectIDLen)] = '\0';

	if (asprintf(&dir_path, "%s%s/", SECURE_STORAGE_PATH, UUID) == -1) {
		return; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&name_with_dir_path, "%s%s", dir_path, hex_ID) == -1) {
		free(dir_path);
		return; // TEE_ERROR_OUT_OF_MEMORY;
	}

	/* TODO: Check that correct file is closed and removed! FILE == objectID */

	if (fclose(object_file) != 0) {
		syslog(LOG_ERR, "Something went wrong with file closening\n");
		TEE_Panic(TEE_ERROR_GENERIC); /* Kill TA */
	}

	remove(name_with_dir_path);

	if (is_directory_empty(dir_path)) {
		rmdir(dir_path);
	}

	free(name_with_dir_path);
	free(dir_path);
}

void ext_release_file(FILE *object_file, void* objectID, size_t objectIDLen)
{
	//xattr
	objectID = objectID;
	objectIDLen = objectIDLen;

	if (object_file == NULL)
		return;

	/* TODO: Check that correct file is closed! FILE == objectID */

	if (fclose(object_file) != 0) {
		syslog(LOG_ERR, "Something went wrong with file closening\n");
		TEE_Panic(TEE_ERROR_GENERIC);
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
		syslog(LOG_ERR, "Cannot open file\n");
		return NULL;
	}
}

FILE *ext_request_for_open(void *objectID, size_t objectIDLen, size_t request_access)
{
	FILE* per_obj_file = NULL;
	char *name_with_dir_path;
	char *dir_path;
	size_t i;
	char hex_ID[TEE_OBJ_ID_LEN_HEX];
	char UUID[TEE_UUID_LEN_HEX];

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN || objectID == NULL || !get_uuid(UUID))
		return NULL;

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	hex_ID[ADD_NULL_CHAR_END_TO_HEX(objectIDLen)] = '\0';

	if (asprintf(&dir_path, "%s%s/", SECURE_STORAGE_PATH, UUID) == -1) {
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&name_with_dir_path, "%s%s", dir_path, hex_ID) == -1) {
		free(dir_path);
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (access(name_with_dir_path, F_OK) != 0) {
		syslog(LOG_ERR, "Access conflict: File not exists\n");
		goto ret;
	}

	per_obj_file = request_file(name_with_dir_path, request_access);

ret:
	free(name_with_dir_path);
	free(dir_path);
	return per_obj_file;
}

FILE *ext_request_for_create(void *objectID, size_t objectIDLen, size_t request_access)
{
	FILE* per_obj_file = NULL;
	char *name_with_dir_path;
	char *dir_path;
	size_t i;
	char hex_ID[TEE_OBJ_ID_LEN_HEX];
	char UUID[TEE_UUID_LEN_HEX];
	int ret_mkdir;

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN || objectID == NULL || !get_uuid(UUID))
		return NULL;

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	hex_ID[ADD_NULL_CHAR_END_TO_HEX(objectIDLen)] = '\0';

	if (asprintf(&dir_path, "%s%s/", SECURE_STORAGE_PATH, UUID) == -1) {
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&name_with_dir_path, "%s%s", dir_path, hex_ID) == -1) {
		free(dir_path);
		return NULL; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if ((request_access & TEE_DATA_FLAG_EXCLUSIVE) && (access(name_with_dir_path, F_OK) == 0)) {
		syslog(LOG_ERR, "Access conflict: File exists\n");
		goto ret;
	}

	ret_mkdir = mkdir(SECURE_STORAGE_PATH, 0777);
	if (ret_mkdir != 0 && errno != EEXIST) {
		syslog(LOG_ERR, "Cannot create Secure Storage directory: %s\n", strerror(errno));
		goto ret;
	}
	ret_mkdir = mkdir(dir_path, 0777);
	if (ret_mkdir != 0 && errno != EEXIST) {
		syslog(LOG_ERR, "Cannot create UUID directory: %s\n", strerror(errno));
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

bool ext_change_object_ID(void *objectID, size_t objectIDLen, void *new_objectID, size_t new_objectIDLen)
{
	char *name_with_dir_path;
	char *new_name_with_dir_path;
	char hex_ID[TEE_OBJ_ID_LEN_HEX];
	char new_hex_ID[TEE_OBJ_ID_LEN_HEX];
	char UUID[TEE_UUID_LEN_HEX];
	size_t i;

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN || objectID == NULL  ||
	    new_objectID == NULL || !get_uuid(UUID))
		return false;

	for (i = 0; i < objectIDLen; ++i)
		sprintf(hex_ID + i * 2, "%02x", *((unsigned char*)objectID + i));

	hex_ID[ADD_NULL_CHAR_END_TO_HEX(objectIDLen)] = '\0';

	for (i = 0; i < new_objectIDLen; ++i)
		sprintf(new_hex_ID + i * 2, "%02x", *((unsigned char*)new_objectID + i));

	new_hex_ID[ADD_NULL_CHAR_END_TO_HEX(new_objectIDLen)] = '\0';

	if (asprintf(&name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, hex_ID) == -1) {
		return false; // TEE_ERROR_OUT_OF_MEMORY;
	}

	if (asprintf(&new_name_with_dir_path, "%s%s/%s", SECURE_STORAGE_PATH, UUID, new_hex_ID) == -1) {
		free(name_with_dir_path);
		return false; // TEE_ERROR_OUT_OF_MEMORY;
	}

	/* TODO: Check if TA can change object ID */

	if (access(new_name_with_dir_path, F_OK) == 0) {
		syslog(LOG_ERR, "Cannot change object ID, because new ID is in use\n");
		return false;
	}

	if (rename(name_with_dir_path, new_name_with_dir_path) != 0) {
		syslog(LOG_ERR, "Rename function failed\n");
		return false;
	}

	free(name_with_dir_path);
	free(new_name_with_dir_path);
	return true;
}

bool ext_alloc_for_enumerator(uint32_t *ID)
{
	struct storage_enumerator *new_enumerator;

	if (ID == NULL)
		return false;

	/* MAlloc for handle and fill */
	new_enumerator = TEE_Malloc(sizeof(struct storage_enumerator), 0);
	if (new_enumerator == NULL) {
		syslog(LOG_ERR, "Cannot malloc for enumerator: Out of memory\n");
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
		syslog(LOG_ERR, "Enumerator: Not a valid enumerator\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	del_enum = enumerators_head;

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
	syslog(LOG_ERR, "Enumerator: Something went wrong with file closening\n");
	TEE_Panic(TEE_ERROR_GENERIC);

free_and_close:
	if (del_enum->dir != NULL)
		closedir(del_enum->dir);
	free(del_enum);
}

struct storage_enumerator *get_enum(uint32_t ID)
{
	struct storage_enumerator *iter_enum = enumerators_head;

	while (iter_enum != NULL) {
		if (iter_enum->ID == ID)
			return iter_enum;

		iter_enum = iter_enum->next;
	}

	return NULL;
}

void ext_reset_enumerator(uint32_t reset_enum_ID)
{
	struct storage_enumerator *reset_enum;

	if (enumerators_head == NULL) {
		syslog(LOG_ERR, "Enumerator: Not a valid enumerator\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	reset_enum = get_enum(reset_enum_ID);
	if (reset_enum == NULL) {
		syslog(LOG_ERR, "Enumerator: Enumerator not valid\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* stop enumeration if needed */
	if (reset_enum->dir != NULL)
		closedir(reset_enum->dir);

	reset_enum->dir = NULL;

	ext_start_enumerator(reset_enum_ID);
}

bool ext_start_enumerator(uint32_t start_enum_ID)
{
	char *dir_path = NULL;
	char UUID[TEE_UUID_LEN_HEX];
	struct storage_enumerator *start_enum;

	if (!get_uuid(UUID))
		return false;

	if (asprintf(&dir_path, "%s%s/", SECURE_STORAGE_PATH, UUID) == -1) {
		return false; // TEE_ERROR_OUT_OF_MEMORY;
	}

	start_enum = get_enum(start_enum_ID);
	if (start_enum == NULL) {
		syslog(LOG_ERR, "Enumerator: Enumerator not valid\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (start_enum->dir != NULL)
		ext_reset_enumerator(start_enum_ID);

	start_enum->dir = opendir(dir_path);
	if (start_enum->dir == NULL) {
		syslog(LOG_ERR, "Enumerator: Something went wrong (dirent failure)\n");
		return false; /* NULL == directory empty */
	}

	if (is_directory_empty(dir_path)) {
		free(dir_path);
		return false; /* FALSE == directory empty -> tee_error_item_not_found */
	}

	free(dir_path);
	return true;
}

bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
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
		syslog(LOG_ERR, "Enumerator: Enumerator not valid\n");
		TEE_Panic(TEE_ERROR_GENERIC);
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

		if (asprintf(&name_with_path, "%s%s/%s",
			     SECURE_STORAGE_PATH, UUID, entry->d_name) == -1) {
			syslog(LOG_ERR, "Enumerator: Out of memory\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		next_object = fopen(name_with_path, "rb");

		free(name_with_path);

		if (next_object == NULL)
			continue;

		if (fread(recv_data_to_caller,
			  sizeof(struct storage_obj_meta_data), 1, next_object) != 1) {
			syslog(LOG_ERR, "Error at read file (enumeration); errno: %i\n", errno);
			memset(recv_data_to_caller, 0, sizeof(struct storage_obj_meta_data));
			fclose(next_object); /* Skip to next object */
			continue;
		}

		/* meta size - object meta info == attributes (structs) + buffers == all Attrs */
		recv_data_to_caller->info.objectSize =
				recv_data_to_caller->meta_size -
				sizeof(struct storage_obj_meta_data);

		/* calculate data size */
		if (fseek(next_object, 0, SEEK_END) != 0)
			syslog(LOG_ERR, "fseek error at get next enumeration; errno: %i\n", errno);

		end_pos = ftell(next_object);
		if (end_pos == -1L)
			syslog(LOG_ERR, "ftell error at get next enumeration; errno: %i\n", errno);

		if (end_pos - recv_data_to_caller->meta_size > UINT32_MAX)
			recv_data_to_caller->info.dataSize = UINT32_MAX;
		else
			recv_data_to_caller->info.dataSize = ftell(next_object) -
							     recv_data_to_caller->meta_size;

		/* Zero data position */
		recv_data_to_caller->info.dataPosition = 0;

	} while (next_object == NULL);

	fclose(next_object);
	return true;
}
