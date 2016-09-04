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

#ifndef __STORAGE_UTILS_H__
#define __STORAGE_UTILS_H__

#include <stdio.h>

#include "../tee_data_types.h"
#include "../tee_storage_api.h"
#include "../crypto/operation_handle.h"

#define BITS2BYTE(bits) ((bits + 7) / 8)
#define BYTE2BITS(bits) ((bits) * 8)

#define MAX_broken_tee_SS_FILE_LENGTH		14
#define MAX_SS_FILE_NAME_WITH_PATH	64 /* Includes end character (0x00) */

#define CREATE_SS_FILE				0xA4
#define NOT_CREATE_SS_FILE			0x00

//TODO: Move this to manager
//#define TEE_MAX_DATA_SIZE (TEE_DATA_MAX_POSITION - sizeof(struct ss_object_meta_info))
#define TEE_MAX_DATA_SIZE TEE_DATA_MAX_POSITION

char *get_ss_path(uint32_t *path_len);

int valid_object_type_and_max_size(uint32_t obj_type, uint32_t obj_size);

int is_value_attribute(uint32_t attr_ID);

int expected_object_attr_count(uint32_t obj_type, uint32_t *expected_attr_count);

//void free_gp_attributes(struct gp_attributes *gp_attrs);

void free_gp_key(struct gp_key *key);

void free_object_handle(TEE_ObjectHandle object);

//void release_ss_file(uint32_t ss_id);

void delete_ss_file(void *objectID, size_t objectIDLen);

void release_and_delete_ss_file(FILE *ss_file, void *objectID, size_t objectIDLen);

void close_persistan_object(void *objectID, uint32_t objectIDLen);

TEE_Result get_broken_tee_ss_file_name_with_path(void *objectID,
						 size_t objectIDLen,
						 char *broken_tee_name_with_path,
						 uint32_t broken_tee_name_with_path_len);

#endif /* __STORAGE_UTILS_H__ */
