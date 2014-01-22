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

#ifndef __STORAGE_KEY_APIS_EXTERNAL_FUNCS_H__
#define __STORAGE_KEY_APIS_EXTERNAL_FUNCS_H__

#include <stdio.h>

#include "tee_storage_common.h"

void ext_delete_file(FILE *object_file, void *objectID, size_t objectIDLen);
void ext_release_file(FILE *object_file, void* objectID, size_t objectIDLen);
FILE *ext_request_for_open(void *objectID, size_t objectIDLen, size_t request_access);
FILE *ext_request_for_create(void *objectID, size_t objectIDLen, size_t request_access);
bool ext_change_object_ID(void *objectID, size_t objectIDLen, void *new_objectID,
			  size_t new_objectIDLen);
bool ext_alloc_for_enumerator(uint32_t *ID);
void ext_free_enumerator(uint32_t free_enum_ID);
void ext_reset_enumerator(uint32_t reset_enum_ID);
bool ext_start_enumerator(uint32_t start_enum_ID);
bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
				       struct storage_obj_meta_data *recv_data_to_caller);

#endif
