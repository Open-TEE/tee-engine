/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "crypto/operation_handle.h"

#define BITS2BYTE(bits) ((bits + 7) / 8)
#define BYTE2BITS(bits) ((bits) * 8)

//TODO: Move this to manager
//#define TEE_MAX_DATA_SIZE (TEE_DATA_MAX_POSITION - sizeof(struct ss_object_meta_info))
#define TEE_MAX_DATA_SIZE TEE_DATA_MAX_POSITION

int keysize_in_bytes(uint32_t key_in_bits);

uint32_t keysize_in_bits(uint32_t key_in_bytes);

void free_gp_attributes(struct gp_attributes *gp_attr);

int valid_object_type_and_max_size(uint32_t obj_type, uint32_t obj_size);

int is_value_attribute(uint32_t attr_ID);

int expected_object_attr_count(uint32_t obj_type, uint32_t *expected_attr_count);

void free_gp_key(struct gp_key *key);

void free_object_handle(TEE_ObjectHandle object);

void close_persistan_object(void *objectID, uint32_t objectIDLen);

TEE_Attribute *get_attr_from_attrArr(uint32_t ID,
				     TEE_Attribute *attrs,
				     uint32_t attrCount);

#endif /* __STORAGE_UTILS_H__ */
