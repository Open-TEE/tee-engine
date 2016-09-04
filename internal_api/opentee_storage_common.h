/*****************************************************************************
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


#ifndef __OPENTEE_STORAGE_COMMON__
#define __OPENTEE_STORAGE_COMMON__

#include "tee_storage_api.h"

/* functions to check properties */
int keysize_in_bytes(uint32_t key_in_bits);
uint32_t keysize_in_bits(uint32_t key_in_bytes);
//bool is_value_attribute(uint32_t attr_ID);

/* internal handle memory helpers */
//uint32_t object_attribute_size(TEE_ObjectHandle object);
void free_attrs(TEE_ObjectHandle object);
void free_object(TEE_ObjectHandle object);
bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count);

/* object copy helpers */
int valid_obj_type_and_attr_count(object_type obj);
void cpy_attr(TEE_ObjectHandle srcObj, uint32_t src_index, TEE_ObjectHandle dstObj,
	      uint32_t dst_index);

void copy_all_attributes(TEE_ObjectHandle srcObj, TEE_ObjectHandle destObj);

/* serialization functions for TA to Manager communication */
size_t calculate_object_handle_size(TEE_ObjectHandle object_handle);
void *pack_object_handle(TEE_ObjectHandle handle, void *mem);
void *unpack_and_alloc_object_handle(TEE_ObjectHandle *returnHandle, void *mem);


//void pack_object_attrs(TEE_ObjectHandle object, char *mem_in);
void pack_object_attrs(struct gp_attributes *attributes, unsigned char *mem_in);
uint32_t calculate_object_handle_size2(TEE_ObjectHandle object_handle);
//void unpack_object_attrs(TEE_Attribute *attr, uint32_t attr_count, uint8_t *mem_in);
void unpack_object_attrs(struct gp_attributes *gp_attr, unsigned char *mem_in);


void free_gp_attributes(struct gp_attributes *gp_attrs);
uint32_t calculate_gp_attrs_size(TEE_Attribute *attrs, uint32_t attrs_count);

TEE_Result deserialize_gp_attribute(unsigned char *mem_in,
				    struct gp_attributes *attributes);
size_t serialize_gp_attribute(struct gp_attributes *attributes,
			      unsigned char *mem_in);


#endif /*__OPENTEE_STORAGE_COMMON__*/
