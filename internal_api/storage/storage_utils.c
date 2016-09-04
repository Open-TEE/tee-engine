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

#include <mbedtls/rsa.h>
#include <stdlib.h>
#include <stdio.h>

#include "object_handle.h"
#include "storage_utils.h"
#include "../crypto/operation_handle.h"
#include "../tee_panic.h"
#include "../tee_storage_api.h"

static bool multiple_of_8(uint32_t number)
{
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
}

void *pack_object_handle(TEE_ObjectHandle object, void *mem_in)
{
	TEE_Attribute *obj_attr = (0);
	char *mem = (char *)mem_in;
	uint32_t n = 0, padding = 0;

	memcpy(mem, &object->per_object, sizeof(object->per_object));
	mem += sizeof(object->per_object);

	memcpy(mem, &object->objectInfo, sizeof(object->objectInfo));
	mem += sizeof(object->objectInfo);

	memcpy(mem, &object->key->gp_attrs.attrs_count, sizeof(object->key->gp_attrs.attrs_count));
	mem += sizeof(object->key->gp_attrs.attrs_count);

	for (n = 0; n < object->key->gp_attrs.attrs_count; ++n) {
		obj_attr = &object->key->gp_attrs.attrs[n];
		if (is_value_attribute(obj_attr->attributeID)) {
			memcpy(mem, obj_attr, sizeof(TEE_Attribute));
			mem += sizeof(TEE_Attribute);
		} else {
			memcpy(mem, &obj_attr->attributeID, sizeof(obj_attr->attributeID));
			mem += sizeof(obj_attr->attributeID);

			memcpy(mem, &obj_attr->content.ref.length,
			       sizeof(obj_attr->content.ref.length));
			mem += sizeof(obj_attr->content.ref.length);

			memcpy(mem, obj_attr->content.ref.buffer, obj_attr->content.ref.length);
			mem += obj_attr->content.ref.length;

			padding = obj_attr->content.ref.length % sizeof(uintptr_t);
			if (padding > 0)
				mem += sizeof(uintptr_t) - padding;
		}
	}

	return (void *)mem;
}

void *unpack_and_alloc_object_handle(TEE_ObjectHandle *ret_object, void *mem_in)
{
	*ret_object = calloc(1, sizeof(struct __TEE_ObjectHandle));
	TEE_ObjectHandle handle = *ret_object;
	uint32_t count = 0;
	uint32_t n = 0;
	char *mem = mem_in;

	memcpy(&(*ret_object)->per_object, mem, sizeof((*ret_object)->per_object));
	mem += sizeof((*ret_object)->per_object);

	memcpy(&(*ret_object)->objectInfo, mem, sizeof((*ret_object)->objectInfo));
	mem += sizeof((*ret_object)->objectInfo);

	memcpy(&(*ret_object)->attrs_count, mem, sizeof(handle->attrs_count));
	mem += sizeof(handle->attrs_count);

	memcpy(&handle->maxObjSizeBytes, mem, sizeof(handle->maxObjSizeBytes));
	mem += sizeof(handle->maxObjSizeBytes);

	count = handle->attrs_count;
	if (count > 0) {
		handle->attrs = calloc(count, sizeof(TEE_Attribute));
		for (; n < count; ++n) {
			TEE_Attribute *attribute = &handle->attrs[n];
			TEE_Attribute *attributePipe = (TEE_Attribute *)mem;
			if (is_value_attribute(attributePipe->attributeID)) {
				memcpy(attribute, mem, sizeof(TEE_Attribute));
				mem += sizeof(TEE_Attribute);
			} else {
				memcpy(&attribute->attributeID, mem,
				       sizeof(attribute->attributeID));
				mem += sizeof(attribute->attributeID);

				memcpy(&attribute->content.ref.length, mem,
				       sizeof(attribute->content.ref.length));
				mem += sizeof(attribute->content.ref.length);

				attribute->content.ref.buffer = calloc(1, handle->maxObjSizeBytes);
				if (attribute->content.ref.buffer) {
					memcpy(attribute->content.ref.buffer, mem,
						   attribute->content.ref.length);
				}
				mem += attribute->content.ref.length;
				uint32_t padding =
				    attribute->content.ref.length % sizeof(uintptr_t);
				if (padding > 0)
					mem += sizeof(uintptr_t) - padding;
			}
		}
	}

	return (void *)mem;
}

int valid_object_type_and_max_size(uint32_t obj_type,
                                   uint32_t obj_size)
{
	switch (obj_type) {
	case TEE_TYPE_AES:
		if (obj_size == 128 || obj_size == 192 || obj_size == 256)
			return 0;
		return 1;

	case TEE_TYPE_DES:
		if (obj_size == 56)
			return 0;
		return 1;

	case TEE_TYPE_DES3:
		if (obj_size == 112 || obj_size == 168)
			return 0;
		return 1;

	case TEE_TYPE_HMAC_MD5:
		if (obj_size >= 80 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA1:
		if (obj_size >= 112 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA224:
		if (obj_size >= 192 && obj_size <= 512 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA256:
		if (obj_size >= 256 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA384:
		if (obj_size >= 64 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_HMAC_SHA512:
		if (obj_size >= 64 && obj_size <= 1024 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_RSA_KEYPAIR:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (obj_size >= 512 && obj_size <= 1024 && multiple_of_64(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DSA_KEYPAIR:
		if (obj_size >= 512 && obj_size <= 1024 && multiple_of_64(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DH_KEYPAIR:
		if (obj_size >= 256 && obj_size <= 2048)
			return 0;
		return 1;

	case TEE_TYPE_GENERIC_SECRET:
		if (obj_size >= 8 && obj_size <= 4096 && multiple_of_8(obj_size))
			return 0;
		return 1;

	case TEE_TYPE_DATA:
		if (obj_size == 0)
			return 0;
		return 1;

	default:
		return 1;
	}
}

int is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 * TEE_ATTR_FLAG_VALUE == 0x20000000
	 */
	return attr_ID & TEE_ATTR_FLAG_VALUE;
}

int expected_object_attr_count(uint32_t obj_type,
			       uint32_t *expected_attr_count)
{
	switch (obj_type) {
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
		*expected_attr_count = 1;
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		*expected_attr_count = 2;
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		*expected_attr_count = 8;
		break;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		*expected_attr_count = 4;
		break;

	case TEE_TYPE_DSA_KEYPAIR:
	case TEE_TYPE_DH_KEYPAIR:
		*expected_attr_count = 5;
		break;

	default:
		return 1;
	}

	return 0;
}

void free_gp_attributes(struct gp_attributes *gp_attrs)
{
	uint32_t i;

	for (i = 0; i < gp_attrs->attrs_count; i++) {

		if (is_value_attribute(gp_attrs->attrs[i].attributeID))
			continue;
		else
			free(gp_attrs->attrs[i].content.ref.buffer);
	}
}

void free_gp_key(struct gp_key *key)
{
	if (key->reference_count != 0)
		key->reference_count--;

	if (key->reference_count)
		return;

	/* mbedtls RSA key */
	if (key->gp_key_type == TEE_TYPE_RSA_PUBLIC_KEY ||
	    key->gp_key_type == TEE_TYPE_RSA_KEYPAIR)
		mbedtls_rsa_free(key->key.rsa.ctx);

	free_gp_attributes(&key->gp_attrs);
	free(key->gp_attrs.attrs);
	free(key);
}

void free_object_handle(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->key)
		free_gp_key(object->key);
	free(object);
	object = 0;
}


void release_ss_file(FILE *ss_file,
		     void *objectID,
		     size_t objectIDLen)
{
	/* TODO: Relese file flags */

	if (fclose(ss_file) != 0)
		TEE_Panic(TEE_ERROR_GENERIC);
}

void release_and_delete_ss_file(FILE *ss_file,
				void *objectID,
				size_t objectIDLen)
{
	release_ss_file(ss_file, objectID, objectIDLen);
	delete_ss_file(objectID, objectIDLen);
}

void delete_ss_file(void *objectID,
		    size_t objectIDLen)
{
	char broken_tee_name_with_path[MAX_SS_FILE_NAME_WITH_PATH];
	uint32_t broken_tee_name_with_path_len = MAX_SS_FILE_NAME_WITH_PATH;
	char broken_tee_name[MAX_broken_tee_SS_FILE_LENGTH];
	uint32_t broken_tee_name_len = MAX_broken_tee_SS_FILE_LENGTH;

	if (map_gpID2broken_teeFileName(objectID, objectIDLen, (void *)broken_tee_name, &broken_tee_name_len))
		return;

	if (concat_path_and_name(broken_tee_name, broken_tee_name_len, broken_tee_name_with_path, MAX_SS_FILE_NAME_WITH_PATH))
		return;

	remove(broken_tee_name_with_path);
}

TEE_Result get_broken_tee_ss_file_name_with_path(void *objectID,
					  size_t objectIDLen,
					  char *broken_tee_name_with_path,
					  uint32_t broken_tee_name_with_path_len)
{
	char broken_tee_name[MAX_broken_tee_SS_FILE_LENGTH];
	uint32_t broken_tee_name_len = MAX_broken_tee_SS_FILE_LENGTH;

	if (map_gpID2broken_teeFileName(objectID, objectIDLen, (void *)broken_tee_name, &broken_tee_name_len))
		return TEE_ERROR_STORAGE_NO_SPACE;

	if (concat_path_and_name(broken_tee_name, broken_tee_name_len, broken_tee_name_with_path, broken_tee_name_with_path_len))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
