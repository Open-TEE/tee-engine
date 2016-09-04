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

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_data_types.h"
#include "tee_storage_api.h"
#include "tee_logging.h"
#include "opentee_storage_common.h"

uint32_t calculate_gp_attrs_size(TEE_Attribute *attrs, uint32_t attrs_count)
{
	uint32_t size = 0, n = 0, padding = 0;
	TEE_Attribute *attribute = NULL;

	if (attrs_count == 0) {
		return 0;
	}

	/* struct gp_key -> TEE_Attribute */
	size += attrs_count * sizeof(TEE_Attribute);

	for (n = 0; n < attrs_count; ++n) {

		attribute = &attrs[n];
		if (!is_value_attribute(attribute->attributeID)) {

			/* make allocation size of arrays align with pointer size */
			padding = attribute->content.ref.length % sizeof(uintptr_t);

			size += attribute->content.ref.length;
			if (padding > 0) {
				size += sizeof(uintptr_t) - padding;
			}

			/* utilizing the pointer size in packing
			   this line is about removing void* from size */
			size -= sizeof(uintptr_t);
		}
	}
	
	return size;
}

void free_gp_attributes(struct gp_attributes *gp_attr)
{
	uint32_t i;

	if (gp_attr == NULL) {
		return;
	}

	if (gp_attr->attrs == NULL) {
		return;
	}

	for (i = 0; i < gp_attr->attrs_count; i++) {
		// Zero is illegal attributeID.
		if (gp_attr->attrs[i].attributeID == 0) {
			//We might jump out, but this function supports
			//middle alloc free
			continue;
		}

		if (is_value_attribute(gp_attr->attrs[i].attributeID)) {
			continue;
		} else {
			free(gp_attr->attrs[i].content.ref.buffer);
		}
	}

	free(gp_attr->attrs);
}

static size_t memcpy_ret_n(void *dest, void *src, size_t n)
{
	if (dest != NULL){
		memcpy(dest, src, n);
	}

	return n;
}

static void inc_offset(unsigned char **mem_in, size_t offset)
{
	if (*mem_in != NULL) {
		*mem_in += offset;
	}
}

TEE_Result deserialize_gp_attribute(unsigned char *mem_in,
				    struct gp_attributes *attributes)
{
	uint32_t n = 0;
	TEE_Attribute attr = {0};

	//Counter part: serialize_gp_attribute

	//Function will malloc gp_attribute buffers.
	//NOTE!!! NOT GP COMPLIENT. Buffer sizes are not maxObjectSizes!

	if (attributes == NULL && mem_in == NULL) {
		return TEE_SUCCESS;
	}
	
	memcpy_ret_n(&attributes->attrs_count, mem_in, sizeof(attributes->attrs_count));
	mem_in += sizeof(attributes->attrs_count);

	if (attributes->attrs_count == 0) {
		return TEE_SUCCESS;
	}

	attributes->attrs = calloc(attributes->attrs_count, sizeof(TEE_Attribute));
	if (attributes->attrs == NULL) {
		goto err;
	}

	for (n = 0; n < attributes->attrs_count; ++n) {
		memcpy_ret_n(&attributes->attrs[n].attributeID, mem_in, sizeof(attr.attributeID));
		mem_in += sizeof(attr.attributeID);
		
		if (is_value_attribute(attr.attributeID)) {
			memcpy_ret_n(&attributes->attrs[n].content.value.a, mem_in, sizeof(attr.content.value.a));
			mem_in += sizeof(attr.content.value.a);

			memcpy_ret_n(&attributes->attrs[n].content.value.b, mem_in, sizeof(attr.content.value.b));
			mem_in += sizeof(attr.content.value.b);
		} else {
			memcpy_ret_n(&attributes->attrs[n].content.ref.length, mem_in, sizeof(attr.content.ref.length));
			mem_in += sizeof(attr.content.ref.length);

			attributes->attrs[n].content.ref.buffer = calloc(1, attributes->attrs[n].content.ref.length);
			if (attributes->attrs[n].content.ref.buffer == NULL) {
				goto err;
			}

			memcpy_ret_n(attributes->attrs[n].content.ref.buffer,
				     mem_in, attributes->attrs[n].content.ref.length);
			mem_in += attributes->attrs[n].content.ref.length;
		}
	}

	return TEE_SUCCESS;
 err:
	free_gp_attributes(attributes);
	return TEE_ERROR_OUT_OF_MEMORY;
}

size_t serialize_gp_attribute(struct gp_attributes *attributes,
			      unsigned char *mem_in)
{
	TEE_Attribute *attr = NULL;
	uint32_t n = 0;
	size_t offset = 0;

	//If mem_in is NULL, functio serialization size
	//Note: using offset variable rather pointer arithmetic.

	//Strategy
	//
	// What (size of what)
	//################################
	//# attr count (sizeof)
	//#---------------------------------
	//# attrID     (sizeof)
	//#----------------------------------
	//# (if VALUE     else REF
	//#  a (sizeof)    |  lenght (sizeof)
	//#-----------------------
	//#  b (sizeof)    |  buffer (lenght)
	//#-----------------------------------
	//# attrID.. (as many as attr count)
	//#--...
	
	if (attributes == NULL) {
		return offset;
	}

	if (attributes->attrs_count == 0) {
		return offset;
	}

	offset += memcpy_ret_n(mem_in, &attributes->attrs_count, sizeof(attributes->attrs_count));
	inc_offset(&mem_in, sizeof(attributes->attrs_count));
	
	for (n = 0; n < attributes->attrs_count; ++n) {

		attr = &attributes->attrs[n];

		offset += memcpy_ret_n(mem_in, &attr->attributeID, sizeof(attr->attributeID));
		inc_offset(&mem_in, sizeof(attributes->attrs_count));

		if (is_value_attribute(attr->attributeID)) {
			offset += memcpy_ret_n(mem_in, &attr->content.value.a, sizeof(attr->content.value.a));
			inc_offset(&mem_in, sizeof(attr->content.value.a));

			offset += memcpy_ret_n(mem_in, &attr->content.value.b, sizeof(attr->content.value.b));
			inc_offset(&mem_in, sizeof(attr->content.value.b));
		} else {
			offset += memcpy_ret_n(mem_in, &attr->content.ref.length, sizeof(attr->content.ref.length));
			inc_offset(&mem_in, sizeof(attr->content.ref.length));

			offset += memcpy_ret_n(mem_in, attr->content.ref.buffer, attr->content.ref.length);
			inc_offset(&mem_in, attr->content.ref.length);
		}
	}

	return offset;
}

void pack_object_attrs(struct gp_attributes *attributes,
		       unsigned char *mem_in)
{
	TEE_Attribute *attr = NULL;
	uint32_t n = 0, padding = 0;

	//Function assumes mem_in is big enough!

	for (n = 0; n < attributes->attrs_count; ++n) {

		attr = &attributes->attrs[n];
		if (is_value_attribute(attr->attributeID)) {
			memcpy(mem_in, attr, sizeof(TEE_Attribute));
			mem_in += sizeof(TEE_Attribute);
			continue;
		}

		/* Reference */
		memcpy(mem_in, &attr->attributeID, sizeof(attr->attributeID));
		mem_in += sizeof(attr->attributeID);

		memcpy(mem_in, &attr->content.ref.length, sizeof(attr->content.ref.length));
		mem_in += sizeof(attr->content.ref.length);

		memcpy(mem_in, attr->content.ref.buffer, attr->content.ref.length);
		mem_in += attr->content.ref.length;

		padding = attr->content.ref.length % sizeof(uintptr_t);
		if (padding > 0)
			mem_in += sizeof(uintptr_t) - padding;
	}
}

void unpack_object_attrs(struct gp_attributes *gp_attr,
			 unsigned char *mem_in)
{
	TEE_Attribute *attrs = gp_attr->attrs;
	uint32_t attr_count = gp_attr->attrs_count;
	uint32_t n = 0, padding = 0;

	//NOTE: function does not malloc buffers for attributes.
	//It assumes gp_attrs.attrs have size:
	//    sizeof(TEE_Attribute) * attribte_count

	if (attr_count < 1) {
		return;
	}


	for (n = 0; n < attr_count; ++n) {

		if (is_value_attribute(((TEE_Attribute *)mem_in)->attributeID)) {
			memcpy(&attrs[n], mem_in, sizeof(TEE_Attribute));
			mem_in += sizeof(TEE_Attribute);
			continue;
		}

		//ID
		memcpy(&attrs[n].attributeID, mem_in, sizeof(attrs[n].attributeID));
		mem_in += sizeof(attrs[n].attributeID);

		//Length
		memcpy(&attrs[n].content.ref.length, mem_in,
		       sizeof(attrs[n].content.ref.length));
		mem_in += sizeof(attrs[n].content.ref.length);

		//Assign buffer
		attrs[n].content.ref.buffer = &mem_in;
		mem_in += attrs[n].content.ref.length;

		//Padding
		padding = attrs[n].content.ref.length % sizeof(uintptr_t);
		if (padding > 0)
			mem_in += sizeof(uintptr_t) - padding;
	}
}

uint32_t keysize_in_bits(uint32_t key_in_bytes)
{
	//TODO: Move to "common between storage/crypto"
	//TODO: Overflow check.
	return key_in_bytes * 8; 
}

int keysize_in_bytes(uint32_t key_in_bits)
{
	//TODO: Move to "common between storage/crypto"
	if (key_in_bits <= UINT_MAX - 7)
		key_in_bits += 7;

	return key_in_bits / 8;
}

int valid_obj_type_and_attr_count(object_type obj)
{
	switch (obj) {
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
		return 1;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		return 2;

	case TEE_TYPE_RSA_KEYPAIR:
		return 8;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		return 4;

	case TEE_TYPE_DSA_KEYPAIR:
		return 5;

	case TEE_TYPE_DH_KEYPAIR:
		return 5;

	case TEE_TYPE_ECDSA_KEYPAIR:
		return 4;

	default:
		return -1;
	}
}
