#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "storage/object_handle.h"
//#include "storage/storage_utils.h"
#include "tee_data_types.h"
//#include "tee_object_handle.h"
#include "tee_storage_api.h"
#include "tee_logging.h"
#include "opentee_storage_common.h"


static void __attribute__((unused)) pri_buf_hex_format2(const char *title,
						       const unsigned char *buf,
						       int buf_len)
{
	int i;

	OT_LOG_ERR("%s:", title);
	for (i = 0; i < buf_len; ++i) {

		if ((i % 32) == 0)
			OT_LOG_ERR("\n");


			OT_LOG_ERR("%02x ", buf[i]);
	}

	OT_LOG_ERR("\n");
}

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
}

/*
uint32_t calculate_object_handle_size2(TEE_ObjectHandle object_handle)
{
	/* Note: This function is calculating "deep" size! It is only doing the part that
	 * is needed for trasfering it over to manager

	uint32_t size = 0, n = 0, padding = 0;
	TEE_Attribute *attribute = NULL;

	/* struct __TEE_ObjectHandle
	size += sizeof(struct persistant_object);
	size += sizeof(TEE_ObjectInfo);
	size += sizeof(struct gp_key);

	/* struct gp_key -> TEE_Attribute
	size += object_handle->key->gp_attrs.attrs_count * sizeof(TEE_Attribute);

	for (n = 0; n < object_handle->key->gp_attrs.attrs_count; ++n) {

		attribute = &object_handle->key->gp_attrs.attrs[n];
		if (!is_value_attribute(attribute->attributeID)) {

			/* make allocation size of arrays align with pointer size
			padding = attribute->content.ref.length % sizeof(uintptr_t);

			size += attribute->content.ref.length;
			if (padding > 0)
				size += sizeof(uintptr_t) - padding;

			/* utilizing the pointer size in packing
			size -= sizeof(uintptr_t);
		}
	}

	return size;
}
*/

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

static void inc_offset(uint8_t **mem_in, size_t offset)
{
	if (*mem_in != NULL) {
		*mem_in += offset;
	}
}

TEE_Result deserialize_gp_attribute(char *mem_in,
				    struct gp_attributes *attributes)
{
	uint32_t n = 0;
	size_t offset = 0, cpySizeof = 0;
	TEE_Result rv = TEE_SUCCESS;
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
		
		OT_LOG_ERR("ATTR COUNT ID [%u]", attributes->attrs[n].attributeID);

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
			      char *mem_in)
{
	TEE_Attribute *attr = NULL;
	uint32_t n = 0;
	size_t offset = 0, cpySizeof = 0;

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
		       char *mem_in)
{
	TEE_Attribute *attr = NULL;
	uint32_t n = 0, padding = 0;

	//Function assumes mem_in is big enough!
/*
	memcpy(mem_in, &object->per_object, sizeof(object->per_object));
	mem_in += sizeof(object->per_object);

	memcpy(mem_in, &object->objectInfo, sizeof(object->objectInfo));
	mem_in += sizeof(object->objectInfo);

	memcpy(mem_in, &object->key->gp_attrs.attrs_count,
	       sizeof(object->key->gp_attrs.attrs_count));
	mem_in += sizeof(object->key->gp_attrs.attrs_count);
*/
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
			 uint8_t *mem_in)
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
	//TODO: Overflow check.
	return key_in_bytes * 8; 
}

int keysize_in_bytes(uint32_t key_in_bits)
{
	if (key_in_bits <= UINT_MAX - 7)
		key_in_bits += 7;

	return key_in_bits / 8;
}

/*
bool is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 * TEE_ATTR_FLAG_VALUE == 0x20000000

	return attr_ID & TEE_ATTR_FLAG_VALUE;
}
*/
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

size_t calculate_object_handle_size(TEE_ObjectHandle object_handle)
{
/*
	uint32_t n = 0;
	size_t size = sizeof(struct __TEE_ObjectHandle);
	size += object_handle->attrs_count * sizeof(TEE_Attribute);
	for (n = 0; n < object_handle->attrs_count; ++n) {
		TEE_Attribute *attribute = &object_handle->attrs[n];
		if (!is_value_attribute(attribute->attributeID)) {
			/* make allocation size of arrays align with pointer size
			uint32_t padding = attribute->content.ref.length % sizeof(uintptr_t);
			size += attribute->content.ref.length;
			if (padding > 0)
				size += sizeof(uintptr_t) - padding;

			/* utilizing the pointer size in packing
			size -= sizeof(uintptr_t);
		}
	}

	return size;
*/
}

static bool WEAK_RANDOM_bytes(unsigned char *buf, int size)
{
	int n;
	for (n = 0; n < size; n++)
		buf[n] = (unsigned char)rand();
	return true;
}

void free_attrs(TEE_ObjectHandle object)
{
	size_t i;
/*
	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (object->attrs[i].content.ref.buffer != NULL) {
				/* Fill key buffer with random data. If random function fails,
				 * zero out key buffer.
				if (!WEAK_RANDOM_bytes(object->attrs[i].content.ref.buffer,
						       object->maxObjSizeBytes)) {
					memset(object->attrs[i].content.ref.buffer, 0,
					       object->attrs[i].content.ref.length);
				}

				free(object->attrs[i].content.ref.buffer);
				object->attrs[i].content.ref.buffer = NULL;
			}
		}
	}

	if (object->attrs != NULL) {
		if (!WEAK_RANDOM_bytes((unsigned char *)(object->attrs),
				       object->attrs_count * sizeof(TEE_Attribute))) {
			memset(object->attrs, 0, object->attrs_count * sizeof(TEE_Attribute));
		}
	}
*/
}

void free_object(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	free_attrs(object);

//	free(object->attrs);

	if (!WEAK_RANDOM_bytes((unsigned char *)object, sizeof(struct __TEE_ObjectHandle)))
		memset(object, 0, sizeof(struct __TEE_ObjectHandle));

	free(object);

	object = NULL;
}

uint32_t object_attribute_size(TEE_ObjectHandle object)
{
	uint32_t object_attr_size = 0;
	size_t i;

	if (object == NULL)
		return object_attr_size;

//	for (i = 0; i < object->attrs_count; ++i) {
//		if (!is_value_attribute(object->attrs[i].attributeID))
//			object_attr_size += object->attrs[i].content.ref.length;
//	}

//	return object_attr_size + object->attrs_count * sizeof(TEE_Attribute);
}

bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count)
{
	size_t i;

/*	for (i = 0; i < attrs_count; ++i) {
		object->attrs[i].content.ref.buffer = calloc(1, object->maxObjSizeBytes);
		if (object->attrs[i].content.ref.buffer == NULL)
			return false;

		object->attrs[i].content.ref.length = object->maxObjSizeBytes;
	}
*/
	return true;
}

void cpy_attr(TEE_ObjectHandle srcObj, uint32_t src_index, TEE_ObjectHandle dstObj,
	      uint32_t dst_index)
{
	if (srcObj == NULL || dstObj == NULL)
		return;
/*
	if (is_value_attribute(srcObj->attrs[src_index].attributeID)) {
		memcpy(&dstObj->attrs[dst_index], &srcObj->attrs[src_index], sizeof(TEE_Attribute));
	} else {
		memcpy(dstObj->attrs[dst_index].content.ref.buffer,
		       srcObj->attrs[src_index].content.ref.buffer,
		       srcObj->attrs[src_index].content.ref.length);

		dstObj->attrs[dst_index].content.ref.length =
		    srcObj->attrs[src_index].content.ref.length;

		dstObj->attrs[dst_index].attributeID = srcObj->attrs[src_index].attributeID;
	}
*/
}

void copy_all_attributes(TEE_ObjectHandle srcObj, TEE_ObjectHandle destObj)
{
	size_t i;
/*
	if (srcObj->attrs_count != destObj->attrs_count) {
		OT_LOG(LOG_ERR, "Copy fail: Attribute count do not match\n");
		return;
	}

	for (i = 0; i < srcObj->attrs_count; i++)
		cpy_attr(srcObj, i, destObj, i);
*/
}
