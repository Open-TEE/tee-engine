#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tee_data_types.h"
#include "tee_object_handle.h"
#include "tee_storage_api.h"
#include "tee_logging.h"
#include "opentee_storage_common.h"

int keysize_in_bits(uint32_t key_in_bits)
{
	if (key_in_bits <= UINT_MAX - 7)
		key_in_bits += 7;

	return key_in_bits / 8;
}

bool is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 * TEE_ATTR_FLAG_VALUE == 0x20000000
	 */
	return attr_ID & TEE_ATTR_FLAG_VALUE;
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

	default:
		return -1;
	}
}

size_t calculate_object_handle_size(TEE_ObjectHandle object_handle)
{
	uint32_t n = 0;
	size_t size = sizeof(struct __TEE_ObjectHandle);
	size += object_handle->attrs_count * sizeof(TEE_Attribute);
	for (n = 0; n < object_handle->attrs_count; ++n) {
		TEE_Attribute *attribute = &object_handle->attrs[n];
		if (!is_value_attribute(attribute->attributeID)) {
			/* make allocation size of arrays align with pointer size */
			uint32_t padding = attribute->content.ref.length % sizeof(uintptr_t);
			size += attribute->content.ref.length;
			if (padding > 0)
				size += sizeof(uintptr_t) - padding;

			/* utilizing the pointer size in packing */
			size -= sizeof(uintptr_t);
		}
	}

	return size;
}

void *pack_object_handle(TEE_ObjectHandle handle, void *mem_in)
{
	uint32_t count = handle->attrs_count;
	uint32_t n = 0;
	char *mem = (char *)mem_in;

	memcpy(mem, &handle->per_object, sizeof(handle->per_object));
	mem += sizeof(handle->per_object);

	memcpy(mem, &handle->objectInfo, sizeof(handle->objectInfo));
	mem += sizeof(handle->objectInfo);

	memcpy(mem, &handle->attrs_count, sizeof(handle->attrs_count));
	mem += sizeof(handle->attrs_count);

	memcpy(mem, &handle->maxObjSizeBytes, sizeof(handle->maxObjSizeBytes));
	mem += sizeof(handle->maxObjSizeBytes);

	for (; n < count; ++n) {
		TEE_Attribute *attribute = &handle->attrs[n];
		if (is_value_attribute(attribute->attributeID)) {
			memcpy(mem, attribute, sizeof(TEE_Attribute));
			mem += sizeof(TEE_Attribute);
		} else {
			memcpy(mem, &attribute->attributeID, sizeof(attribute->attributeID));
			mem += sizeof(attribute->attributeID);

			memcpy(mem, &attribute->content.ref.length,
			       sizeof(attribute->content.ref.length));
			mem += sizeof(attribute->content.ref.length);

			memcpy(mem, attribute->content.ref.buffer, attribute->content.ref.length);
			mem += attribute->content.ref.length;
			uint32_t padding = attribute->content.ref.length % sizeof(uintptr_t);
			if (padding > 0)
				mem += sizeof(uintptr_t) - padding;
		}
	}
	return (void *)mem;
}

void *unpack_and_alloc_object_handle(TEE_ObjectHandle *returnHandle, void *mem_in)
{
	*returnHandle = calloc(1, sizeof(struct __TEE_ObjectHandle));
	TEE_ObjectHandle handle = *returnHandle;
	uint32_t count = 0;
	uint32_t n = 0;
	char *mem = mem_in;

	memcpy(&handle->per_object, mem, sizeof(handle->per_object));
	mem += sizeof(handle->per_object);

	memcpy(&handle->objectInfo, mem, sizeof(handle->objectInfo));
	mem += sizeof(handle->objectInfo);

	memcpy(&handle->attrs_count, mem, sizeof(handle->attrs_count));
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

static bool WEAK_RANDOM_bytes(unsigned char *buf, int num)
{
	unsigned char foo = num;
	while (--num) {
		foo |= foo * num + (num >> 1);
		buf[num] |= foo;
	}
	buf[num] |= foo;
	return true;
}

void free_attrs(TEE_ObjectHandle object)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (object->attrs[i].content.ref.buffer != NULL) {
				/* Fill key buffer with random data. If random function fails,
				 * zero out key buffer. */
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
	return;
}

void free_object(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	free_attrs(object);

	free(object->attrs);

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

	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID))
			object_attr_size += object->attrs[i].content.ref.length;
	}

	return object_attr_size + object->attrs_count * sizeof(TEE_Attribute);
}

bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count)
{
	size_t i;

	for (i = 0; i < attrs_count; ++i) {
		object->attrs[i].content.ref.buffer = calloc(1, object->maxObjSizeBytes);
		if (object->attrs[i].content.ref.buffer == NULL)
			return false;

		object->attrs[i].content.ref.length = object->maxObjSizeBytes;
	}

	return true;
}

void cpy_attr(TEE_ObjectHandle srcObj, uint32_t src_index, TEE_ObjectHandle dstObj,
	      uint32_t dst_index)
{
	if (srcObj == NULL || dstObj == NULL)
		return;

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
}

void copy_all_attributes(TEE_ObjectHandle srcObj, TEE_ObjectHandle destObj)
{
	size_t i;

	if (srcObj->attrs_count != destObj->attrs_count) {
		OT_LOG(LOG_ERR, "Copy fail: Attribute count do not match\n");
		return;
	}

	for (i = 0; i < srcObj->attrs_count; i++)
		cpy_attr(srcObj, i, destObj, i);
}
