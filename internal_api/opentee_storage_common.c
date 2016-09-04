#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_data_types.h"
//#include "tee_object_handle.h"
#include "tee_storage_api.h"
#include "tee_logging.h"
#include "opentee_storage_common.h"

uint32_t calculate_object_handle_size2(TEE_ObjectHandle object_handle)
{
        /* Note: This function is calculating "deep" size! It is only doing the part that
         * is needed for trasfering it over to manager */

        uint32_t size = 0, n = 0, padding = 0;
        TEE_Attribute *attribute = NULL;

        /* struct __TEE_ObjectHandle */
        size += sizeof(struct persistant_object);
        size += sizeof(TEE_ObjectInfo);
        size += sizeof(struct gp_key);

        /* struct gp_key -> TEE_Attribute */
        size += object_handle->key->gp_attrs.attrs_count * sizeof(TEE_Attribute);

        for (n = 0; n < object_handle->key->gp_attrs.attrs_count; ++n) {

                attribute = &object_handle->key->gp_attrs.attrs[n];
                if (!is_value_attribute(attribute->attributeID)) {

                        /* make allocation size of arrays align with pointer size */
                        padding = attribute->content.ref.length % sizeof(uintptr_t);

                        size += attribute->content.ref.length;
                        if (padding > 0)
                                size += sizeof(uintptr_t) - padding;

                        /* utilizing the pointer size in packing */
                        size -= sizeof(uintptr_t);
                }
        }

        return size;
}

void pack_object_attrs(TEE_ObjectHandle object,
                       char *mem_in)
{
        TEE_Attribute *obj_attr = NULL;
        uint32_t n = 0, padding = 0;
/*
        memcpy(mem_in, &object->per_object, sizeof(object->per_object));
        mem_in += sizeof(object->per_object);

        memcpy(mem_in, &object->objectInfo, sizeof(object->objectInfo));
        mem_in += sizeof(object->objectInfo);

        memcpy(mem_in, &object->key->gp_attrs.attrs_count,
               sizeof(object->key->gp_attrs.attrs_count));
        mem_in += sizeof(object->key->gp_attrs.attrs_count);
*/
        for (n = 0; n < object->key->gp_attrs.attrs_count; ++n) {

                obj_attr = &object->key->gp_attrs.attrs[n];
                if (is_value_attribute(obj_attr->attributeID)) {
                        memcpy(mem_in, obj_attr, sizeof(TEE_Attribute));
                        mem_in += sizeof(TEE_Attribute);
                        continue;
                }

                /* Reference */
                memcpy(mem_in, &obj_attr->attributeID, sizeof(obj_attr->attributeID));
                mem_in += sizeof(obj_attr->attributeID);

                memcpy(mem_in, &obj_attr->content.ref.length, sizeof(obj_attr->content.ref.length));
                mem_in += sizeof(obj_attr->content.ref.length);

                memcpy(mem_in, obj_attr->content.ref.buffer, obj_attr->content.ref.length);
                mem_in += obj_attr->content.ref.length;

                padding = obj_attr->content.ref.length % sizeof(uintptr_t);
                if (padding > 0)
                        mem_in += sizeof(uintptr_t) - padding;
        }
}

void unpack_object_attrs(TEE_Attribute *attrs,
                         uint32_t attr_count,
                         uint8_t *mem_in)
{
        uint32_t n = 0, padding = 0;

        if (attr_count < 1)
                return;

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
