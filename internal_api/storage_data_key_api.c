 /*****************************************************************************
** Copyright (C) 2013 ICRI.						    **
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
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>


#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "storage_data_key_api.h"
#include "tee_memory.h"

struct __TEE_ObjectHandle {
	TEE_ObjectInfo *objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t maxObjSizeBytes;
};

static const uint32_t EMU_ALL = 1;

/*
 * ## TEMP ##
 */
static bool multiple_of_8(uint32_t number); /* ok */
static bool multiple_of_64(uint32_t number); /* ok */
static bool is_usage_extractable(TEE_ObjectHandle object); /* ok */
static bool is_persistent_obj(TEE_ObjectHandle object); /* ok */
static bool is_value_attribute(uint32_t attr_ID); /* ok */
static bool is_public_attribute(uint32_t attr_ID); /* ok */
static bool is_initialized(TEE_ObjectHandle object); /* ok */
static void reset_attrs(TEE_ObjectHandle obj); /* ok */
static void free_attrs(TEE_ObjectHandle object); /* ok */
static bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count);
static bool valid_object_max_size(object_type obj, uint32_t size); /* ok */
static int valid_obj_type_and_attr_count(object_type obj); /* ok */
static int get_attr_index(TEE_ObjectHandle object, uint32_t attributeID); /* ok */
static int gen_rsa_keypair(TEE_ObjectHandle obj, uint32_t key_size);
static int gen_10_key(TEE_ObjectHandle object, uint32_t keySize);
static int gen_dsa_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount);
static int gen_dh_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount);
static int bn2ref_to_obj(BIGNUM *bn, uint32_t ID, TEE_ObjectHandle obj, int i);
static int extract_attr_to_object(uint32_t ID, TEE_Attribute* params, uint32_t paramCount, TEE_ObjectHandle object, uint32_t index);
static int does_arr_contain_attrID(uint32_t ID, TEE_Attribute* attrs, uint32_t attrCount);
static int copy_obj_attr_to_obj(TEE_ObjectHandle srcObj, uint32_t attrID, TEE_ObjectHandle destObj, uint32_t destIndex);

/*
 * ## Non internal API functions ##
 */

static int does_arr_contain_attrID(uint32_t ID, TEE_Attribute* attrs, uint32_t attrCount)
{
	size_t i;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID)
			return i;
	}

	return -1;
}

static int copy_obj_attr_to_obj(TEE_ObjectHandle srcObj, uint32_t attrID, TEE_ObjectHandle destObj, uint32_t destIndex)
{
	int srcIndex = -1;

	if (attrID == EMU_ALL) {
		memcpy(&destObj->attrs[destIndex], &srcObj->attrs[destIndex], sizeof(TEE_Attribute));

		if (!is_value_attribute(srcObj->attrs[destIndex].attributeID)) {
			memcpy(destObj->attrs[destIndex].content.ref.buffer, srcObj->attrs[destIndex].content.ref.buffer, srcObj->attrs[destIndex].content.ref.length);
			destObj->attrs[destIndex].content.ref.length = srcObj->attrs[destIndex].content.ref.length;
		}

		return 1;
	}

	srcIndex = get_attr_index(srcObj, attrID);

	if (srcIndex == -1)
		return 0; /* Array does not contain extracted attribute */

	if (destIndex > destObj->attrs_count)
		return -1; /* Should never happen */

	memcpy(&destObj->attrs[destIndex], &srcObj->attrs[srcIndex], sizeof(TEE_Attribute));

	if (!is_value_attribute(srcObj->attrs[srcIndex].attributeID)) {
		memcpy(destObj->attrs[destIndex].content.ref.buffer, srcObj->attrs[srcIndex].content.ref.buffer, srcObj->attrs[srcIndex].content.ref.length);
		destObj->attrs[destIndex].content.ref.length = srcObj->attrs[srcIndex].content.ref.length;
	}

	return 1;
}

static int extract_attr_to_object(uint32_t ID, TEE_Attribute* params, uint32_t paramCount, TEE_ObjectHandle object, uint32_t index)
{
	int attr_index;

	attr_index = does_arr_contain_attrID(ID, params, paramCount);

	if (attr_index == -1)
		return 0; /* Array does not contain extracted attribute */

	if (index > object->attrs_count)
		return -1; /* Should never happen */

	memcpy(&object->attrs[index], &params[attr_index], sizeof(TEE_Attribute));

	if (!is_value_attribute(params[attr_index].attributeID)) {
		if (object->maxObjSizeBytes >= params[attr_index].content.ref.length) {
			memcpy(object->attrs[index].content.ref.buffer, params[attr_index].content.ref.buffer, params[attr_index].content.ref.length);
		}

		else {
			memcpy(object->attrs[index].content.ref.buffer, params[attr_index].content.ref.buffer, object->maxObjSizeBytes);
			object->attrs[index].content.ref.length = object->maxObjSizeBytes;
		}
	}

	return 1;
}

static int bn2ref_to_obj(BIGNUM *bn, uint32_t ID, TEE_ObjectHandle obj, int i)
{
	obj->attrs[i].content.ref.length = BN_num_bytes(bn);
	if (obj->attrs[i].content.ref.length > obj->maxObjSizeBytes)
		return -1;

	obj->attrs[i].attributeID = ID;
	BN_bn2bin(bn, obj->attrs[i].content.ref.buffer);
	return 1;
}

static int gen_10_key(TEE_ObjectHandle object, uint32_t keySize)
{
	if (!RAND_bytes(object->attrs->content.ref.buffer, keySize/8))
		return 0;

	object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;
	object->attrs->content.ref.length = keySize / 8;

	return 1;
}

static int gen_rsa_keypair(TEE_ObjectHandle obj, uint32_t key_size)
{
	int i = 0;
	RSA *rsa_key = RSA_generate_key(key_size, RSA_3, NULL, NULL);

	if (rsa_key == NULL)
		return 0;

	if (!RSA_check_key(rsa_key)) {
		RSA_free(rsa_key);
		return 0;
	}

	/* Extract/copy values from RSA struct to object */

	if (bn2ref_to_obj(rsa_key->n, TEE_ATTR_RSA_MODULUS, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->e, TEE_ATTR_RSA_PUBLIC_EXPONENT, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->d, TEE_ATTR_RSA_PRIVATE_EXPONENT, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->p, TEE_ATTR_RSA_PRIME1, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->q, TEE_ATTR_RSA_PRIME2, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->dmp1, TEE_ATTR_RSA_EXPONENT1, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->dmq1, TEE_ATTR_RSA_EXPONENT2, obj, i++) == -1 ||
	    bn2ref_to_obj(rsa_key->iqmp, TEE_ATTR_RSA_COEFFICIENT, obj, i++) == -1) {
		RSA_free(rsa_key);
		return -1;
	}

	RSA_free(rsa_key);

	return 1;
}

static int gen_dsa_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount)
{
	int i = 0, attr_index = 0;
	DSA *dsa_key = DSA_new();

	if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DSA_BASE, params, paramCount, object, i++)) {
		DSA_free(dsa_key);
		return -1;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DSA_PRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->p);
	attr_index = get_attr_index(object, TEE_ATTR_DSA_SUBPRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->q);
	attr_index = get_attr_index(object, TEE_ATTR_DSA_BASE);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dsa_key->g);

	if (!DSA_generate_key(dsa_key)) {
		DSA_free(dsa_key);
		return 0;
	}

	if (bn2ref_to_obj(dsa_key->pub_key, TEE_ATTR_DSA_PUBLIC_VALUE, object, i++) == -1 ||
	    bn2ref_to_obj(dsa_key->priv_key, TEE_ATTR_DSA_PRIVATE_VALUE, object, i++) == -1) {
		DSA_free(dsa_key);
		return -1;
	}

	DSA_free(dsa_key);

	return 1;
}

static int gen_dh_keypair(TEE_ObjectHandle object, TEE_Attribute* params, uint32_t paramCount)
{
	int i = 0, attr_index = 0;
	DH *dh_key = DH_new();

	if (extract_attr_to_object(TEE_ATTR_DH_PRIME, params, paramCount, object, i++) &&
	    extract_attr_to_object(TEE_ATTR_DH_BASE, params, paramCount, object, i++)) {
		DH_free(dh_key);
		return -1;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DH_PRIME);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dh_key->p);
	attr_index = get_attr_index(object, TEE_ATTR_DH_BASE);
	BN_bin2bn(object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length, dh_key->g);

	if (!DH_generate_key(dh_key))
		return -1;

	if (bn2ref_to_obj(dh_key->pub_key, TEE_ATTR_DH_PUBLIC_VALUE, object, i++) == -1 ||
	    bn2ref_to_obj(dh_key->priv_key, TEE_ATTR_DH_PRIVATE_VALUE, object, i++) == -1) {
		DH_free(dh_key);
		return -1;
	}

	DH_free(dh_key);

	return 1;
}

static bool is_usage_extractable(TEE_ObjectHandle object)
{
	return (object->objectInfo->objectUsage ^ TEE_USAGE_EXTRACTABLE);
}

static bool is_persistent_obj(TEE_ObjectHandle object)
{
	return (object->objectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT);
}

static bool is_initialized(TEE_ObjectHandle object)
{
	return (object->objectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED);
}

static bool is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 */
	return (attr_ID & TEE_ATTR_FLAG_VALUE);
}

static bool is_public_attribute(uint32_t attr_ID)
{
	/* Bit [28]:
	 * 0: protected attribute
	 * 1: public attribute
	 */
	return (attr_ID & TEE_ATTR_FLAG_VALUE);
}

static bool multiple_of_8(uint32_t number)
{
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
}

static void reset_attrs(TEE_ObjectHandle obj)
{
	size_t i;

	for (i = 0; i < obj->attrs_count; ++i) {
		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			memset(obj->attrs[i].content.ref.buffer, 0, obj->attrs[i].content.ref.length);
		}

		memset(&obj->attrs[i], 0, sizeof(TEE_Attribute));
	}
}

static bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count)
{
	size_t i;

	for (i = 0; i < attrs_count; ++i) {
		object->attrs[i].content.ref.buffer = TEE_Malloc(object->maxObjSizeBytes, 0);
		if (object->attrs[i].content.ref.buffer == NULL)
			return false;

		object->attrs[i].content.ref.length = object->maxObjSizeBytes; /* malloc space (or should be maxObjectSize?) */
	}

	return true;
}

static void free_attrs(TEE_ObjectHandle object)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (is_value_attribute(object->attrs[i].attributeID)) {
			object->attrs->content.value.a = 0;
			object->attrs->content.value.b = 0;
			continue;
		}

		object->attrs[i].content.ref.length = 0;
		free(object->attrs[i].content.ref.buffer);
	}
}

static bool valid_object_max_size(object_type obj, uint32_t size)
{
	switch (obj) {
	case TEE_TYPE_AES:
		if (size == 128 || size == 192 || size == 256)
			return true;
		return false;

	case TEE_TYPE_DES:
		if (size == 56)
			return true;
		return false;

	case TEE_TYPE_DES3:
		if (size == 112 || size == 168)
			return true;
		return false;

	case TEE_TYPE_HMAC_MD5:
		if (size >= 80 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA1:
		if (size >= 112 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA224:
		if (size >= 192 && size <= 512 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA256:
		if (size >= 256 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA384:
		if (size >= 64 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA512:
		if (size >= 64 && size <= 1024 && multiple_of_8(size))
			return true;
		return false;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_RSA_KEYPAIR:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (size >= 512 && size <= 1024 && multiple_of_64(size))
			return true;
		return false;

	case TEE_TYPE_DSA_KEYPAIR:
		if (size >= 512 && size <= 1024 && multiple_of_64(size))
			return true;
		return false;

	case TEE_TYPE_DH_KEYPAIR:
		if (size >= 256 && size <= 2048)
			return true;
		return false;

	case TEE_TYPE_GENERIC_SECRET:
		if (size >= 8 && size <= 4096 && multiple_of_8(size))
			return true;
		return false;

	default:
		return false;
	}
}

static int valid_obj_type_and_attr_count(object_type obj)
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

static int get_attr_index(TEE_ObjectHandle object, uint32_t attributeID)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (object->attrs[i].attributeID == attributeID)
			return i;
	}

	return -1;
}


/*
 * ## Internal API functions ##
 */

void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo* objectInfo)
{
	if (object == NULL || objectInfo == NULL)
		return;

	memcpy(objectInfo, object->objectInfo, sizeof(objectInfo));
}

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
	if (object == NULL)
		return;

	object->objectInfo->objectUsage = objectUsage ^ object->objectInfo->objectUsage;
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object, uint32_t attributeID, void* buffer, size_t* size)
{
	int attr_index = -1;

	/* Check input parameters */
	if (object == NULL) {
		syslog(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (buffer == NULL) {
		syslog(LOG_ERR, "buffer NULL\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Is this buffer attribute */
	if (is_value_attribute(attributeID)) {
		/* panic(); */
		syslog(LOG_ERR, "Not a buffer attribute\n");
		return TEE_ERROR_GENERIC;
	}

	/* Find attribute, if it is found */
	attr_index = get_attr_index(object, attributeID);

	/* NB! This take a count initialization status! */
	if (attr_index == -1) {
		syslog(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found*/

	if (!is_public_attribute(attributeID) && !is_usage_extractable(object)) {
		/* panic(); */
		syslog(LOG_ERR, "Not axtractable attribute\n");
		return TEE_ERROR_GENERIC;
	}

	if (object->attrs[attr_index].content.ref.length > *size) {
		syslog(LOG_ERR, "Short buffer\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(buffer, &object->attrs[attr_index].content.ref.buffer, object->attrs[attr_index].content.ref.length);
	*size = object->attrs[attr_index].content.ref.length;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object, uint32_t attributeID, uint32_t* a, uint32_t* b)
{
	int attr_index = -1;

	/* Check input parameters */
	if (object == NULL) {
		syslog(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (a == NULL && b == NULL) {
		syslog(LOG_ERR, "A and B NULL\n");
		return TEE_SUCCESS; /* ? */
	}

	if (!is_value_attribute(attributeID)) {
		/* panic(); */
	}

	/* Find attribute, if it is found */

	attr_index = get_attr_index(object, attributeID);

	/* NB! This take a count initialization status! */
	if (attr_index == -1) {
		syslog(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found*/

	if (!is_public_attribute(attributeID) && !is_usage_extractable(object)) {
		/* panic(); */
		syslog(LOG_ERR, "Not axtractable attribute\n");
		return TEE_ERROR_GENERIC;
	}

	if (a != NULL)
		*a = object->attrs[attr_index].content.value.a;

	if (b != NULL)
		*b = object->attrs[attr_index].content.value.b;

	return TEE_SUCCESS;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	if (!is_persistent_obj(object)) {
		TEE_FreeTransientObject(object);
	}

	/* TODO: per functionality */
}

TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxObjectSize, TEE_ObjectHandle* object)
{
	TEE_ObjectHandle tmp_handle;
	int attr_count = valid_obj_type_and_attr_count(objectType);

	/* Check parameters */
	if (attr_count == -1) {
		syslog(LOG_ERR, "Not valid object type\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}
	if (!valid_object_max_size(objectType, maxObjectSize)) {
		syslog(LOG_ERR, "Not valid object max size\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Alloc memory for objectHandle */
	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		goto out_of_mem_handle;

	tmp_handle->objectInfo = TEE_Malloc(sizeof(TEE_ObjectInfo), 0);
	if (tmp_handle->objectInfo == NULL)
		goto out_of_mem_info;

	/* object info */
	tmp_handle->objectInfo->objectUsage = 0xFFFFFFFF;
	tmp_handle->objectInfo->maxObjectSize = maxObjectSize;
	tmp_handle->objectInfo->objectType = objectType;
	tmp_handle->objectInfo->objectSize = 0;
	tmp_handle->objectInfo->dataSize = 0;
	tmp_handle->objectInfo->handleFlags = 0x00000000;
	tmp_handle->attrs_count = attr_count;
	tmp_handle->maxObjSizeBytes = (maxObjectSize + 7) / 8;

	/* Alloc memory for attributes (pointers) */
	tmp_handle->attrs = TEE_Malloc(attr_count * sizeof(TEE_Attribute), 0);
	if (tmp_handle->attrs == NULL)
		goto out_of_mem_attrs_ptr;

	/* Alloc memory for object attributes */
	switch(objectType) {
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
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_DH_KEYPAIR:
		/* -1, because DH contains one value attribute */
		if (!malloc_for_attrs(tmp_handle, attr_count-1))
			goto out_of_mem_attrs;
		break;

	default:
		break; /* Should never get here */
	}

	*object = tmp_handle;

	return TEE_SUCCESS;

out_of_mem_attrs:
	free(tmp_handle->attrs);
	free(tmp_handle->objectInfo);
out_of_mem_attrs_ptr:
	free(tmp_handle);
	free(tmp_handle->objectInfo);
out_of_mem_info:
	free(tmp_handle);
out_of_mem_handle:
	syslog(LOG_ERR, "Out of memory\n");

	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	/* TODO: add persistant object functionality */

	if (object == NULL)
		return;

	if (!is_persistent_obj(object)) {
		free_attrs(object);
		free(object->attrs);
		free(object->objectInfo);
		free(object);
	}
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	/* Reset info */
	object->objectInfo->objectUsage = 0xFFFFFFFF;
	object->objectInfo->objectSize = 0;
	object->objectInfo->dataSize = 0;
	object->objectInfo->handleFlags = 0x00000000;

	reset_attrs(object);

	/* KEY RESET! */
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object, TEE_Attribute* attrs, uint32_t attrCount)
{
	uint32_t i = 0;

	if (object == NULL || attrs == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_initialized(object)) {
		syslog(LOG_ERR, "Can not populate initialized object\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch(object->objectInfo->objectType) {
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
		if (extract_attr_to_object(TEE_ATTR_SECRET_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_RSA_KEYPAIR:
		if (does_arr_contain_attrID(TEE_ATTR_RSA_PRIME1, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_PRIME2, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount) ||
		    does_arr_contain_attrID(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount)) {

			if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIME1, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIME2, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount, object, i++))
				break;
		}

		else {
			if (extract_attr_to_object(TEE_ATTR_RSA_MODULUS, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount, object, i++) &&
			    extract_attr_to_object(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount, object, i++))
				break;
		}

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PUBLIC_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_DSA_KEYPAIR:
		if (extract_attr_to_object(TEE_ATTR_DSA_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_SUBPRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PRIVATE_VALUE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DSA_PUBLIC_VALUE, attrs, attrCount, object, i++))
			break;

	case TEE_TYPE_DH_KEYPAIR:
		if (extract_attr_to_object(TEE_ATTR_DH_PRIME, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_BASE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_PUBLIC_VALUE, attrs, attrCount, object, i++) &&
		    extract_attr_to_object(TEE_ATTR_DH_PRIVATE_VALUE, attrs, attrCount, object, i++)) {
			extract_attr_to_object(TEE_ATTR_DH_SUBPRIME, attrs, attrCount, object, i++);
			break;
		}

	default:
		/* Correct response would be PANIC, but not yet implmented */
		free_attrs(object);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object->objectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED; /* TODO: CHECK!! */
	
	return TEE_SUCCESS;
}

void TEE_InitRefAttribute(TEE_Attribute* attr, uint32_t attributeID, void* buffer, size_t length)
{
	if (attr == NULL)
		return;
	
	if (is_value_attribute(attributeID)) {
		syslog(LOG_ERR, "Not a value attribute\n");
		/* panic() */
	}

	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute* attr, uint32_t attributeID, uint32_t a, uint32_t b)
{
	if (attr == NULL)
		return;

	if (!is_value_attribute(attributeID)) {
		syslog(LOG_ERR, "Not a value attribute\n");
		/* panic() */
	}

	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject, TEE_ObjectHandle srcObject)
{
	size_t i = 0;

	if (destObject == NULL || srcObject == NULL)
		return;

	if (is_initialized(destObject) || !is_initialized(srcObject)) {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	if (srcObject->maxObjSizeBytes > destObject->maxObjSizeBytes) {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	/* Extract attributes, if possible */
	if (destObject->objectInfo->objectType == srcObject->objectInfo->objectType) {
		if (srcObject->attrs_count != destObject->attrs_count) {
			/* Should never end up here */
			return;
		}

		for (i = 0; i < srcObject->attrs_count; ++i) {
			if (copy_obj_attr_to_obj(srcObject, EMU_ALL, destObject, i) < 0)
				/* Correct would e panic, but not implemented (yet) */
				return;
		}
	}

	else if (destObject->objectInfo->objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		 srcObject->objectInfo->objectType == TEE_TYPE_RSA_KEYPAIR) {
		if (copy_obj_attr_to_obj(srcObject, TEE_ATTR_RSA_MODULUS, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, TEE_ATTR_RSA_PUBLIC_EXPONENT, destObject, i++) < 0) {
			/* Correct would e panic, but not implemented (yet) */
			return;
		}

	}

	else if (destObject->objectInfo->objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		 srcObject->objectInfo->objectType == TEE_TYPE_DSA_KEYPAIR) {
		if (copy_obj_attr_to_obj(srcObject, TEE_ATTR_DSA_PUBLIC_VALUE, destObject, i++) < 0 ||
		    copy_obj_attr_to_obj(srcObject, 0, destObject, i++) < 0) {
			/* Correct would e panic, but not implemented (yet) */
			return;
		}
	}

	else {
		/* Correct would e panic, but not implemented (yet) */
		return;
	}

	destObject->objectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED; /* TODO: CHECK!! */
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute* params, uint32_t paramCount)
{
	int ret_val = 1;

	if (object == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo->maxObjectSize < keySize) {
		syslog(LOG_ERR, "KeySize is too large\n");
		/* panic() */
	}

	/* Should be a transient object and uninit */
	if (is_persistent_obj(object) || is_initialized(object)) {
		/* panic() */
	}

	switch(object->objectInfo->objectType) {
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
		ret_val = gen_10_key(object, keySize);
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret_val = gen_rsa_keypair(object, keySize);
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		ret_val = gen_dsa_keypair(object, params, paramCount);
		break;

	case TEE_TYPE_DH_KEYPAIR:
		ret_val = gen_dh_keypair(object, params, paramCount);
		break;

	default:
		break; /* panic() Should never get here */
	}

	if (ret_val == -1) {
		/* If ret_val is -1, KeySize too large or mandatory parameter missing
		 * Correct response would be PANIC, but not yet implmented */
		return TEE_ERROR_GENERIC;
	}

	if (ret_val == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object->objectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED; /* TODO: CHECK!! */

	return TEE_SUCCESS;
}
