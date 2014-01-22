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

#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "storage_data_key_api.h"
#include "tee_memory.h"

struct __TEE_ObjectHandle {
	TEE_ObjectInfo *objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	void *public_key;
	void *private_ley;
};


/*
 * ## TEMP, wil be removed. Function intorduction ##
 */
static bool is_value_attribute(uint32_t attr_ID); /* ok */
static bool valid_attrID(int32_t attributeID); /* ok */
static void reset_attrs(TEE_ObjectHandle obj); /* ok */
static TEE_Result handle_first_10_popu(TEE_ObjectHandle object, TEE_Attribute* attrs, uint32_t attrCount);
static bool handle_first_10_malloc(TEE_ObjectHandle object, uint32_t len);
static void free_attrs(TEE_ObjectHandle object);
static bool is_initialized(uint32_t handleFlags);
static bool multiple_of_8(uint32_t number);
static bool multiple_of_64(uint32_t number);
static bool valid_object_max_size(object_type obj, uint32_t size);
static int valid_obj_type_and_attr_count(object_type obj);
static bool gen_key_AES(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute* params, uint32_t paramCount);
static bool is_persistent_obj(TEE_ObjectHandle object);

/*
 * ## Non internal API functions ##
 */

static bool is_persistent_obj(TEE_ObjectHandle object)
{
	return (object->objectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT);
}

static bool gen_10_key(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute* params, uint32_t paramCount)
{
	size_t i;
	bool found_ATTR_SECRET_VALUE = false;

	/* Maybe not first */
	for (i = 0; i < paramCount; ++i) {
		if (params[i].attributeID == TEE_ATTR_SECRET_VALUE) {
			found_ATTR_SECRET_VALUE = true;
			object->attrs->content.ref.length = object->attrs[i].content.ref.length;
			object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;
			memcpy(&object->attrs[0], &params[i], sizeof(TEE_Attribute) + object->attrs->content.ref.length);
			return true;
		}
	}

	unsigned char buf[12];
		unsigned char* buf_ptr = buf;
		RAND_bytes(buf, 12);
/*	if (!RAND_bytes(object->attrs->content.ref.buffer, object->objectInfo->maxObjectSize / 8))
		return false;
*/
	return true;
}

static bool is_value_attribute(uint32_t attr_ID)
{
	/* if bit 29 is not 1 == buffer attribute */
	return (attr_ID & (1 << 29));
}

static bool valid_attrID(int32_t attributeID)
{
	switch(attributeID) {
	case TEE_ATTR_SECRET_VALUE:
	case TEE_ATTR_RSA_MODULUS:
	case TEE_ATTR_RSA_PUBLIC_EXPONENT:
	case TEE_ATTR_RSA_PRIVATE_EXPONENT:
	case TEE_ATTR_RSA_PRIME1:
	case TEE_ATTR_RSA_PRIME2:
	case TEE_ATTR_RSA_EXPONENT1:
	case TEE_ATTR_RSA_EXPONENT2:
	case TEE_ATTR_RSA_COEFFICIENT:
	case TEE_ATTR_DSA_PRIME:
	case TEE_ATTR_DSA_SUBPRIME:
	case TEE_ATTR_DSA_BASE:
	case TEE_ATTR_DSA_PUBLIC_VALUE:
	case TEE_ATTR_DSA_PRIVATE_VALUE:
	case TEE_ATTR_DH_PRIME:
	case TEE_ATTR_DH_SUBPRIME:
	case TEE_ATTR_DH_BASE:
	case TEE_ATTR_DH_X_BITS:
	case TEE_ATTR_DH_PUBLIC_VALUE:
	case TEE_ATTR_DH_PRIVATE_VALUE:
	case TEE_ATTR_RSA_OAEP_LABEL:
	case TEE_ATTR_RSA_PSS_SALT_LENGTH:
		return true;
		break;

	default:
		return false;
	}
}

static void reset_attrs(TEE_ObjectHandle obj)
{
	size_t i, len;

	for (i = 0; i < obj->attrs_count; ++i) {
		len = sizeof(TEE_Attribute);
		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			len += obj->attrs[i].content.ref.length;
		}

		memset(&obj->attrs[i], 0, len);
	}
}

/*!
 * \brief handle_first_10
 * Function handles following attributes initilization to objec:
 * TEE_TYPE_DES, TEE_TYPE_DES3, TEE_TYPE_HMAC_MD5, TEE_TYPE_HMAC_SHA1, TEE_TYPE_HMAC_SHA224,
 * TEE_TYPE_HMAC_SHA256, TEE_TYPE_HMAC_SHA384, TEE_TYPE_HMAC_SHA512, TEE_TYPE_GENERIC_SECRET
 * \param object
 * \param attrs
 * \param attrCount
 * \return
 */
static TEE_Result handle_first_10_popu(TEE_ObjectHandle object, TEE_Attribute* attrs, uint32_t attrCount)
{	
	size_t i;
	size_t buf_len;

	/* For loop is need, because there can be more than one value and wanted is not first */
	for (i = 0; i < attrCount; ++i) {
		if (attrs[i].attributeID == TEE_ATTR_SECRET_VALUE) {
			buf_len = object->attrs[i].content.ref.length;
			object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;
			memcpy(&object->attrs[0], &attrs[i], sizeof(TEE_Attribute) + buf_len);
			return TEE_SUCCESS;
		}
	}

	syslog(LOG_ERR, "Provide all necessery parameter(s)\n");
	return TEE_ERROR_BAD_PARAMETERS;
}

static bool handle_first_10_malloc(TEE_ObjectHandle object, uint32_t len)
{
	object->attrs->content.ref.buffer = TEE_Malloc((len + 8) / 8, 0);
	if (object->attrs->content.ref.buffer == NULL)
		return false;

	object->attrs->content.ref.length = (len + 8) / 8; /* malloc space or should be maxObjectSize? */

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

		if (object->attrs[i].content.ref.buffer != NULL) {
			object->attrs[i].content.ref.length = 0;
			free(object->attrs[i].content.ref.buffer);
		}
	}
}

static bool is_initialized(uint32_t handleFlags)
{
	/*chnge to (handleFlags & TEE_HANDLE_FLAG_INITIALIZED) */
	return (handleFlags & TEE_HANDLE_FLAG_INITIALIZED);
}

static bool multiple_of_8(uint32_t number)
{
	/* Keeping the ? : -operation */
	return !(number % 8) ? true : false;
}

static bool multiple_of_64(uint32_t number)
{
	return !(number % 64) ? true : false;
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

/*
 * ## Internal API functions
 */
TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxObjectSize, TEE_ObjectHandle* object)
{
	TEE_ObjectHandle tmp_handle;
	int attr_count = valid_obj_type_and_attr_count(objectType);

	/* Check parameters */
	if (attr_count == -1) {
		syslog(LOG_ERR, "Not valid object type\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (valid_object_max_size(objectType, maxObjectSize)) {
		syslog(LOG_ERR, "Not valid object max size\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Alloc memory for objectHandle and initialize */
	
	/* For object handle */
	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		goto out_of_mem_info;

	/* object info */
	tmp_handle->objectInfo->objectUsage = 0xFFFFFFFF;
	tmp_handle->objectInfo->maxObjectSize = maxObjectSize;
	tmp_handle->objectInfo->objectType = objectType;
	tmp_handle->objectInfo->objectSize = 0;
	tmp_handle->objectInfo->dataSize = 0;
	tmp_handle->objectInfo->handleFlags = 0x00000000;
	tmp_handle->attrs_count = attr_count;


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
		if (!handle_first_10_malloc(tmp_handle, tmp_handle->objectInfo->maxObjectSize))
			goto out_of_mem_attrs;
		break;

	case TEE_TYPE_RSA_KEYPAIR: /* TODO */
	case TEE_TYPE_DSA_PUBLIC_KEY: /* TODO */
	case TEE_TYPE_DSA_KEYPAIR: /* TODO */
	case TEE_TYPE_DH_KEYPAIR: /* TODO */
	default:
		break; /* Should never get here */
	}

	*object = tmp_handle;

	return TEE_SUCCESS;


out_of_mem_attrs:
	free(tmp_handle->attrs);
out_of_mem_attrs_ptr:
	free(tmp_handle);
out_of_mem_info:
	syslog(LOG_ERR, "Out of memory\n");
	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	/* Should check that this is a valid object (opened) */

	free_attrs(object);
	free(object->attrs);
	free(object);

	/* KEY CLEAR! */
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
	TEE_Result return_value;

	if (object == NULL || attrs == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/*no fucn*/
	if (is_initialized(object->objectInfo->handleFlags)) {
		syslog(LOG_ERR, "Initialized container\n");
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
		return_value = handle_first_10_popu(object, attrs, attrCount);
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY: /* TODO */
	case TEE_TYPE_RSA_KEYPAIR: /* TODO */
	case TEE_TYPE_DSA_PUBLIC_KEY: /* TODO */
	case TEE_TYPE_DSA_KEYPAIR: /* TODO */
	case TEE_TYPE_DH_KEYPAIR: /* TODO */
	default:
		return_value = TEE_ERROR_BAD_PARAMETERS;
	}

	/* set initialization flag */
	object->objectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	
	return return_value;
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

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute* params, uint32_t paramCount)
{
	if (object == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo->maxObjectSize < keySize) {
		syslog(LOG_ERR, "KeySize is too large\n");
		/* panic() */
	}

	/* Should be a transient object and uninit */
	if (is_persistent_obj(object) || is_initialized(object->objectInfo->handleFlags))
		/* panic() */

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
		if (gen_10_key(object, keySize, params, paramCount))
			/* panic() */
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
	case TEE_TYPE_DH_KEYPAIR:
	default:
		break; /* panic() Should never get here */
	}

	return TEE_SUCCESS;
}




