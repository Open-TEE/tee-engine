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

#define _GNU_SOURCE

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/des.h>

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "tee_storage_api.h"
#include "tee_memory.h"
#include "tee_panic.h"
#include "tee_storage_common.h"
#include "tee_object_handle.h"
#include "tee_logging.h"
#include "tee_time_api.h" /*TEE_TIMEOUT_INFINITE*/
#include "com_protocol.h" /*MGR CMD IDs*/
#include "tee_internal_client_api.h"

#include "opentee_internal_api.h"
#include "opentee_storage_common.h"

static void openssl_cleanup()
{
	CRYPTO_cleanup_all_ex_data();
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


static int get_attr_index_from_attrArr(uint32_t ID, TEE_Attribute *attrs, uint32_t attrCount)
{
	size_t i;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID)
			return i;
	}

	return -1;
}



static bool copy_attr_from_obj_to_obj(TEE_ObjectHandle srcObj, uint32_t cpy_attrID,
				      TEE_ObjectHandle destObj, uint32_t destIndex)
{
	int srcIndex = get_attr_index(srcObj, cpy_attrID);

	if (srcIndex == -1)
		return false; /* Object does not contain copied attribute */

	if (destIndex >= destObj->attrs_count)
		return false; /* Should never happen */

	cpy_attr(srcObj, srcIndex, destObj, destIndex);

	return true;
}

static bool copy_attr_from_attrArr_to_object(TEE_Attribute *params, uint32_t paramCount,
					     uint32_t cpy_attr_ID, TEE_ObjectHandle object,
					     uint32_t dest_index)
{
	int attr_index = get_attr_index_from_attrArr(cpy_attr_ID, params, paramCount);
	;

	if (attr_index == -1)
		return false; /* Array does not contain extracted attribute */

	if (dest_index >= object->attrs_count)
		return false; /* Should never happen */

	if (is_value_attribute(params[attr_index].attributeID)) {
		memcpy(&object->attrs[dest_index], &params[attr_index], sizeof(TEE_Attribute));
	} else {
		object->attrs[dest_index].attributeID = params[attr_index].attributeID;

		if (params[attr_index].content.ref.length > object->maxObjSizeBytes)
			object->attrs[dest_index].content.ref.length = object->maxObjSizeBytes;
		else
			object->attrs[dest_index].content.ref.length =
			    params[attr_index].content.ref.length;

		memcpy(object->attrs[dest_index].content.ref.buffer,
		       params[attr_index].content.ref.buffer,
		       object->attrs[dest_index].content.ref.length);
	}

	return true;
}

static bool bn_to_obj_ref_attr(BIGNUM *bn, uint32_t atrr_ID, TEE_ObjectHandle obj, int obj_index)
{
	/* add suslog */
	obj->attrs[obj_index].content.ref.length = BN_num_bytes(bn);
	if (obj->attrs[obj_index].content.ref.length > obj->maxObjSizeBytes)
		return false;

	obj->attrs[obj_index].attributeID = atrr_ID;
	if (BN_bn2bin(bn, obj->attrs[obj_index].content.ref.buffer) == 0) {
		OT_LOG(LOG_ERR, "BN2bin failed (openssl failure)\n");
		return false;
	}

	return true;
}

static TEE_Result gen_des_key(TEE_ObjectHandle object, uint32_t keySize)
{
	DES_cblock key1;
	DES_cblock key2;
	DES_cblock key3;

	object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;

	/* 56 des key */
	DES_random_key(&key1);
	memcpy(object->attrs->content.ref.buffer, key1, sizeof(key1));

	if (keySize <= 56) {
		object->attrs->content.ref.length = sizeof(key1);
		return TEE_SUCCESS;
	}

	DES_random_key(&key2);
	memcpy((unsigned char *)object->attrs->content.ref.buffer + sizeof(key1), key2,
	       sizeof(key2));

	if (keySize <= 112) {
		object->attrs->content.ref.length = sizeof(key1) + sizeof(key2);
		return TEE_SUCCESS;
	}

	DES_random_key(&key3);
	memcpy((unsigned char *)object->attrs->content.ref.buffer + sizeof(key1) + sizeof(key2),
	       key3, sizeof(key3));
	object->attrs->content.ref.length = sizeof(key1) + sizeof(key2) + sizeof(key3);

	return TEE_SUCCESS;
}

static TEE_Result gen_symmetric_key(TEE_ObjectHandle object, uint32_t keySize)
{
	if (!RAND_bytes(object->attrs->content.ref.buffer, keysize_in_bits(keySize))) {
		OT_LOG(LOG_ERR, "Cannot create random bytes (openssl failure)\n");
		return TEE_ERROR_GENERIC;
	}

	object->attrs->attributeID = TEE_ATTR_SECRET_VALUE;
	object->attrs->content.ref.length = keysize_in_bits(keySize);

	return TEE_SUCCESS;
}

static TEE_Result gen_rsa_keypair(TEE_ObjectHandle obj, uint32_t key_size, TEE_Attribute *params,
				  uint32_t paramCount)
{
	int i = 0; /* Attribute index at object */
	TEE_Result ret_val = TEE_SUCCESS;
	RSA *rsa_key = NULL;
	BIGNUM *bn_pub_exp = NULL;
	int pub_exp_index_at_params =
	    get_attr_index_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, params, paramCount);

	rsa_key = RSA_new();
	if (rsa_key == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for RSA key (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	bn_pub_exp = BN_new();
	if (bn_pub_exp == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for public exp (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (pub_exp_index_at_params != -1) {
		bn_pub_exp =
		    BN_bin2bn(params[pub_exp_index_at_params].content.ref.buffer,
			      params[pub_exp_index_at_params].content.ref.length, bn_pub_exp);
		if (bn_pub_exp == NULL) {
			OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
			ret_val = TEE_ERROR_GENERIC;
			goto ret;
		}
	} else {
		/* RSA_F4 == 65537 */
		if (BN_set_word(bn_pub_exp, RSA_F4) == 0) {
			OT_LOG(LOG_ERR, "bn_set_word failed (openssl failure)\n");
			ret_val = TEE_ERROR_GENERIC;
			goto ret;
		}
	}

	if (!RSA_generate_key_ex(rsa_key, key_size, bn_pub_exp, NULL)) {
		OT_LOG(LOG_ERR, "RSA key generation failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!RSA_check_key(rsa_key)) {
		OT_LOG(LOG_ERR, "RSA key generation failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	/* Extract/copy values from RSA struct to object */

	if (!bn_to_obj_ref_attr(rsa_key->n, TEE_ATTR_RSA_MODULUS, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->e, TEE_ATTR_RSA_PUBLIC_EXPONENT, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->d, TEE_ATTR_RSA_PRIVATE_EXPONENT, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->p, TEE_ATTR_RSA_PRIME1, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->q, TEE_ATTR_RSA_PRIME2, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->dmp1, TEE_ATTR_RSA_EXPONENT1, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->dmq1, TEE_ATTR_RSA_EXPONENT2, obj, i++) ||
	    !bn_to_obj_ref_attr(rsa_key->iqmp, TEE_ATTR_RSA_COEFFICIENT, obj, i++)) {
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

ret:
	if (rsa_key != NULL)
		RSA_free(rsa_key);
	if (bn_pub_exp != NULL)
		BN_clear_free(bn_pub_exp);
	return ret_val;
}

static TEE_Result gen_dsa_keypair(TEE_ObjectHandle object, TEE_Attribute *params,
				  uint32_t paramCount)
{
	int i = 0; /* Attribute index at object */
	int attr_index = 0;
	TEE_Result ret_val = TEE_SUCCESS;
	DSA *dsa_key = NULL;

	dsa_key = DSA_new();
	if (dsa_key == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for DSA key (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!copy_attr_from_attrArr_to_object(params, paramCount, TEE_ATTR_DSA_PRIME, object, i++) ||
	    !copy_attr_from_attrArr_to_object(params, paramCount, TEE_ATTR_DSA_SUBPRIME,  object, i++) ||
	    !copy_attr_from_attrArr_to_object(params, paramCount, TEE_ATTR_DSA_BASE, object, i++)) {
		OT_LOG(LOG_ERR, "DSA key generation failed. Provide all mandatory parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr_index = get_attr_index(object, TEE_ATTR_DSA_PRIME);
	dsa_key->p = BN_bin2bn(object->attrs[attr_index].content.ref.buffer,
			       object->attrs[attr_index].content.ref.length, dsa_key->p);
	if (dsa_key->p == NULL) {
		OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DSA_SUBPRIME);
	dsa_key->q = BN_bin2bn(object->attrs[attr_index].content.ref.buffer,
			       object->attrs[attr_index].content.ref.length, dsa_key->q);
	if (!dsa_key->q) {
		OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DSA_BASE);
	dsa_key->g = BN_bin2bn(object->attrs[attr_index].content.ref.buffer,
			       object->attrs[attr_index].content.ref.length, dsa_key->g);
	if (!dsa_key->g) {
		OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!DSA_generate_key(dsa_key)) {
		OT_LOG(LOG_ERR, "DSA key generation failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!bn_to_obj_ref_attr(dsa_key->pub_key, TEE_ATTR_DSA_PUBLIC_VALUE, object, i++) ||
	    !bn_to_obj_ref_attr(dsa_key->priv_key, TEE_ATTR_DSA_PRIVATE_VALUE, object, i++)) {
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

ret:
	if (dsa_key != NULL)
		DSA_free(dsa_key);
	return ret_val;
}

static TEE_Result gen_dh_keypair(TEE_ObjectHandle object, TEE_Attribute *params,
				 uint32_t paramCount)
{
	int i = 0; /* Attribute index at object */
	int attr_index = 0;
	TEE_Result ret_val = TEE_SUCCESS;
	DH *dh_key = NULL;

	dh_key = DH_new();
	if (dh_key == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for DH key (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!copy_attr_from_attrArr_to_object(params, paramCount, TEE_ATTR_DH_PRIME, object, i++) ||
	    !copy_attr_from_attrArr_to_object(params, paramCount, TEE_ATTR_DH_BASE, object, i++)) {
		OT_LOG(LOG_ERR, "DH key generation failed. Provide all mandatory parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr_index = get_attr_index(object, TEE_ATTR_DH_PRIME);
	dh_key->p = BN_bin2bn(object->attrs[attr_index].content.ref.buffer,
			      object->attrs[attr_index].content.ref.length, dh_key->p);
	if (dh_key->p == NULL) {
		OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	attr_index = get_attr_index(object, TEE_ATTR_DH_BASE);
	dh_key->g = BN_bin2bn(object->attrs[attr_index].content.ref.buffer,
			      object->attrs[attr_index].content.ref.length, dh_key->g);
	if (dh_key->g == NULL) {
		OT_LOG(LOG_ERR, "bin2bn failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!DH_generate_key(dh_key)) {
		OT_LOG(LOG_ERR, "DH key generation failed (openssl failure)\n");
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

	if (!bn_to_obj_ref_attr(dh_key->pub_key, TEE_ATTR_DH_PUBLIC_VALUE, object, i++) ||
	    !bn_to_obj_ref_attr(dh_key->priv_key, TEE_ATTR_DH_PRIVATE_VALUE, object, i++)) {
		ret_val = TEE_ERROR_GENERIC;
		goto ret;
	}

ret:
	if (dh_key != NULL)
		DH_free(dh_key);
	return ret_val;
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
		if (is_value_attribute(obj->attrs[i].attributeID)) {
			obj->attrs[i].content.value.a = 0;
			obj->attrs[i].content.value.b = 0;
		} else {
			if (!RAND_bytes(obj->attrs[i].content.ref.buffer, obj->maxObjSizeBytes))
				memset(obj->attrs[i].content.ref.buffer, 0,
				       obj->attrs[i].content.ref.length);

			obj->attrs[i].content.ref.length = 0;
		}

		obj->attrs[i].attributeID = 0;
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

static int get_attr_index_and_check_rights(TEE_ObjectHandle object, uint32_t attributeID)
{
	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Object not initialized\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (!(attributeID & TEE_ATTR_FLAG_PUBLIC) &&
	    !(object->objectInfo.objectUsage & TEE_USAGE_EXTRACTABLE)) {
		OT_LOG(LOG_ERR, "Not axtractable attribute\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	return get_attr_index(object, attributeID);
}

static uint32_t key_raw_size(uint32_t objectType, uint32_t key)
{
	switch (objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
		/* Always 56 bit 8 parity bit = 64bit */
		return keysize_in_bits(key) + 1;

	case TEE_TYPE_DES3:
		if (key == 112)
			return keysize_in_bits(key) + 2;

		if (key == 168)
			return keysize_in_bits(key) + 3;

	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
	case TEE_TYPE_DH_KEYPAIR:
	default:
		return keysize_in_bits(key);
	}
}

/************************************************************************************************
*												 *
*												 *
*												 *
*												 *
* ############################################################################################# *
* #											       # *
* #  ---------------------------------------------------------------------------------------  # *
* #  |										            |  # *
* #  | #    #   #  # ## I n t e r n a l   A P I   f u n c t i o n s ## #  #   #    #     # |  # *
* #  |										            |  # *
* #  ---------------------------------------------------------------------------------------  # *
* #											       # *
* ############################################################################################# *
*												 *
*												 *
*												 *
*												 *
************************************************************************************************/

void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo)
{
	if (object == NULL || objectInfo == NULL)
		return;

	memcpy(objectInfo, &object->objectInfo, sizeof(TEE_ObjectInfo));

	/* data pos */
	if (object->per_object.data_position > UINT32_MAX)
		objectInfo->dataPosition = UINT32_MAX;
	else
		objectInfo->dataPosition = object->per_object.data_position;

	/* data size */
	if (object->per_object.data_size > UINT32_MAX)
		objectInfo->dataSize = UINT32_MAX;
	else
		objectInfo->dataSize = object->per_object.data_size;

	/* obj size */
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)
		objectInfo->objectSize = object_attribute_size(object);
	else
		objectInfo->objectSize = 0;
}

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
	if (object == NULL)
		return;

	object->objectInfo.objectUsage ^= objectUsage;
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object, uint32_t attributeID, void *buffer,
					size_t *size)
{
	int attr_index;

	/* Check input parameters */
	if (object == NULL) {
		OT_LOG(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (buffer == NULL || size == NULL) {
		OT_LOG(LOG_ERR, "Size or buffer NULL\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Is this buffer attribute */
	if (is_value_attribute(attributeID)) {
		OT_LOG(LOG_ERR, "Not a buffer attribute\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	/* Find attribute, if it is found */
	attr_index = get_attr_index_and_check_rights(object, attributeID);
	if (attr_index == -1) {
		OT_LOG(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found */

	if (object->attrs[attr_index].content.ref.length > *size) {
		OT_LOG(LOG_ERR, "Short buffer\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(buffer, object->attrs[attr_index].content.ref.buffer,
	       object->attrs[attr_index].content.ref.length);

	*size = object->attrs[attr_index].content.ref.length;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object, uint32_t attributeID, uint32_t *a,
				       uint32_t *b)
{
	int attr_index;

	/* Check input parameters */
	if (object == NULL) {
		OT_LOG(LOG_ERR, "Object NULL\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (!is_value_attribute(attributeID)) {
		OT_LOG(LOG_ERR, "Not a value attribute\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	attr_index = get_attr_index_and_check_rights(object, attributeID);
	if (attr_index == -1) {
		OT_LOG(LOG_ERR, "Attribute not found\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Attribute found */

	if (a != NULL)
		*a = object->attrs[attr_index].content.value.a;

	if (b != NULL)
		*b = object->attrs[attr_index].content.value.b;

	return TEE_SUCCESS;
}

TEE_Result TEE_AllocateTransientObject(uint32_t objectType, uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	TEE_ObjectHandle tmp_handle;
	int attr_count = valid_obj_type_and_attr_count(objectType);

	/* Check parameters */
	if (attr_count == -1) {
		OT_LOG(LOG_ERR, "Not valid object type\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!valid_object_max_size(objectType, maxObjectSize)) {
		OT_LOG(LOG_ERR, "Not valid object max size\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Alloc memory for objectHandle */
	tmp_handle = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (tmp_handle == NULL)
		goto out_of_mem;

	/* object info */
	tmp_handle->objectInfo.objectUsage = 0xFFFFFFFF;
	tmp_handle->objectInfo.maxObjectSize = maxObjectSize;
	tmp_handle->objectInfo.objectType = objectType;
	tmp_handle->objectInfo.objectSize = 0;
	tmp_handle->objectInfo.dataSize = 0;
	tmp_handle->objectInfo.handleFlags = 0x00000000;
	tmp_handle->attrs_count = attr_count;
	tmp_handle->maxObjSizeBytes = key_raw_size(objectType, maxObjectSize);

	/* Alloc memory for attributes (pointers) */
	tmp_handle->attrs = TEE_Malloc(attr_count * sizeof(TEE_Attribute), 0);
	if (tmp_handle->attrs == NULL)
		goto out_of_mem;

	/* Alloc memory for object attributes */
	switch (objectType) {
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
	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
		if (!malloc_for_attrs(tmp_handle, attr_count))
			goto out_of_mem;
		break;

	case TEE_TYPE_DH_KEYPAIR:
		/* -1, because DH contains one value attribute */
		if (!malloc_for_attrs(tmp_handle, attr_count - 1))
			goto out_of_mem;
		break;

	default:
		/* Should never get here
		 * Let's free all memory */
		goto out_of_mem;
		break;
	}

	*object = tmp_handle;

	return TEE_SUCCESS;

out_of_mem:
	OT_LOG(LOG_ERR, "Out of memory\n");
	free_object(tmp_handle);
	*object = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG(LOG_ERR, "Function is not allowed to a persistant object\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	free_object(object);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL || object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		return;

	/* Reset info */
	object->objectInfo.objectUsage = 0xFFFFFFFF;
	object->objectInfo.objectSize = 0;
	object->objectInfo.dataSize = 0;
	object->objectInfo.handleFlags = 0x00000000;

	reset_attrs(object);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object, TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	uint32_t dest_index = 0;

	if (object == NULL || attrs == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG(LOG_ERR, "Can not populate initialized object or persistant\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (object->attrs_count !=
	    (uint32_t)valid_obj_type_and_attr_count(object->objectInfo.objectType)) {
		/* Should never get here */
		OT_LOG(LOG_ERR, "Something is not right with object\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	switch (object->objectInfo.objectType) {
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
		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_SECRET_VALUE,
						      object, dest_index++))
			goto bad_paras;

		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_MODULUS,
						      object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(
			attrs, attrCount, TEE_ATTR_RSA_PUBLIC_EXPONENT, object, dest_index++))
			goto bad_paras;

		break;

	case TEE_TYPE_RSA_KEYPAIR:
		if (get_attr_index_from_attrArr(TEE_ATTR_RSA_PRIME1, attrs, attrCount) != -1 ||
		    get_attr_index_from_attrArr(TEE_ATTR_RSA_PRIME2, attrs, attrCount) != -1 ||
		    get_attr_index_from_attrArr(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount) != -1 ||
		    get_attr_index_from_attrArr(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount) != -1 ||
		    get_attr_index_from_attrArr(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount) != -1 ) {

			if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_PRIME1,  object, dest_index++) ||
			    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_PRIME2, object, dest_index++) ||
			    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_EXPONENT1, object, dest_index++) ||
			    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_EXPONENT2, object, dest_index++) ||
			    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_COEFFICIENT, object, dest_index++))
				goto bad_paras;
		}

		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_MODULUS, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_PUBLIC_EXPONENT, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_RSA_PRIVATE_EXPONENT, object, dest_index++))
			goto bad_paras;

		break;

	case TEE_TYPE_DSA_PUBLIC_KEY:
		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_PRIME, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_SUBPRIME, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_BASE, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_PUBLIC_VALUE, object, dest_index++))
			goto bad_paras;

		break;

	case TEE_TYPE_DSA_KEYPAIR:
		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_PRIME, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_SUBPRIME, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_BASE, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_PRIVATE_VALUE, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DSA_PUBLIC_VALUE, object, dest_index++))
			goto bad_paras;

		break;

	case TEE_TYPE_DH_KEYPAIR:
		if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DH_PRIME, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DH_BASE, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DH_PUBLIC_VALUE, object, dest_index++) ||
		    !copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DH_PRIVATE_VALUE, object, dest_index++))
			goto bad_paras;

		if (get_attr_index_from_attrArr(TEE_ATTR_DH_SUBPRIME, attrs, attrCount) != -1) {
			if (!copy_attr_from_attrArr_to_object(attrs, attrCount, TEE_ATTR_DH_SUBPRIME, object, dest_index++))
				goto bad_paras;
		}

		break;

	default:
		/* should never get here */
		OT_LOG(LOG_ERR, "Something went wrong when populating transient object\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	return TEE_SUCCESS;

bad_paras:
	OT_LOG(LOG_ERR, "Provide all mandatory parameters\n");
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	return TEE_ERROR_BAD_PARAMETERS; /* Only compile purpose or else reaches non-void.. */
}

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID, void *buffer, size_t length)
{
	if (attr == NULL)
		return;

	if (is_value_attribute(attributeID)) {
		OT_LOG(LOG_ERR, "Not a value attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr->attributeID = attributeID;
	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID, uint32_t a, uint32_t b)
{
	if (attr == NULL)
		return;

	if (!is_value_attribute(attributeID)) {
		OT_LOG(LOG_ERR, "Not a value attribute\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject, TEE_ObjectHandle srcObject)
{
	uint32_t dest_index = 0;

	if (destObject == NULL || srcObject == NULL)
		return;

	if (destObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(srcObject->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Dest object initalized and source object is uninitialized\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (srcObject->maxObjSizeBytes > destObject->maxObjSizeBytes) {
		OT_LOG(LOG_ERR, "Problem with destination and source object size\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Copy attributes, if possible */
	if (destObject->objectInfo.objectType == srcObject->objectInfo.objectType) {
		if (srcObject->attrs_count != destObject->attrs_count) {
			OT_LOG(LOG_ERR, "Can't copy objs, because attribute count do not match\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		copy_all_attributes(srcObject, destObject);

	} else if (destObject->objectInfo.objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		   srcObject->objectInfo.objectType == TEE_TYPE_RSA_KEYPAIR) {
		if (!copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_RSA_MODULUS, destObject, dest_index++) ||
		    !copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_RSA_PUBLIC_EXPONENT, destObject, dest_index++)) {
			OT_LOG(LOG_ERR, "Can not copy objects, because something went wrong\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}
	} else if (destObject->objectInfo.objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		   srcObject->objectInfo.objectType == TEE_TYPE_DSA_KEYPAIR) {
		if (!copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_DSA_PUBLIC_VALUE, destObject, dest_index++) ||
		    !copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_DSA_SUBPRIME, destObject, dest_index++) ||
		    !copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_DSA_BASE, destObject, dest_index++) ||
		    !copy_attr_from_obj_to_obj(srcObject, TEE_ATTR_DSA_PRIME, destObject, dest_index++)) {
			OT_LOG(LOG_ERR, "Can not copy objects, because something went wrong\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}
	} else {
		OT_LOG(LOG_ERR, "Error in copying attributes: Problem with compatibles\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	destObject->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize, TEE_Attribute *params,
			   uint32_t paramCount)
{
	TEE_Result ret_val = TEE_SUCCESS;

	if (object == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (object->objectInfo.maxObjectSize < keySize) {
		OT_LOG(LOG_ERR, "KeySize is too large\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Should be a transient object and uninit */
	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		OT_LOG(LOG_ERR, "Object initialized or not a transient object\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (object->attrs_count !=
	    (uint32_t)valid_obj_type_and_attr_count(object->objectInfo.objectType)) {
		/* Should never get here */
		OT_LOG(LOG_ERR, "Something is not right with object\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	switch (object->objectInfo.objectType) {
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
		ret_val = gen_des_key(object, keySize);
		break;

	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		ret_val = gen_symmetric_key(object, keySize);
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret_val = gen_rsa_keypair(object, keySize, params, paramCount);
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		ret_val = gen_dsa_keypair(object, params, paramCount);
		break;

	case TEE_TYPE_DH_KEYPAIR:
		ret_val = gen_dh_keypair(object, params, paramCount);
		break;

	default:
		/* Should never get here */
		OT_LOG(LOG_ERR, "Something went wrong in key generation\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	openssl_cleanup();

	if (ret_val == TEE_ERROR_GENERIC) {
		OT_LOG(LOG_ERR, "Something went wrong in key generation\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	return ret_val;
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
				    uint32_t flags, TEE_ObjectHandle *object)
{
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_open_persistent *openParams;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL\n");
		return TEE_ERROR_GENERIC;
	}

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	payload.size = sizeof(struct com_mrg_open_persistent);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		openParams = payload.data;
		openParams->storageID = storageID;
		openParams->flags = flags;
		memcpy(openParams->objectID, objectID, objectIDLen);
		openParams->objectIDLen = objectIDLen;

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_OPEN_PERSISTENT,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			unpack_and_alloc_object_handle(object, returnPayload.data);
			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}

	return retVal;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_close_persistent *closeObject;

	if (object == NULL)
		return;

	payload.size = calculate_object_handle_size(object);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		closeObject = payload.data;
		pack_object_handle(object, &closeObject->openHandleOffset);

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_CLOSE_OBJECT, &payload,
				     &returnPayload);
		TEE_Free(payload.data);
	}

	free_object(object);
	return;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
				      uint32_t flags, TEE_ObjectHandle attributeHandle,
				      void *initialData, size_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	/* serialize to manager */
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	size_t messageSize = offsetof(struct com_mrg_create_persistent, attributeHandleOffset);
	TEE_ObjectHandle tempHandle = NULL;
	struct com_mrg_create_persistent *createParams;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectID == NULL) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL\n");
		return TEE_ERROR_GENERIC;
	}

	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (attributeHandle != NULL) {
		if (!(attributeHandle->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
			OT_LOG(LOG_ERR,
			       "CAnnot create a persistant object from unitialized object\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}
		messageSize += calculate_object_handle_size(attributeHandle);
	}

	payload.size = messageSize;
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		createParams = payload.data;
		createParams->storageID = storageID;
		createParams->flags = flags;
		memcpy(createParams->objectID, objectID, objectIDLen);
		createParams->objectIDLen = objectIDLen;

		if (attributeHandle != NULL)
			pack_object_handle(attributeHandle, &createParams->attributeHandleOffset);

		retVal =
		    TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_CREATE_PERSISTENT,
					 &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {

			if (initialDataLen > 0 || object) {
				unpack_and_alloc_object_handle(&tempHandle, returnPayload.data);

				if (object)
					*object = tempHandle;

				if (initialDataLen > 0) {
					/* TODO: should we check if succeeds or not */
					retVal = TEE_WriteObjectData(tempHandle,
								     initialData,
								     initialDataLen);

					if (!object)
						free_object(tempHandle);
				}
			}

			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object, void *newObjectID,
				      size_t newObjectIDLen)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	struct com_mrg_rename_persistent *renameParams;

	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "ObjectID buffer is NULL or not persistant object\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "ObjectID length too big\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "TEE_RenamePerObj: No rights or not valid object\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	payload.size = offsetof(struct com_mrg_rename_persistent, objectHandleOffset) +
		       calculate_object_handle_size(object);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		renameParams = payload.data;
		memcpy(renameParams->newObjectID, newObjectID, newObjectIDLen);
		renameParams->newObjectIDLen = newObjectIDLen;
		pack_object_handle(object, &renameParams->objectHandleOffset);

		retVal =
		    TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_RENAME_PERSISTENT,
					 &payload, &returnPayload);

		TEE_Free(payload.data);
	}

	return retVal;
}

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_close_persistent *closeObject;

	if (object == NULL)
		return;

	if (!(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		OT_LOG(LOG_ERR, "Not a persistant object\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "TEE_CloAndDelPerObj: No rights or not valid object\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	payload.size = calculate_object_handle_size(object);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		closeObject = payload.data;
		pack_object_handle(object, &closeObject->openHandleOffset);

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				     COM_MGR_CMD_ID_CLOSE_AND_DELETE_PERSISTENT, &payload,
				     &returnPayload);

		TEE_Free(payload.data);
	}

	free_object(object);
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_enum_command *enumParams;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	*objectEnumerator = TEE_Malloc(sizeof(struct __TEE_ObjectEnumHandle), 0);
	if (*objectEnumerator == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	payload.size = 0;

	retVal =
	    TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_OBJ_ENUM_ALLOCATE_PERSIST,
				 &payload, &returnPayload);

	if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
		enumParams = returnPayload.data;

		(*objectEnumerator)->ID = enumParams->ID;

		TEE_Free(returnPayload.data);
	}

	return retVal;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;

	if (objectEnumerator == NULL)
		return;

	payload.size = sizeof(struct com_mrg_enum_command);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_OBJ_ENUM_FREE_PERSIST,
					      &payload, NULL);

		TEE_Free(payload.data);
	}

	TEE_Free(objectEnumerator);
	objectEnumerator = NULL;
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;

	if (objectEnumerator == NULL)
		return;

	payload.size = sizeof(struct com_mrg_enum_command);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;

		TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
				     COM_MGR_CMD_ID_OBJ_ENUM_RESET_PERSIST,
				     &payload, NULL);

		TEE_Free(payload.data);
	}
	return;
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
					       uint32_t storageID)
{
	struct com_mgr_invoke_cmd_payload payload;
	struct com_mrg_enum_command *enumParams;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	payload.size = sizeof(struct com_mrg_enum_command) + sizeof(storageID);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		enumParams = payload.data;
		enumParams->ID = objectEnumerator->ID;
		memcpy(payload.data + sizeof(struct com_mrg_enum_command),
		       &storageID,
		       sizeof(storageID));

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_OBJ_ENUM_START,
					      &payload, NULL);


		TEE_Free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo, void *objectID,
				       size_t *objectIDLen)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	struct com_mrg_enum_command_next *enumNext;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL)
		return TEE_ERROR_GENERIC;

	payload.size = sizeof(struct com_mrg_enum_command_next);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		enumNext = payload.data;
		enumNext->ID = objectEnumerator->ID;

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_OBJ_ENUM_GET_NEXT,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			enumNext = returnPayload.data;

			memcpy(objectID, enumNext->objectID, enumNext->objectIDLen);
			*objectIDLen = enumNext->objectIDLen;

			if (objectInfo)
				memcpy(objectInfo, &enumNext->info, sizeof(TEE_ObjectInfo));

			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	size_t returnObjSize;
	void *writePtr;

	if (object == NULL || buffer == NULL || count == NULL)
		return TEE_ERROR_GENERIC;

	*count = 0;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		OT_LOG(LOG_ERR, "Can not read persistant object data: Not proper access rights\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	payload.size = calculate_object_handle_size(object) + sizeof(size_t);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		writePtr = payload.data;

		writePtr = pack_object_handle(object, writePtr);
		memcpy(writePtr, &size, sizeof(size_t));

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_READ_OBJ_DATA,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			memcpy(&returnObjSize, returnPayload.data, sizeof(size_t));
			*count = returnObjSize;

			memcpy(buffer, returnPayload.data + sizeof(size_t), *count);
			object->per_object.data_position += *count;

			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	void *writePtr;

	if (object == NULL || buffer == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		OT_LOG(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	payload.size = calculate_object_handle_size(object) + size + sizeof(size_t);
	payload.data = TEE_Malloc(payload.size, 0);
	if (payload.data) {
		writePtr = payload.data;

		writePtr = pack_object_handle(object, writePtr);

		memcpy(writePtr, &size, sizeof(size_t));
		writePtr += sizeof(size_t);
		memcpy(writePtr, buffer, size);

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_WRITE_OBJ_DATA,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS)
			object->per_object.data_position += size;

		TEE_Free(payload.data);
	}
	return retVal;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	void *writePtr;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "Can not write persistent object data: Not proper access rights\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistent object. Something is wrong\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	payload.size = calculate_object_handle_size(object) + sizeof(size);
	payload.data = TEE_Malloc(payload.size, 0);
	if (payload.data) {
		writePtr = payload.data;

		writePtr = pack_object_handle(object, writePtr);
		memcpy(writePtr, &size, sizeof(size));

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
					      COM_MGR_CMD_ID_TRUNCATE_OBJ_DATA,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			memcpy(&object->per_object.data_position, returnPayload.data,
			       sizeof(object->per_object.data_position));
			memcpy(&object->per_object.data_size,
			       returnPayload.data + sizeof(object->per_object.data_position),
			       sizeof(object->per_object.data_size));
			TEE_Free(returnPayload.data);
		}
		TEE_Free(payload.data);
	}

	return retVal;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	struct com_mgr_invoke_cmd_payload payload, returnPayload;
	TEE_Result retVal = TEE_ERROR_OUT_OF_MEMORY;
	void *writePtr;
	uint32_t copyWhence = whence;

	if (object == NULL || object->per_object.object_file == NULL)
		return TEE_ERROR_GENERIC;

	payload.size = calculate_object_handle_size(object) + sizeof(int32_t) + sizeof(uint32_t);
	payload.data = TEE_Malloc(payload.size, 0);

	if (payload.data) {
		writePtr = payload.data;

		writePtr = pack_object_handle(object, writePtr);
		memcpy(writePtr, &offset, sizeof(int32_t));
		writePtr += sizeof(int32_t);
		memcpy(writePtr, &copyWhence, sizeof(uint32_t));

		retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE, COM_MGR_CMD_ID_SEEK_OBJ_DATA,
					      &payload, &returnPayload);

		if (retVal == TEE_SUCCESS && returnPayload.size > 0) {
			memcpy(&object->per_object.data_position, returnPayload.data,
			       sizeof(object->per_object.data_position));
			TEE_Free(returnPayload.data);
		}

		TEE_Free(payload.data);
	}
	return retVal;
}
