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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>

#include "tee_storage_api.h"
#include "tee_memory.h"
#include "storage_key_apis_external_funcs.h"
#include "tee_panic.h"
#include "tee_storage_common.h"
#include "tee_object_handle.h"
#include "tee_logging.h"

struct __TEE_ObjectEnumHandle {
	uint32_t ID;
};

static inline int keysize_in_bits(uint32_t key_in_bits)
{
	if (key_in_bits <= UINT_MAX - 7)
		key_in_bits += 7;

	return key_in_bits / 8;
}

static void release_file(TEE_ObjectHandle object, FILE *obj_file, void *objectID,
			 size_t objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	/* TODO: File closing may fail at the manager end -> user should be inform,
	 * but close functions return values are void */

	if (object != NULL) {
		ext_release_file(object->per_object.object_file, object->per_object.obj_id,
				 object->per_object.obj_id_len);
		object->per_object.object_file = NULL;
	} else {
		ext_release_file(obj_file, objectID, objectIDLen);
		obj_file = NULL;
	}
}

static void delete_file(TEE_ObjectHandle object, FILE *obj_file, void *objectID, size_t objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	/* TODO: File closing may fail at the manager end -> user should be inform,
	 * but close functions return values are void */

	if (object != NULL) {
		ext_delete_file(object->per_object.object_file, object->per_object.obj_id,
				object->per_object.obj_id_len);
		object->per_object.object_file = NULL;
	} else {
		ext_delete_file(obj_file, objectID, objectIDLen);
		obj_file = NULL;
	}
}

static FILE *request_for_open(void *objectID, size_t objectIDLen, size_t request_access)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	return ext_request_for_open(objectID, objectIDLen, request_access);
}

static FILE *request_for_create(void *objectID, size_t objectIDLen, size_t request_access)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	return ext_request_for_create(objectID, objectIDLen, request_access);
}

static bool change_object_ID(TEE_ObjectHandle object, void *new_objectID, size_t new_objectIDLen)
{
	/* Exact functionality will be add when Manager process is implemented (for example IPC) */

	if (!ext_change_object_ID(object->per_object.obj_id, object->per_object.obj_id_len,
				  new_objectID, new_objectIDLen))
		return false;

	/* change ID in object */
	memcpy(object->per_object.obj_id, new_objectID, new_objectIDLen);
	object->per_object.obj_id_len = new_objectIDLen;

	/* Begin: Move this to manager (add error handling if there is IO error) */

	struct storage_obj_meta_data renamed_meta_data;

	rewind(object->per_object.object_file);
	memset(&renamed_meta_data, 0, sizeof(struct storage_obj_meta_data));

	if (fread(&renamed_meta_data, sizeof(struct storage_obj_meta_data), 1,
		  object->per_object.object_file) != 1) {
		OT_LOG(LOG_ERR, "Read error at renaming\n");
		return false;
	}

	memcpy(renamed_meta_data.obj_id, new_objectID, new_objectIDLen);
	renamed_meta_data.obj_id_len = new_objectIDLen;

	rewind(object->per_object.object_file);

	if (fwrite(&renamed_meta_data, sizeof(struct storage_obj_meta_data), 1,
		   object->per_object.object_file) != 1) {
		OT_LOG(LOG_ERR, "Write error at renaming\n");
	}

	if (fflush(object->per_object.object_file) != 0) {
		OT_LOG(LOG_ERR, "Fflush error at renaming\n");
	}

	if (fseek(object->per_object.object_file, object->per_object.data_position, SEEK_SET) != 0)
		OT_LOG(LOG_ERR, "Fseek error at renaming\n");

	/* End */

	return true;
}

static void openssl_cleanup()
{
	CRYPTO_cleanup_all_ex_data();
}

static bool is_value_attribute(uint32_t attr_ID)
{
	/* Bit [29]:
	 * 0: buffer attribute
	 * 1: value attribute
	 * TEE_ATTR_FLAG_VALUE == 0x20000000
	 */
	return (attr_ID & TEE_ATTR_FLAG_VALUE);
}

static void free_attrs(TEE_ObjectHandle object)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (object->attrs[i].content.ref.buffer != NULL) {
				/* Fill key buffer with random data. If random function fails,
				 * zero out key buffer. */
				if (!RAND_bytes(object->attrs[i].content.ref.buffer,
						object->maxObjSizeBytes)) {
					memset(object->attrs[i].content.ref.buffer, 0,
					       object->attrs[i].content.ref.length);
				}

				TEE_Free(object->attrs[i].content.ref.buffer);
				object->attrs[i].content.ref.buffer = NULL;
			}
		}
	}

	if (object->attrs != NULL) {
		if (!RAND_bytes((unsigned char *)(object->attrs),
				object->attrs_count * sizeof(TEE_Attribute))) {
			memset(object->attrs, 0, object->attrs_count * sizeof(TEE_Attribute));
		}
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

static TEE_Result load_attributes(TEE_ObjectHandle obj)
{
	size_t i;

	if (obj == NULL || obj->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Something went wrong with persistant object attribute loading\n");
		return TEE_ERROR_GENERIC;
	}

	if (obj->attrs_count == 0) {
		obj->attrs = NULL;
		return TEE_SUCCESS;
	}

	/* Alloc memory for attributes (pointers) */
	obj->attrs = TEE_Malloc(obj->attrs_count * sizeof(TEE_Attribute), 0);
	if (obj->attrs == NULL) {
		OT_LOG(LOG_ERR, "Cannot load attributes, because out of memory\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (i = 0; i < obj->attrs_count; ++i) {
		if (fread(&obj->attrs[i], sizeof(TEE_Attribute),
			  1, obj->per_object.object_file) != 1)
			goto err_at_read;

		if (!is_value_attribute(obj->attrs[i].attributeID)) {
			obj->attrs[i].content.ref.buffer = TEE_Malloc(obj->maxObjSizeBytes, 0);
			if (obj->attrs[i].content.ref.buffer == NULL) {
				free_attrs(obj);
				TEE_Free(obj->attrs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			if (fread(obj->attrs[i].content.ref.buffer,
				  obj->attrs[i].content.ref.length, 1,
				  obj->per_object.object_file) != 1)
				goto err_at_read;
		}
	}

	return TEE_SUCCESS;

err_at_read:
	OT_LOG(LOG_ERR, "Error at fread\n");
	free_attrs(obj);
	TEE_Free(obj->attrs);
	return TEE_ERROR_GENERIC;
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

static void cpy_attr(TEE_ObjectHandle srcObj, uint32_t src_index, TEE_ObjectHandle dstObj,
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

static void copy_all_attributes(TEE_ObjectHandle srcObj, TEE_ObjectHandle destObj)
{
	size_t i;

	if (srcObj->attrs_count != destObj->attrs_count) {
		OT_LOG(LOG_ERR, "Copy fail: Attribute count do not match\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	for (i = 0; i < srcObj->attrs_count; i++) {
		cpy_attr(srcObj, i, destObj, i);
	}
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
	// add suslog
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

static bool malloc_for_attrs(TEE_ObjectHandle object, uint32_t attrs_count)
{
	size_t i;

	for (i = 0; i < attrs_count; ++i) {
		object->attrs[i].content.ref.buffer = TEE_Malloc(object->maxObjSizeBytes, 0);
		if (object->attrs[i].content.ref.buffer == NULL)
			return false;

		object->attrs[i].content.ref.length = object->maxObjSizeBytes;
	}

	return true;
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

static void free_object(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	free_attrs(object);
	TEE_Free(object->attrs);
	if (!RAND_bytes((unsigned char *)object, sizeof(struct __TEE_ObjectHandle)))
		memset(object, 0, sizeof(struct __TEE_ObjectHandle));
	TEE_Free(object);
	object = NULL;
}

static TEE_Result deep_copy_object(TEE_ObjectHandle *dst_obj, TEE_ObjectHandle src_obj)
{
	TEE_ObjectHandle cpy_obj;
	int attr_count;

	if (dst_obj == NULL)
		return TEE_ERROR_GENERIC;

	/* malloc for object handler and cpy that */
	cpy_obj = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (cpy_obj == NULL)
		goto err_out_of_mem;

	if (src_obj != NULL) {
		attr_count = valid_obj_type_and_attr_count(src_obj->objectInfo.objectType);
		if (attr_count == -1)
			return TEE_ERROR_GENERIC;

		memcpy(cpy_obj, src_obj, sizeof(struct __TEE_ObjectHandle));

		// Move single function
		/* Malloc for attribute pointers */
		cpy_obj->attrs = TEE_Malloc(src_obj->attrs_count * sizeof(TEE_Attribute), 0);
		if (cpy_obj->attrs == NULL)
			goto err_out_of_mem;

		/* Malloc space for attributes (attribute buffers) */
		switch (src_obj->objectInfo.objectType) {
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
		case TEE_TYPE_DSA_PUBLIC_KEY:
		case TEE_TYPE_DSA_KEYPAIR:
			if (!malloc_for_attrs(cpy_obj, attr_count))
				goto err_out_of_mem;
			break;

		case TEE_TYPE_DH_KEYPAIR:
			/* -1, because DH contains one value attribute */
			if (!malloc_for_attrs(cpy_obj, attr_count - 1))
				goto err_out_of_mem;
			break;

		default:
			/* Should never get here */
			goto err_out_of_mem;
			break;
		}

		copy_all_attributes(src_obj, cpy_obj);
	}

	*dst_obj = cpy_obj;

	return TEE_SUCCESS;

err_out_of_mem:
	OT_LOG(LOG_ERR, "Cannot malloc space for object\n");
	free_object(cpy_obj);
	*dst_obj = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
}

static bool serialize_attributes_to_storage(TEE_ObjectHandle object, FILE *storage)
{
	size_t i;

	if (object == NULL)
		return true;

	if (storage == NULL)
		return false;

	/* Write attributes to storage (if there is attributes)
	 * Serilization strategy: for (i = 0; i < attributes count in obj; ++i)
	 *				write TEE_Attribute (struct) to file
	 *				if TEE_Attribute != value attribute
	 *					write attribute buffer to file
	 *
	 * if write should fail -> delete a whole file
	 */

	for (i = 0; i < object->attrs_count; ++i) {
		if (fwrite(&object->attrs[i], sizeof(TEE_Attribute), 1, storage) != 1)
			return false;

		if (!is_value_attribute(object->attrs[i].attributeID)) {
			if (fwrite(object->attrs[i].content.ref.buffer,
				   object->attrs[i].content.ref.length, 1, storage) != 1)
				return false;
		}
	}

	return true;
}

static uint32_t object_attribute_size(TEE_ObjectHandle object)
{
	uint32_t object_attr_size = 0;
	size_t i;

	if (object == NULL)
		return object_attr_size;

	for (i = 0; i < object->attrs_count; ++i) {
		if (!is_value_attribute(object->attrs[i].attributeID))
			object_attr_size += object->attrs[i].content.ref.length;
	}

	return (object_attr_size + object->attrs_count * sizeof(TEE_Attribute));
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

void TEE_CloseObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		release_file(object, NULL, NULL, 0);

	free_object(object);
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
	TEE_ObjectHandle new_object = NULL;
	struct storage_obj_meta_data meta_info_from_storage;
	TEE_Result ret_val = TEE_SUCCESS;
	FILE *per_storage_file = NULL;

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

	per_storage_file = request_for_open(objectID, objectIDLen, flags);
	if (per_storage_file == NULL) {
		OT_LOG(LOG_ERR, "Open: Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Access granted. Malloc space for new object handler */
	new_object = TEE_Malloc(sizeof(struct __TEE_ObjectHandle), 0);
	if (new_object == NULL) {
		OT_LOG(LOG_ERR, "Cannot malloc space for object handler\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Read persistant object file meta info from storage and fill it new object */
	memset(&meta_info_from_storage, 0, sizeof(struct storage_obj_meta_data));

	if (fread(&meta_info_from_storage, sizeof(struct storage_obj_meta_data), 1,
		  per_storage_file) != 1) {
		OT_LOG(LOG_ERR, "Cannot read object meta data\n");
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	if (meta_info_from_storage.obj_id_len > TEE_OBJECT_ID_MAX_LEN) {
		OT_LOG(LOG_ERR, "meta_info_from_storage.obj_id_len length too big\n");
		goto err;
	}

	memcpy(&new_object->objectInfo, &meta_info_from_storage.info, sizeof(TEE_ObjectInfo));
	new_object->attrs_count = meta_info_from_storage.attrs_count;
	new_object->per_object.obj_id_len = meta_info_from_storage.obj_id_len;
	memcpy(new_object->per_object.obj_id, meta_info_from_storage.obj_id,
	       meta_info_from_storage.obj_id_len);

	/* Reproduct/fill rest of object parameters */
	new_object->per_object.object_file = per_storage_file;
	per_storage_file = NULL;
	new_object->maxObjSizeBytes = keysize_in_bits(new_object->objectInfo.maxObjectSize);

	/* Load object attributes */
	ret_val = load_attributes(new_object);
	if (ret_val != TEE_SUCCESS)
		goto err;

	/* Initialization/calculation of data position, size and data begin variables */
	new_object->per_object.data_begin = ftell(new_object->per_object.object_file);
	if (new_object->per_object.data_begin == -1L) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_position = new_object->per_object.data_begin;
	if (fseek(new_object->per_object.object_file, 0, SEEK_END) != 0) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}
	new_object->per_object.data_size =
	    ftell(new_object->per_object.object_file) - new_object->per_object.data_begin;
	if (fseek(new_object->per_object.object_file, new_object->per_object.data_begin,
		  SEEK_SET) != 0) {
		ret_val = TEE_ERROR_GENERIC;
		goto err;
	}

	/* Handler flags update */
	new_object->objectInfo.handleFlags = 0; /* reset flags */
	new_object->objectInfo.handleFlags |=
	    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

	*object = new_object;

	return ret_val;

err:
	if (per_storage_file == NULL)
		release_file(new_object, NULL, objectID, objectIDLen);
	else
		release_file(NULL, per_storage_file, objectID, objectIDLen);

	free_object(new_object);
	*object = NULL;
	return ret_val;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, void *objectID, size_t objectIDLen,
				      uint32_t flags, TEE_ObjectHandle attributes,
				      void *initialData, size_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	struct storage_obj_meta_data meta_info_to_storage;
	FILE *obj_storage_file;
	TEE_Result ret_obj_alloc;

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

	if (attributes != NULL &&
	    !(attributes->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "CAnnot create a persistant object from unitialized object\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	obj_storage_file = request_for_create(objectID, objectIDLen, flags);
	if (obj_storage_file == NULL) {
		OT_LOG(LOG_ERR, "Create: Access conflict\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	/* Access has been granted. Fill needed info for object storing */
	memset(&meta_info_to_storage, 0, sizeof(struct storage_obj_meta_data));

	if (attributes != NULL) {
		memcpy(&meta_info_to_storage.info, &attributes->objectInfo, sizeof(TEE_ObjectInfo));
		meta_info_to_storage.attrs_count = attributes->attrs_count;
	} else {
		meta_info_to_storage.attrs_count = 0;
	}

	meta_info_to_storage.meta_size = sizeof(struct storage_obj_meta_data) +
					 object_attribute_size(attributes);

	memcpy(meta_info_to_storage.obj_id, objectID, objectIDLen);
	meta_info_to_storage.obj_id_len = objectIDLen;

	/* Meta info is filled. Write meta info to storage */
	if (fwrite(&meta_info_to_storage, sizeof(struct storage_obj_meta_data), 1,
		   obj_storage_file) != 1)
		goto err_at_meta_or_init_data_write;

	/* store attributes */
	if (!serialize_attributes_to_storage(attributes, obj_storage_file))
		goto err_at_meta_or_init_data_write;

	if (initialData != NULL) {
		if (fwrite(initialData, initialDataLen, 1, obj_storage_file) != 1)
			goto err_at_meta_or_init_data_write;
	}

	if (fflush(obj_storage_file) != 0)
		goto err_at_meta_or_init_data_write;

	if (object != NULL) {
		ret_obj_alloc = deep_copy_object(object, attributes);
		if (ret_obj_alloc != TEE_SUCCESS)
			goto err_at_obj_alloc;

		/* update current state to allocated handle */
		(*object)->objectInfo.handleFlags = 0; /* reset flags */
		(*object)->objectInfo.handleFlags |=
		    (TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED | flags);

		(*object)->per_object.data_position = ftell(obj_storage_file);
		if ((*object)->per_object.data_position == -1L)
			goto err_at_obj_alloc;
		(*object)->per_object.data_begin =
		    (*object)->per_object.data_position - initialDataLen;

		(*object)->per_object.data_size = initialDataLen;

		/* Cpy obj ID to alloceted object */
		memcpy((*object)->per_object.obj_id, objectID, objectIDLen);
		(*object)->per_object.obj_id_len = objectIDLen;

		/* sign storage "location"(=file) */
		(*object)->per_object.object_file = obj_storage_file;

	} else {
		release_file(NULL, obj_storage_file, objectID, objectIDLen);
	}

	return TEE_SUCCESS;

err_at_meta_or_init_data_write:
	OT_LOG(LOG_ERR, "Error with fwrite or fflush\n");
	delete_file(NULL, obj_storage_file, objectID, objectIDLen);
	if (obj_storage_file != NULL && errno == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;

err_at_obj_alloc:
	OT_LOG(LOG_ERR, "Cannot alloc object\n");
	delete_file(NULL, obj_storage_file, objectID, objectIDLen);
	(*object) = NULL;
	if (ret_obj_alloc == TEE_ERROR_OUT_OF_MEMORY)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object, void *newObjectID,
				      size_t newObjectIDLen)
{
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

	if (!change_object_ID(object, newObjectID, newObjectIDLen)) {
		OT_LOG(LOG_ERR, "Access conflict: ID exists\n");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	return TEE_SUCCESS;
}

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
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

	delete_file(object, NULL, NULL, 0);
	free_object(object);
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *objectEnumerator)
{
	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	*objectEnumerator = TEE_Malloc(sizeof(struct __TEE_ObjectEnumHandle), 0);
	if (*objectEnumerator == NULL)
		goto error;

	if (!ext_alloc_for_enumerator(&(*objectEnumerator)->ID))
		goto error;

	return TEE_SUCCESS;

error:
	TEE_Free(*objectEnumerator);
	*objectEnumerator = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	ext_free_enumerator(objectEnumerator->ID);

	TEE_Free(objectEnumerator);
	objectEnumerator = NULL;
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	if (objectEnumerator == NULL)
		return;

	ext_reset_enumerator(objectEnumerator->ID);
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator,
					       uint32_t storageID)
{
	if (storageID != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (objectEnumerator == NULL)
		return TEE_ERROR_GENERIC;

	if (!ext_start_enumerator(objectEnumerator->ID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo, void *objectID,
				       size_t *objectIDLen)
{
	struct storage_obj_meta_data recv_per_obj;

	if (objectEnumerator == NULL || objectID == NULL || objectIDLen == NULL)
		return TEE_ERROR_GENERIC;

	if (!ext_get_next_obj_from_enumeration(objectEnumerator->ID, &recv_per_obj))
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Generate/copy info to provided parameters */
	/* Overflow err possibility, but no way of checking that */
	memcpy(objectID, recv_per_obj.obj_id, recv_per_obj.obj_id_len);
	*objectIDLen = recv_per_obj.obj_id_len;

	if (objectInfo != NULL)
		memcpy(objectInfo, &recv_per_obj.info, sizeof(TEE_ObjectInfo));

	return TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count)
{
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

	if (feof(object->per_object.object_file)) {
		OT_LOG(LOG_ERR, "Can't read: end of file\n");
		goto ret;
	}

	*count = fread(buffer, 1, size, object->per_object.object_file);
	object->per_object.data_position += *count;

ret:
	return TEE_SUCCESS;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, void *buffer, size_t size)
{
	size_t write_bytes;
	int err_no = 0;
	unsigned long end;
	unsigned long pos;

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

	if (fflush(object->per_object.object_file) != 0) {
		OT_LOG(LOG_ERR, "Cannot flush before write\n");
		goto error;
	}

	end = object->per_object.data_begin + object->per_object.data_size;
	pos = object->per_object.data_position;

	write_bytes = fwrite(buffer, 1, size, object->per_object.object_file);

	if (write_bytes != size) {
		OT_LOG(LOG_DEBUG, "Stream write error has been occured\n");
		goto error;
	}

	if (fflush(object->per_object.object_file) != 0) {
		OT_LOG(LOG_ERR, "Cannot flush after write\n");
		goto error;
	}

	if ((write_bytes + pos) > end)
		object->per_object.data_size += pos + write_bytes - end;

	object->per_object.data_position += write_bytes;

	return TEE_SUCCESS;

error:
	err_no = errno;
	/* TODO: atomic write. For now a cheap solution: set file handler as it was before write */
	if (fseek(object->per_object.object_file, object->per_object.data_position, SEEK_SET) != 0)
		OT_LOG(LOG_ERR, "fseek error at write object data\n");
	if (err_no == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	unsigned long pos;
	unsigned long begin;

	if (object == NULL)
		return TEE_ERROR_GENERIC;

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		OT_LOG(LOG_ERR, "Can not write persistant object data: Not proper access rights\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	if (object->per_object.object_file == NULL) {
		OT_LOG(LOG_ERR, "Not a proper persistant object. Something is wrong\n");
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);
	}

	pos = object->per_object.data_position;
	begin = object->per_object.data_begin;

	if (ftruncate(fileno(object->per_object.object_file), begin + size) != 0)
		goto error;

	if (pos > (size + begin)) {
		/* TODO: If fseek fail -> kabum, so some solution is needed */
		if (fseek(object->per_object.object_file, size + begin, SEEK_SET) != 0)
			OT_LOG(LOG_ERR, "fseek error at truncate object data\n");
		object->per_object.data_position = size + begin;
	}

	object->per_object.data_size = size;

	return TEE_SUCCESS;

error:
	if (errno == ENOSPC)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return TEE_ERROR_GENERIC;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
	long begin;
	long end;
	long pos;

	if (object == NULL || object->per_object.object_file == NULL)
		return TEE_ERROR_GENERIC;

	begin = object->per_object.data_begin;
	end = object->per_object.data_begin + object->per_object.data_size;
	pos = object->per_object.data_position;

	// if whence is SEEK_CUR should stay as current pos
	if (whence == TEE_DATA_SEEK_END)
		pos = end;
	else if (whence == TEE_DATA_SEEK_SET)
		pos = begin;

	pos += offset;

	// check for overflow or underflow
	if (pos > end)
		pos = end;
	else if (pos < begin)
		pos = begin;

	object->per_object.data_position = pos;

	/* TODO: If fseek fail -> kabum, so some solution is needed */
	if (fseek(object->per_object.object_file, pos, TEE_DATA_SEEK_SET) != 0)
		OT_LOG(LOG_ERR, "Fseek failed at seek data\n");

	return TEE_SUCCESS;
}
