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

#include <mbedtls/ctr_drbg.h>

#include "object_handle.h"
#include "storage_utils.h"
#include "../tee_storage_api.h"
#include "../tee_panic.h"
#include "../crypto/operation_handle.h"
#include "../crypto/crypto_utils.h"
#include "../../include/tee_internal_api.h"

/* mbedtls RSA key components sizes. NOTE: How we did get these values? It was done by generating
 * RSA key with mbedtls and then calculated sizes from generated key. */
#define mbedtls_RSA_PUBLIC_EXP_t		int
#define mbedtls_RSA_PUBLIC_EXP			sizeof(mbedtls_RSA_PUBLIC_EXP_t)
#define mbedtls_RSA_PRIVATE_EXP(modulo)		(modulo)
#define mbedtls_RSA_PRIME_1(modulo)		(modulo / 2)
#define mbedtls_RSA_PRIME_2(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_1(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_2(modulo)		(modulo / 2)
#define mbedtls_RSA_COEFFICIENT(modulo)		(modulo / 2)


static TEE_Attribute *get_attr_from_attrArr(uint32_t ID,
					    TEE_Attribute *attrs,
					    uint32_t attrCount)
{
	uint32_t i;

	if (attrs == NULL)
		return (TEE_Attribute *)NULL;

	for (i = 0; i < attrCount; ++i) {
		if (ID == attrs[i].attributeID)
			return &attrs[i];
	}

	return (TEE_Attribute *)NULL;
}

static int malloc_attr(TEE_Attribute *init_attr,
		       uint32_t attrID,
		       uint32_t buf_len,
		       uint8_t **key)
{
	init_attr->content.ref.buffer = calloc(1, buf_len);
	if (init_attr->content.ref.buffer == NULL)
		return 1;

	/*This is pointer to key struct. This function will also update the value into that! */
	if (*key)
		*key = (uint8_t *)init_attr->content.ref.buffer;
	init_attr->content.ref.length = buf_len;
	init_attr->attributeID = attrID;
	return 0;
}

static TEE_Attribute *copy_attr2gpKeyAttr(struct gp_key *key,
					  TEE_Attribute *cpy_attr)
{
	TEE_Attribute *gp_attr;

	gp_attr = get_attr_from_attrArr(cpy_attr->attributeID,
					key->gp_attrs.attrs, key->gp_attrs.attrs_count);
	if (gp_attr == NULL)
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */

	if (cpy_attr->content.ref.length > gp_attr->content.ref.length)
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */

	gp_attr->content.ref.length = cpy_attr->content.ref.length;
	memcpy(gp_attr->content.ref.buffer,
	       cpy_attr->content.ref.buffer,
	       cpy_attr->content.ref.length);

	return gp_attr;
}

static void copy_attr2mbedtlsMpi(mbedtls_mpi *mpi,
				 TEE_Attribute *gp_attr)
{
	if (gp_attr == NULL || mpi == NULL)
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */

	if (mbedtls_mpi_read_binary(mpi, gp_attr->content.ref.buffer, gp_attr->content.ref.length))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
}

/* Secret key attribute is used for AES, DES, DES3 and HMAC operations */
static TEE_Result populate_secret_key(TEE_Attribute *attrs,
				      uint32_t attrCount,
				      struct gp_key *key)
{
	TEE_Attribute *secret_attr, *gp_secret_key_attr;

	secret_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE, attrs, attrCount);
	if (secret_attr == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (secret_attr->content.ref.length > key->key_max_length)
		return TEE_ERROR_BAD_PARAMETERS;

	gp_secret_key_attr = copy_attr2gpKeyAttr(key, secret_attr);

	key->key.secret.key = (uint8_t *)gp_secret_key_attr->content.ref.buffer;
	key->key_lenght = secret_attr->content.ref.length;

	return TEE_SUCCESS;
}

static TEE_Result populate_rsa_key(TEE_Attribute *attrs,
				   uint32_t attrCount,
				   struct gp_key *key)
{
	TEE_Attribute *modulo = 0, *public_exp = 0, *private_exp = 0, *prime1 = 0,
			*prime2 = 0, *coff = 0, *exp1 = 0, *exp2 = 0, *correspond_gp_key_attr = 0;

	/* Common for public and rsa key pair */
	modulo = get_attr_from_attrArr(TEE_ATTR_RSA_MODULUS, attrs, attrCount);
	public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, attrs, attrCount);
	if (modulo == NULL || public_exp == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (modulo->content.ref.length > key->key_max_length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (public_exp->content.ref.length != mbedtls_RSA_PUBLIC_EXP)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {

		private_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount);
		if (private_exp == NULL)
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

		if (private_exp->content.ref.length != mbedtls_RSA_PRIVATE_EXP(modulo->content.ref.length))
			return TEE_ERROR_BAD_PARAMETERS;

		/* If one provided, then all must be found */
		prime1 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME1, attrs, attrCount);
		prime2 = get_attr_from_attrArr(TEE_ATTR_RSA_PRIME2, attrs, attrCount);
		coff = get_attr_from_attrArr(TEE_ATTR_RSA_COEFFICIENT, attrs, attrCount);
		exp1 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT1, attrs, attrCount);
		exp2 = get_attr_from_attrArr(TEE_ATTR_RSA_EXPONENT2, attrs, attrCount);
		if (prime1 || prime2 || coff || exp1 || exp2) {

			if (prime1 == NULL  || prime2 == NULL  || coff == NULL  || exp1 == NULL  || exp2 == NULL)
				TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

			if (prime1->content.ref.length != mbedtls_RSA_PRIME_1(modulo->content.ref.length) ||
			    prime2->content.ref.length != mbedtls_RSA_PRIME_2(modulo->content.ref.length) ||
			    exp1->content.ref.length != mbedtls_RSA_EXPONENT_1(modulo->content.ref.length) ||
			    exp2->content.ref.length != mbedtls_RSA_EXPONENT_2(modulo->content.ref.length) ||
			    coff->content.ref.length != mbedtls_RSA_COEFFICIENT(modulo->content.ref.length))
				return TEE_ERROR_BAD_PARAMETERS;

			/* -- Parameters are OK -- */

			/* Prime1 */
			copy_attr2gpKeyAttr(key, prime1);
			copy_attr2mbedtlsMpi(&key->key.rsa.ctx.P, prime1);

			/* Prime2 */
			copy_attr2gpKeyAttr(key, prime2);
			copy_attr2mbedtlsMpi(&key->key.rsa.ctx.Q, prime2);

			/* Exponent 1 */
			copy_attr2gpKeyAttr(key, exp1);
			copy_attr2mbedtlsMpi(&key->key.rsa.ctx.DP, exp1);

			/* Exponent 2 */
			copy_attr2gpKeyAttr(key, exp2);
			copy_attr2mbedtlsMpi(&key->key.rsa.ctx.DQ, exp2);

			/* Cofficient */
			copy_attr2gpKeyAttr(key, coff);
			copy_attr2mbedtlsMpi(&key->key.rsa.ctx.QP, coff);
		}

		/* Private exponent */
		copy_attr2gpKeyAttr(key, private_exp);
		copy_attr2mbedtlsMpi(&key->key.rsa.ctx.D, private_exp);
	}

	/* Modulo */
	copy_attr2gpKeyAttr(key, modulo);
	copy_attr2mbedtlsMpi(&key->key.rsa.ctx.N, modulo);

	/* Public exponent */
	copy_attr2gpKeyAttr(key, public_exp);
	copy_attr2mbedtlsMpi(&key->key.rsa.ctx.E, public_exp);

	key->key_lenght = modulo->content.ref.length;

	return TEE_SUCCESS;
}

static int malloc_rsa_attrs(struct gp_key *key,
			    uint32_t objectType,
			    uint32_t maxObjectSize)
{
	int index = 0;

	/* Modulo: Modulo is key size */
	/* Public exponent: e points to memory of 4 bytes in size (mbedtls RSA) */
	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_MODULUS, maxObjectSize, NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PUBLIC_EXPONENT, mbedtls_RSA_PUBLIC_EXP, NULL))
		goto err;

	if (objectType == TEE_TYPE_RSA_PUBLIC_KEY)
		return 0;

	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIVATE_EXPONENT, mbedtls_RSA_PRIVATE_EXP(maxObjectSize), NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME1, mbedtls_RSA_PRIME_1(maxObjectSize), NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME2, mbedtls_RSA_PRIME_2(maxObjectSize), NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT1, mbedtls_RSA_EXPONENT_1(maxObjectSize), NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT2, mbedtls_RSA_EXPONENT_2(maxObjectSize), NULL) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_COEFFICIENT, mbedtls_RSA_COEFFICIENT(maxObjectSize) , NULL))
		goto err;

	return 0;

err:
	free_gp_attributes(&key->gp_attrs);
	return 1;
}

static int malloc_gp_key_struct(struct gp_key **key,
				uint32_t objectType,
				uint32_t maxObjectSize)
{
	*key = (struct gp_key *)calloc(1, sizeof(struct gp_key));
	if (*key == NULL)
		goto err_1;

	if (expected_object_attr_count(objectType, &(*key)->gp_attrs.attrs_count))
		TEE_Panic(TEE_ERROR_GENERIC);

	(*key)->gp_attrs.attrs = (TEE_Attribute *)calloc(1, sizeof(TEE_Attribute) * (*key)->gp_attrs.attrs_count);
	if ((*key)->gp_attrs.attrs == NULL)
		goto err_2;

	switch (objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
		if (malloc_attr((*key)->gp_attrs.attrs, TEE_ATTR_SECRET_VALUE, maxObjectSize, &(*key)->key.secret.key))
			goto err_2;
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
		mbedtls_rsa_init(&key->key.rsa.ctx, NULL, NULL);
		if (malloc_rsa_attrs(*key, objectType, maxObjectSize))
			goto err_2;
		break;

	default:
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	(*key)->gp_key_type = objectType;
	(*key)->key_max_length = maxObjectSize;

	return 0;

err_2:
	free(*key);
err_1:
	*key = 0;
	return 1;
}

static TEE_Result gen_symmetric_key(struct gp_key *key,
				    uint32_t keySize)
{
	TEE_GenerateRandom((void *)key->key.secret.key, keySize);
	return TEE_SUCCESS;
}

static TEE_Result gen_rsa_keypair(struct gp_key *key,
				  uint32_t keySize,
				  TEE_Attribute *params,
				  uint32_t paramCount)
{
	mbedtls_RSA_PUBLIC_EXP_t pub_exp = 65537; /* Initialized with default value */
	TEE_Attribute *usr_public_exp;

	usr_public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, params, paramCount);
	if (usr_public_exp) {

		if (usr_public_exp->content.ref.length != mbedtls_RSA_PUBLIC_EXP)
			return TEE_ERROR_BAD_PARAMETERS;

		memcpy(&pub_exp, usr_public_exp->content.ref.buffer, mbedtls_RSA_PUBLIC_EXP);
	}

	if(mbedtls_rsa_gen_key(&key->key.rsa.ctx, mbedtls_ctr_drbg_random,
			       &ot_mbedtls_ctr_drbg, keySize, pub_exp != 0 ))
		return TEE_ERROR_GENERIC;

	return TEE_ERROR_NOT_IMPLEMENTED;
}







/*
 * GP Transient API
 */

TEE_Result TEE_AllocateTransientObject(uint32_t objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	if (object == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	*object = 0;

	if (valid_object_type_and_max_size(objectType, maxObjectSize))
		return TEE_ERROR_NOT_SUPPORTED;

	/* Alloc memory for objectHandle */
	*object = (TEE_ObjectHandle)calloc(1, sizeof(struct __TEE_ObjectHandle));
	if (*object == NULL)
		goto out_of_mem_1;

	if (objectType != TEE_TYPE_DATA) {
		if (malloc_gp_key_struct(&(*object)->key, objectType, BITS2BYTE(maxObjectSize)))
			goto out_of_mem_2;
	}

	/* object info */
	(*object)->objectInfo.objectUsage = 0xFFFFFFFF;
	(*object)->objectInfo.maxObjectSize = maxObjectSize;
	(*object)->objectInfo.objectType = objectType;
	(*object)->objectInfo.keySize = 0;
	(*object)->objectInfo.dataSize = 0;
	(*object)->objectInfo.handleFlags = 0x00000000;

	return TEE_SUCCESS;

out_of_mem_2:
	free(*object);
out_of_mem_1:
	*object = 0;
	return TEE_ERROR_OUT_OF_MEMORY;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	free_object_handle(object);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	if (object == NULL)
		return;

	if (object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* Reset info */
	object->objectInfo.objectUsage = 0xFFFFFFFF;
	object->objectInfo.keySize = 0;
	object->objectInfo.dataSize = 0;
	object->objectInfo.handleFlags = 0x00000000;

	/* Note: Breaking GP compatibility. Can't reuse the key, because it
	 * might be used by operation. We need to malloc new gp key struct for object */

	if (malloc_gp_key_struct(&object->key, object->objectInfo.objectType, object->objectInfo.maxObjectSize))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

	free_gp_key(object->key);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	TEE_Result ret = TEE_SUCCESS;

	if (object == NULL || attrs == NULL ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (object->objectInfo.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
		ret = populate_secret_key(attrs, attrCount, object->key);
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
	case TEE_TYPE_RSA_KEYPAIR:
		ret = populate_rsa_key(attrs, attrCount, object->key);
		break;

	default:
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (ret == TEE_SUCCESS) {
		object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		object->key->reference_count++;
	}

	return ret;
}

void TEE_InitRefAttribute(TEE_Attribute *attr,
			  uint32_t attributeID,
			  void *buffer,
			  size_t length)
{
	if (attr == NULL || is_value_attribute(attributeID))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	attr->attributeID = attributeID;
	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr,
			    uint32_t attributeID,
			    uint32_t a,
			    uint32_t b)
{
	if (attr == NULL || !is_value_attribute(attributeID))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
			       TEE_ObjectHandle srcObject)
{
	/* Not used by PKCS11TA */

	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object,
			   uint32_t keySize,
			   TEE_Attribute *params,
			   uint32_t paramCount)
{
	TEE_Result ret = TEE_SUCCESS;

	/* Should be a transient object and uninit */
	if (object == NULL ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED ||
	    object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT ||
	    BITS2BYTE(keySize) > object->key->key_max_length)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (object->objectInfo.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		ret = gen_symmetric_key(object->key, BITS2BYTE(keySize));
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret = gen_rsa_keypair(object->key, BITS2BYTE(keySize), params, paramCount);
		break;

	default:
		/* Should never get here */
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (ret == TEE_SUCCESS) {
		object->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		object->key->reference_count++;
		object->key->key_lenght = BITS2BYTE(keySize);
	}

	return ret;
}
