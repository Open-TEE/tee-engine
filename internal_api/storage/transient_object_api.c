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

#include <sys/select.h>

#include "object_handle.h"
#include "storage_utils.h"
#include "../tee_storage_api.h"
#include "../tee_panic.h"
#include "../crypto/operation_handle.h"
#include "../crypto/crypto_utils.h"
#include "../../include/tee_internal_api.h"
#include "../../utils.h"


/* broken_tee RSA: e points to memory of 4 bytes in size */
#define broken_tee_RSA_PUBLIC_EXP				4
/* broken_tee RSA: d points to memory of key_size_bytes in size */
#define broken_tee_RSA_PRIVATE_EXP(modulo)		(modulo)
/* broken_tee RSA(rest RSA components): points to memory of key_size_bytes/2 in size */
#define broken_tee_RSA_PRIME_1(modulo)			(modulo / 2)
#define broken_tee_RSA_PRIME_2(modulo)			(modulo / 2)
#define broken_tee_RSA_EXPONENT_1(modulo)		(modulo / 2)
#define broken_tee_RSA_EXPONENT_2(modulo)		(modulo / 2)
#define broken_tee_RSA_COEFFICIENT(modulo)		(modulo / 2)


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

	if (public_exp->content.ref.length != broken_tee_RSA_PUBLIC_EXP)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key->gp_key_type == TEE_TYPE_RSA_KEYPAIR) {

		private_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PRIVATE_EXPONENT, attrs, attrCount);
		if (private_exp == NULL)
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

		if (private_exp->content.ref.length != broken_tee_RSA_PRIVATE_EXP(modulo->content.ref.length))
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

			if (prime1->content.ref.length != broken_tee_RSA_PRIME_1(modulo->content.ref.length) ||
			    prime2->content.ref.length != broken_tee_RSA_PRIME_2(modulo->content.ref.length) ||
			    exp1->content.ref.length != broken_tee_RSA_EXPONENT_1(modulo->content.ref.length) ||
			    exp2->content.ref.length != broken_tee_RSA_EXPONENT_2(modulo->content.ref.length) ||
			    coff->content.ref.length != broken_tee_RSA_COEFFICIENT(modulo->content.ref.length))
				return TEE_ERROR_BAD_PARAMETERS;

			/* -- Parameters are OK -- */

			copy_attr2gpKeyAttr(key, prime1);
			copy_attr2gpKeyAttr(key, prime2);
			copy_attr2gpKeyAttr(key, exp1);
			copy_attr2gpKeyAttr(key, exp2);
			copy_attr2gpKeyAttr(key, coff);
		} else {
			key->key.rsa.dp = (uint8_t *)NULL;
			key->key.rsa.dq = (uint8_t *)NULL;
			key->key.rsa.qinv = (uint8_t *)NULL;
			key->key.rsa.p = (uint8_t *)NULL;
			key->key.rsa.q = (uint8_t *)NULL;
		}

		/* Private exponent */
		copy_attr2gpKeyAttr(key, private_exp);
	}

	/* Modulo */
	copy_attr2gpKeyAttr(key, modulo);

	/* Public exponent */
	copy_attr2gpKeyAttr(key, public_exp);

	key->key_lenght = modulo->content.ref.length;

	return TEE_SUCCESS;
}

static int malloc_rsa_attrs(struct gp_key *key,
			    uint32_t objectType,
			    uint32_t maxObjectSize)
{
	int index = 0;

	/* Modulo: Modulo is key size */
	/* Public exponent: e points to memory of 4 bytes in size (broken_tee RSA) */
	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_MODULUS, maxObjectSize, &key->key.rsa.n) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PUBLIC_EXPONENT, broken_tee_RSA_PUBLIC_EXP, &key->key.rsa.e))
		goto err;

	if (objectType == TEE_TYPE_RSA_PUBLIC_KEY)
		return 0;

	/* Private exponent: d points to memory of key_size_bytes in size (broken_tee RSA) */
	/* Prime1: q points to memory of key_size_bytes/2 in size  (broken_tee RSA) */
	/* Prime2: p points to memory of key_size_bytes/2 in size  (broken_tee RSA) */
	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIVATE_EXPONENT, broken_tee_RSA_PRIVATE_EXP(maxObjectSize), &key->key.rsa.d) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME1, broken_tee_RSA_PRIME_1(maxObjectSize), &key->key.rsa.p) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_PRIME2, broken_tee_RSA_PRIME_2(maxObjectSize), &key->key.rsa.q))
		goto err;

	/* broken_tee is not using Exponent1, Exponent2 and Cofficient.
	 * These are just saved, if user wants to sace whole key
	 * Reserve space modulo/2 for each */
	if (malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT1, broken_tee_RSA_EXPONENT_1(maxObjectSize), &key->key.rsa.dp) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_EXPONENT2, broken_tee_RSA_EXPONENT_2(maxObjectSize), &key->key.rsa.dq) ||
	    malloc_attr(&key->gp_attrs.attrs[index++], TEE_ATTR_RSA_COEFFICIENT, broken_tee_RSA_COEFFICIENT(maxObjectSize) , &key->key.rsa.qinv))
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
	uint32_t pub_exp_default_val = 65537;
	crypto_rsa_keygen_ctx ctx = {0};
	TEE_Attribute *public_exp;
	int crypto_fd;
	fd_set fds;
	int ret;

	public_exp = get_attr_from_attrArr(TEE_ATTR_RSA_PUBLIC_EXPONENT, params, paramCount);
	if (public_exp) {

		if (public_exp->content.ref.length != broken_tee_RSA_PUBLIC_EXP)
			return TEE_ERROR_BAD_PARAMETERS;

		memcpy(key->key.rsa.e, public_exp->content.ref.buffer, broken_tee_RSA_PUBLIC_EXP);
	} else {
		memcpy(key->key.rsa.e, &pub_exp_default_val, broken_tee_RSA_PUBLIC_EXP);
	}

	crypto_fd = crypto_get_fd();

	ret = crypto_rsa_keygen_start(keySize,
				      key->key.rsa.n, key->key.rsa.e, key->key.rsa.p,	key->key.rsa.q,
				      key->key.rsa.d, key->key.rsa.dp, key->key.rsa.dq, key->key.rsa.qinv, &ctx);

	if (ret != OK)
		return TEE_ERROR_GENERIC;

	FD_ZERO(&fds);
	FD_SET(crypto_fd, &fds);

	if (select(crypto_fd + 1, (fd_set *)NULL, (fd_set *)NULL, &fds, (struct timeval *)NULL) == -1)
		return TEE_ERROR_GENERIC;

	if (FD_ISSET(crypto_fd, &fds)) {

		if (crypto_rsa_keygen_get_key(&ctx) != OK)
			return TEE_ERROR_GENERIC;
	} else {
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
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

	free_gp_key(object->key);

	if (malloc_gp_key_struct(&object->key, object->objectInfo.objectType, object->objectInfo.maxObjectSize))
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
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
