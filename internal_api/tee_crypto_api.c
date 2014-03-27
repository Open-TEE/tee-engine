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

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <string.h>
#include <syslog.h>

#include "tee_crypto_api.h"
#include "tee_memory.h"
#include "storage_data_key_api.h"
#include "tee_object_handle.h"
#include "tee_panic.h"
#include "data_types.h"





/*
 * ## Variables ##
 */

struct key {
	RSA *rsa_key;
	DSA *dsa_key;
	DH *dh_key;
	void *sym_key;
	uint32_t sym_key_len;
	EVP_CIPHER_CTX *ctx;
};

struct __TEE_OperationHandle{
	TEE_OperationInfo operation_info;
	struct key key;
};




/*
 * ## NON internal api functions ##
 */

/* This function is collection algorithms/key sizes that is not supported/not implemented
 * If you add supportion or implementation to some of these algorithms, remove it from this func. */
static bool not_supported_algorithms(uint32_t algorithm, uint32_t key_size)
{
	switch (algorithm) {
	case TEE_ALG_AES_CTS:
		return true;

	case TEE_ALG_AES_XTS:
		if (key_size == 192)
			return true;
	default:
		return false;
	}
}

static bool valid_mode_and_algorithm(uint32_t alg, TEE_OperationMode mode)
{
	switch (mode) {
	case TEE_MODE_ENCRYPT:
		switch (alg) {
		case TEE_ALG_AES_ECB_NOPAD:
		case TEE_ALG_AES_CBC_NOPAD:
		case TEE_ALG_AES_CTR:
		case TEE_ALG_AES_CTS:
		case TEE_ALG_AES_XTS:
		case TEE_ALG_AES_CCM:
		case TEE_ALG_AES_GCM:
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
		case TEE_ALG_RSAES_PKCS1_V1_5:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		case TEE_ALG_RSA_NOPAD:
			return true;
		default:
			return false;
		}

	case TEE_MODE_DECRYPT:
		switch (alg) {
		case TEE_ALG_AES_ECB_NOPAD:
		case TEE_ALG_AES_CBC_NOPAD:
		case TEE_ALG_AES_CTR:
		case TEE_ALG_AES_CTS:
		case TEE_ALG_AES_XTS:
		case TEE_ALG_AES_CCM:
		case TEE_ALG_AES_GCM:
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
		case TEE_ALG_RSAES_PKCS1_V1_5:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		case TEE_ALG_RSA_NOPAD:
			return true;
		default:
			return false;
		}

	case TEE_MODE_SIGN:
		switch (alg) {
		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		case TEE_ALG_DSA_SHA1:
			return true;
		default:
			return false;
		}

	case TEE_MODE_VERIFY:
		switch (alg) {
		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		case TEE_ALG_DSA_SHA1:
			return true;
		default:
			return false;
		}

	case TEE_MODE_MAC:
		switch (alg) {
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_AES_CMAC:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
		case TEE_ALG_HMAC_MD5:
		case TEE_ALG_HMAC_SHA1:
		case TEE_ALG_HMAC_SHA224:
		case TEE_ALG_HMAC_SHA256:
		case TEE_ALG_HMAC_SHA384:
		case TEE_ALG_HMAC_SHA512:
			return true;
		default:
			return false;
		}

	case TEE_MODE_DIGEST:
		switch (alg) {
		case TEE_ALG_MD5:
		case TEE_ALG_SHA1:
		case TEE_ALG_SHA224:
		case TEE_ALG_SHA256:
		case TEE_ALG_SHA384:
		case TEE_ALG_SHA512:
			return true;
		default:
			return false;
		}

	case TEE_MODE_DERIVE:
		switch (alg) {
		case TEE_ALG_DH_DERIVE_SHARED_SECRET:
			return true;
		default:
			return false;
		}
	default:
		return false;
	}
}

static bool valid_mode(TEE_OperationMode mode)
{
	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
	case TEE_MODE_SIGN:
	case TEE_MODE_VERIFY:
	case TEE_MODE_MAC:
	case TEE_MODE_DIGEST:
	case TEE_MODE_DERIVE:
		return true;

	default:
		return false;
	}
}

/* Remove when not needed.. only for copying algorithms..
bool valid_algorithm(algorithm_Identifier alg)
{
	switch (alg) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return true;
	default:
		return false;
	}
}
*/

static TEE_Result malloc_key_meta_info(TEE_OperationHandle operation, uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_SUCCESS;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
		operation->key.rsa_key = RSA_new();
		if (!operation->key.rsa_key) {
			syslog(LOG_ERR, "Cannot malloc space for rsa key (openssl failure)\n");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		break;

	case TEE_ALG_DSA_SHA1:
		operation->key.dsa_key = DSA_new();
		if (!operation->key.dsa_key) {
			syslog(LOG_ERR, "Cannot malloc space for dsa key (openssl failure)\n");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		operation->key.dh_key = DH_new();
		if (!operation->key.dh_key) {
			syslog(LOG_ERR, "Cannot malloc space for dh key (openssl failure)\n");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		break;

	default:
		/* Should never end up here */
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Attribute *get_attr_by_ID(TEE_ObjectHandle object, uint32_t attributeID)
{
	size_t i;

	for (i = 0; i < object->attrs_count; ++i) {
		if (object->attrs[i].attributeID == attributeID)
			return &object->attrs[i];
	}

	return NULL;
}

static TEE_Result malloc_and_cpy_symmetric_key(struct key *op_key, TEE_ObjectHandle key)
{
	TEE_Attribute *sym_key = NULL;

	sym_key = get_attr_by_ID(key, TEE_ATTR_SECRET_VALUE);
	if (!sym_key) {
		syslog(LOG_ERR, "Key does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	op_key->sym_key = TEE_Malloc(sym_key->content.ref.length, 0);
	if (!op_key->sym_key) {
		syslog(LOG_ERR, "Cannot malloc space for symmetric key\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	op_key->sym_key_len = sym_key->content.ref.length;

	memcpy(op_key->sym_key, sym_key->content.ref.buffer, sym_key->content.ref.length);

	return TEE_SUCCESS;
}

/* This function type is BOOL only for debug purpose */
static bool cpy_rsa_comp_to_op_key(BIGNUM *rsa_comp_at_RSA_struct,
				   uint32_t attrID, TEE_ObjectHandle key)
{
	TEE_Attribute *rsa_component = NULL;

	rsa_component = get_attr_by_ID(key, attrID);
	if (!rsa_component) {
		syslog(LOG_ERR, "RSA attribute ID is not found at key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!BN_bin2bn(rsa_component->content.ref.buffer,
		       rsa_component->content.ref.length, rsa_comp_at_RSA_struct)) {
		syslog(LOG_ERR, "bin2bn failed (openssl failure)\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return true;
}

static TEE_Result malloc_and_cpy_rsa_key(struct key *op_key, TEE_ObjectHandle key)
{
	if (!op_key->rsa_key) {
		syslog(LOG_ERR, "Not a proper operation handler\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (get_attr_by_ID(key, TEE_ATTR_RSA_PRIME1) ||
	    get_attr_by_ID(key, TEE_ATTR_RSA_PRIME2) ||
	    get_attr_by_ID(key, TEE_ATTR_RSA_EXPONENT1) ||
	    get_attr_by_ID(key, TEE_ATTR_RSA_EXPONENT1) ||
	    get_attr_by_ID(key, TEE_ATTR_RSA_COEFFICIENT)) {

		if (!cpy_rsa_comp_to_op_key(op_key->rsa_key->p, TEE_ATTR_RSA_PRIME1, key) ||
		    !cpy_rsa_comp_to_op_key(op_key->rsa_key->q, TEE_ATTR_RSA_PRIME2, key) ||
		    !cpy_rsa_comp_to_op_key(op_key->rsa_key->dmp1, TEE_ATTR_RSA_EXPONENT1, key) ||
		    !cpy_rsa_comp_to_op_key(op_key->rsa_key->dmq1, TEE_ATTR_RSA_EXPONENT2, key) ||
		    !cpy_rsa_comp_to_op_key(op_key->rsa_key->iqmp, TEE_ATTR_RSA_COEFFICIENT, key)) {
			syslog(LOG_ERR, "Error with RSA key component\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}
	}

	if (!cpy_rsa_comp_to_op_key(op_key->rsa_key->n, TEE_ATTR_RSA_MODULUS, key) ||
	    !cpy_rsa_comp_to_op_key(op_key->rsa_key->e, TEE_ATTR_RSA_PUBLIC_EXPONENT, key) ||
	    !cpy_rsa_comp_to_op_key(op_key->rsa_key->d, TEE_ATTR_RSA_PRIVATE_EXPONENT, key)) {
		syslog(LOG_ERR, "Error with RSA key component\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	return TEE_SUCCESS;
}

static TEE_Result malloc_and_init_keys_to_op(struct key *op_key, uint32_t op_alg,
					     TEE_ObjectHandle key)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (op_alg) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		ret = malloc_and_cpy_symmetric_key(op_key, key);
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
		ret = malloc_and_cpy_rsa_key(op_key, key);
		break;

	case TEE_ALG_DSA_SHA1:
		//ret = malloc_and_cpy_dsa_key(op_key, key);
		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		//ret = malloc_and_cpy_dh_key(op_key, key);
		break;

	default:
		/* Should never end up here */
		ret = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return ret;
}

static void rand_buf(void *buf, uint32_t len)
{
	if (!buf)
		return;

	if (!RAND_bytes(buf, len))
		TEE_MemFill(buf, 0, len);
}

static void free_key(struct key *released_key)
{
	if (!released_key)
		return;

	/* Free openssl structs */
	RSA_free(released_key->rsa_key);
	DSA_free(released_key->dsa_key);
	DH_free(released_key->dh_key);

	/* Free symmetric key */
	rand_buf(released_key->sym_key, released_key->sym_key_len);
	rand_buf(&released_key->sym_key_len, sizeof(released_key->sym_key_len));
	TEE_Free(released_key->sym_key);

	/* EVP cipher context */
	EVP_CIPHER_CTX_free(released_key->ctx);
}

const EVP_CIPHER *load_AES_DES_DES3_evp_cipher(uint32_t algorithm, uint32_t key_size)
{
	switch (algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
		switch (key_size) {
		case 128:
			return EVP_aes_128_ecb();
		case 192:
			return EVP_aes_192_ecb();
		case 256:
			return EVP_aes_256_ecb();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_AES_CBC_NOPAD:
		switch (key_size) {
		case 128:
			return EVP_aes_128_cbc();
		case 192:
			return EVP_aes_192_cbc();
		case 256:
			return EVP_aes_256_cbc();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_AES_CTR:
		switch (key_size) {
		case 128:
			return EVP_aes_128_ctr();
		case 192:
			return EVP_aes_192_ctr();
		case 256:
			return EVP_aes_256_ctr();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_AES_CTS:
		/* Not supported */
		return NULL;

	case TEE_ALG_AES_XTS:
		switch (key_size) {
		case 128:
			return EVP_aes_128_xts();
		case 192:
			/* Not supported */
			return NULL;
		case 256:
			return EVP_aes_256_xts();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_AES_CCM:
		switch (key_size) {
		case 128:
			return EVP_aes_128_ccm();
		case 192:
			return EVP_aes_192_ccm();
		case 256:
			return EVP_aes_256_ccm();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_AES_GCM:
		switch (key_size) {
		case 128:
			return EVP_aes_128_gcm();
		case 192:
			return EVP_aes_192_gcm();
		case 256:
			return EVP_aes_256_gcm();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_DES_ECB_NOPAD:
		return EVP_des_ecb();

	case TEE_ALG_DES_CBC_NOPAD:
		return EVP_des_cbc();

	case TEE_ALG_DES3_ECB_NOPAD:
		return EVP_des_ede3_ecb();

	case TEE_ALG_DES3_CBC_NOPAD:
		return EVP_des_ede3_cbc();

	default:
		return NULL;
	}
}

static void set_symmetric_padding(uint32_t algorithm, EVP_CIPHER_CTX *ctx)
{
	switch (algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		 EVP_CIPHER_CTX_set_padding(ctx, 0);
	default:
		return;
	}
}








/*************************************************************************************************
*												 *
*												 *
*												 *
*												 *
* ############################################################################################## *
* #											       # *
* #  ---------------------------------------------------------------------------------------   # *
* #  |										            |  # *
* #  | #    #   #  # ## I n t e r n a l   A P I   f u n c t i o n s ## #  #   #    #     #  |  # *
* #  |										            |  # *
* #  ---------------------------------------------------------------------------------------   # *
* #											       # *
* ############################################################################################## *
*												 *
*												 *
*												 *
*												 *
*************************************************************************************************/






TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation, uint32_t algorithm,
				 uint32_t mode, uint32_t maxKeySize)
{
	/* TODO: Add max/algo key check */

	/* NOTICE: Alloc all resources here. Now it is divited to setOperationKey -func  */

	TEE_OperationHandle tmp_handle = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!valid_mode_and_algorithm(algorithm, mode)) {
		syslog(LOG_ERR, "Not a valid mode, algorithm or mode for algorithm\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (not_supported_algorithms(algorithm, maxKeySize)) {
		syslog(LOG_ERR, "Algorithm not yet implemented\n");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	tmp_handle = TEE_Malloc(sizeof(struct __TEE_OperationHandle), 0);
	if (tmp_handle == NULL) {
		syslog(LOG_ERR, "Out of memory (operation handler)\n");
		goto error;
	}

	/* Function only malloc space for key structs. Not the actual key components! */
	ret = malloc_key_meta_info(tmp_handle, algorithm);
	if (ret != TEE_SUCCESS)
		goto error; /* error message has been logged */

	/* Create and initializes */
	tmp_handle->key.ctx = EVP_CIPHER_CTX_new();
	if (!tmp_handle->key.ctx) {
		syslog(LOG_ERR, "Out of memory (EVP context)\n");
		goto error;
	}

	tmp_handle->operation_info.mode = mode;
	tmp_handle->operation_info.algorithm = algorithm;
	tmp_handle->operation_info.maxKeySize = maxKeySize;

	*operation = tmp_handle;
	return ret;

error:
	TEE_FreeOperation(tmp_handle);
	*operation = NULL;
	return ret;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	if (!operation)
		return;

	/* Free key */
	free_key(&operation->key);

	/* Free operation handle */
	rand_buf(operation, sizeof(struct __TEE_OperationHandle));
	TEE_Free(operation);
	operation = NULL;

	/* openssl cleanup */
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	ERR_free_strings();
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	/* TODO: Add check for: The type, size, or usage of key is
	 * not compatible with the algorithm, mode, or size of the operation.
	 * TODO: If key null -> clear all :/
	 * TODO: Check and add correct flags end of operation */

	TEE_Result ret;

	if (!operation || !key)
		return TEE_ERROR_GENERIC;

	if (!(key->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		syslog(LOG_ERR, "Key is not initialized\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.algorithm == TEE_ALG_AES_XTS) {
		syslog(LOG_ERR, "Operation expecting two keys\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if ((operation->operation_info.mode == TEE_MODE_DIGEST) && key) {
		syslog(LOG_ERR, "Not expected a key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	ret = malloc_and_init_keys_to_op(&operation->key, operation->operation_info.algorithm, key);
	if (ret != TEE_SUCCESS) {
		syslog(LOG_ERR, "Something went wrong at key set\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	operation->operation_info.handleState &= TEE_HANDLE_FLAG_KEY_SET;

	return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation, TEE_ObjectHandle key1,
				TEE_ObjectHandle key2)
{
	/* TODO: Same TODO as setOpKey */

	/* Notice: The TEE_SetOperationKey2 function initializes an existing operation with
	 * two keys. This is used only for the algorithm TEE_ALG_AES_XTS. */

	TEE_Attribute *sym_key1 = NULL;
	TEE_Attribute *sym_key2 = NULL;

	if (!operation || !key1 || !key2)
		return TEE_ERROR_GENERIC;

	if (operation->operation_info.algorithm != TEE_ALG_AES_XTS) {
		syslog(LOG_ERR, "Operation NOT expecting two keys\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!(key1->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(key2->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		syslog(LOG_ERR, "Key is not initialized\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (((operation->operation_info.mode == TEE_MODE_DIGEST) && key1) ||
	    ((operation->operation_info.mode == TEE_MODE_DIGEST) && key2)){
		syslog(LOG_ERR, "Not expected a key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	sym_key1 = get_attr_by_ID(key1, TEE_ATTR_SECRET_VALUE);
	if (!sym_key1) {
		syslog(LOG_ERR, "Key1 does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	sym_key2 = get_attr_by_ID(key2, TEE_ATTR_SECRET_VALUE);
	if (!sym_key2) {
		syslog(LOG_ERR, "Key2 does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	operation->key.sym_key_len = sym_key1->content.ref.length + sym_key2->content.ref.length;

	operation->key.sym_key = TEE_Malloc(operation->key.sym_key_len, 0);
	if (!operation->key.sym_key) {
		syslog(LOG_ERR, "Cannot malloc space for AES XTS symmetric key\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Hardcoded openssl solution! */
	memcpy(operation->key.sym_key, sym_key1->content.ref.buffer, sym_key1->content.ref.length);
	memcpy((unsigned char *)operation->key.sym_key + sym_key1->content.ref.length,
		sym_key2->content.ref.buffer, sym_key2->content.ref.length);

	operation->operation_info.handleState &= TEE_HANDLE_FLAG_KEY_SET;

	return TEE_SUCCESS;
}


void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (!dstOperation || !srcOperation) {
		/* panic(TEE_ERROR_BAD_PARAMETERS); */
	}

	if (dstOperation->operation_info.mode != srcOperation->operation_info.mode) {
		/* panic(TEE_ERROR_BAD_STATE); */
	}

	if (dstOperation->operation_info.algorithm != srcOperation->operation_info.algorithm) {
		/* panic(TEE_ERROR_BAD_STATE); */
	}

	if (srcOperation->operation_info.maxKeySize > dstOperation->operation_info.maxKeySize) {
		/* panic(TEE_ERROR_BAD_PARAMETERS); */
	}

	memcpy(dstOperation, srcOperation, sizeof(struct __TEE_OperationHandle));
}

void TEE_CipherInit(TEE_OperationHandle operation, void* IV, size_t IVLen)
{	
	const EVP_CIPHER *cipher = NULL;

	cipher = load_AES_DES_DES3_evp_cipher(operation->operation_info.algorithm,
					      operation->operation_info.maxKeySize);
	if (!cipher) {
		syslog(LOG_ERR, "Algorithm is not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	set_symmetric_padding(operation->operation_info.algorithm, operation->key.ctx);

	/* EVP logic: return 1 for success and 0 for failure. */
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {
		if (EVP_EncryptInit_ex(operation->key.ctx,
				       cipher, NULL, operation->key.sym_key, IV) == 0) {
			syslog(LOG_ERR, "Something went wrong at enc init (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {
		if (EVP_DecryptInit_ex(operation->key.ctx,
				       cipher, NULL, operation->key.sym_key, IV) == 0) {
			syslog(LOG_ERR, "Something went wrong at dec init (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else {
		/* Should never end up here! */
		syslog(LOG_ERR, "Something is wrong with cipher init\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void* srcData, size_t srcLen,
			    void* destData, size_t *destLen)
{
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {
		if (EVP_EncryptUpdate(operation->key.ctx, destData, destLen,
				      srcData, srcLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at enc update (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {3;
		if (EVP_DecryptUpdate(operation->key.ctx, destData, destLen,
				      srcData, srcLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at dec update (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else {
		/* Should never end up here! */
		syslog(LOG_ERR, "Something is wrong with cipher update\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void* srcData, size_t srcLen,
			     void* destData, size_t *destLen)
{
	/* TODO: Handle SRC data !! */
	srcData = srcData;
	srcLen = srcLen;

	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {
		if (EVP_EncryptFinal_ex(operation->key.ctx, destData, destLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at enc final (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {
		if (EVP_DecryptFinal_ex(operation->key.ctx, destData, destLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at dec final (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
	} else {
		/* Should never end up here! */
		syslog(LOG_ERR, "Something is wrong with cipher do final\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return TEE_SUCCESS;
}









