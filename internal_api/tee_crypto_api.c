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

#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <string.h>
#include <syslog.h>
#include <limits.h>

#include "tee_crypto_api.h"
#include "tee_memory.h"
#include "tee_storage_api.h"
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
	void *IV;
	uint32_t IV_len;
};

struct __TEE_OperationHandle {
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

/* NOTICE: openssl init and cleanup should only called once. These should be executed before
 * TA is loaded/first invoke command */
static bool openssl_init()
{
	int read_bytes;
	long seed_bytes = 1; /* # INCREASE # */
	unsigned char test_buf[10];

	/* Init and load algorithms */
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* seed random generator */
	read_bytes = RAND_load_file("/dev/random", seed_bytes);
	if (read_bytes != seed_bytes) {
		syslog(LOG_ERR, "PRNG seed fail (openssl failure)\n");
		return false;
	}

	/* test PNRG */
	if (!RAND_bytes(test_buf, sizeof(test_buf))){
		syslog(LOG_ERR, "Problems with random generator (openssl failure)\n");
		return false;
	}

	return true;
}

static void openssl_cleanup()
{
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
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

/* Remove when not needed.. only for copying algorithms and modes..
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

/* Done: AES, DES, DES3 */
static bool valid_key_size_for_algorithm(uint32_t alg, uint32_t key)
{
	switch (alg) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
		if (key == 128 || key == 256)
			return true;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_GCM:
		if (key == 128 || key == 192 || key == 256)
			return true;
		break;

	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		if (key == 56)
			return true;
		break;

	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		if (key == 112 || key == 168)
			return true;
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
		if (key >= 256 && key <= 2048)
			return true;
		return false;

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
	default:
		break;
	}

	syslog(LOG_ERR, "Algorithm do not sup that key\n");
	return false;
}

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

	if (!RSA_check_key(op_key->rsa_key)) {
		syslog(LOG_ERR, "RSA key setting failed\n");
		TEE_Panic(TEE_ERROR_GENERIC);
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

	/* Free IV */
	rand_buf(released_key->IV, released_key->IV_len);
	TEE_Free(released_key->IV);

	/* EVP cipher context */
	if (released_key->ctx)
		EVP_CIPHER_CTX_cleanup(released_key->ctx);
	EVP_CIPHER_CTX_free(released_key->ctx);

}

/*
static const EVP_MD *load_evp_digest(uint32_t algorithm)
{
	switch (algorithm) {
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
	case TEE_ALG_MD5:
		return EVP_md5();

	case TEE_ALG_SHA1:
		return EVP_sha1();

	case TEE_ALG_SHA224:
		return EVP_sha224();

	case TEE_ALG_SHA256:
		return EVP_sha256();

	case TEE_ALG_SHA384:
		return EVP_sha384();

	case TEE_ALG_SHA512:
		return EVP_sha512();

	case TEE_ALG_HMAC_MD5:		
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	default:
		return NULL;
	}
}
*/

static const EVP_CIPHER *load_evp_symmetric_cipher(uint32_t algorithm, uint32_t key_size)
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
		/* Not supported. No openssl direct sup */
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
/*
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
*/
	case TEE_ALG_DES_ECB_NOPAD:
		return EVP_des_ecb();

	case TEE_ALG_DES_CBC_NOPAD:
		return EVP_des_cbc();

	case TEE_ALG_DES3_ECB_NOPAD:
		switch (key_size) {
		case 112:
			return EVP_des_ede_ecb();
		case 168:
			return EVP_des_ede3_ecb();
		default:
			return NULL;
		}

		return NULL;

	case TEE_ALG_DES3_CBC_NOPAD:
		switch (key_size) {
		case 112:
			return EVP_des_ede_cbc();
		case 168:
			return EVP_des_ede3_cbc();
		default:
			return NULL;
		}

	default:
		return NULL;
	}
}

static bool alg_requires_2_keys(uint32_t alg)
{
	return (alg == TEE_ALG_AES_XTS) ? true : false;
}

static int size_t2int(size_t cast_size_t)
{
	if (cast_size_t > INT_MAX) {
		syslog(LOG_ERR, "size_t to int overflow!\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return cast_size_t;
}

static size_t int2size_t(int cast_int)
{
	if (cast_int < 0) {
		syslog(LOG_ERR, "int to size_t underflow!\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return cast_int;
}

static uint32_t get_operation_class(uint32_t alg)
{
	switch (alg) {
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
		return TEE_OPERATION_CIPHER;

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		return TEE_OPERATION_MAC;

	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
		return TEE_OPERATION_AE;

	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		return TEE_OPERATION_DIGEST;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
		return TEE_OPERATION_ASYMMETRIC_CIPHER;

	case TEE_ALG_DSA_SHA1:
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
		return TEE_OPERATION_ASYMMETRIC_SIGNATURE;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		return TEE_OPERATION_KEY_DERIVATION;

	default:
		syslog(LOG_ERR, "Seems so that algorithm can not match operation type\n");
		TEE_Panic(TEE_ERROR_GENERIC);
		return 0; /* return for compiler */
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

static bool valid_key_type_for_operation_algorithm(uint32_t key_type, uint32_t op_algorithm)
{
	switch (key_type) {
	case TEE_TYPE_GENERIC_SECRET:
		return true;

	case TEE_TYPE_AES:
		switch (op_algorithm) {
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
			return true;
		default:
			return false;
		}

	case TEE_TYPE_DES:
		switch (op_algorithm) {
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
			return true;
		default:
			return false;
		}

	case TEE_TYPE_DES3:
		switch (op_algorithm) {
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			return true;
		default:
			return false;
		}

	case TEE_TYPE_HMAC_MD5:
		if (op_algorithm == TEE_ALG_MD5)
			return true;
		return false;

	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
		switch (op_algorithm) {
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

	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_RSA_PUBLIC_KEY:
		switch (op_algorithm) {
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

			return true;
		default:
			return false;
		}

	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
		if (op_algorithm == TEE_ALG_DSA_SHA1)
			return true;
		return false;


	case TEE_TYPE_DH_KEYPAIR:
		if (op_algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET)
			return true;
		return false;

	default:
		return false;
	}
}

static bool key_usege_allow_operation(uint32_t obj_usage, uint32_t op_mode, uint32_t alg)
{
	/* RSA no padding is a special case */
	if (alg == TEE_ALG_RSA_NOPAD) {

		if ((obj_usage & TEE_USAGE_DECRYPT) &&
		    (obj_usage & TEE_USAGE_VERIFY) && (op_mode == TEE_MODE_DECRYPT)) {
			return true;
		} else if ((obj_usage & TEE_USAGE_ENCRYPT) &&
			   (obj_usage & TEE_USAGE_SIGN) && (op_mode == TEE_MODE_ENCRYPT)) {
			return true;
		} else {
			return false;
		}
	}

	switch (op_mode) {
	case TEE_MODE_ENCRYPT:
		if (obj_usage & TEE_USAGE_ENCRYPT)
			return true;
		return false;

	case TEE_MODE_DECRYPT:
		if (obj_usage & TEE_USAGE_DECRYPT)
			return true;
		return false;

	case TEE_MODE_SIGN:
		if (obj_usage & TEE_USAGE_SIGN)
			return true;
		return false;

	case TEE_MODE_VERIFY:
		if (obj_usage & TEE_USAGE_VERIFY)
			return true;
		return false;

	case TEE_MODE_MAC:
		if (obj_usage & TEE_USAGE_MAC)
			return true;
		return false;

	case TEE_MODE_DIGEST:
		/* Should never happen */
		syslog(LOG_ERR, "No need object for digest\n");
		TEE_Panic(TEE_ERROR_GENERIC);

	case TEE_MODE_DERIVE:
		if (obj_usage & TEE_USAGE_DERIVE)
			return true;
		return false;

	default:
		return false;
	}
}

static TEE_Result valid_key_and_operation(TEE_ObjectHandle key, TEE_OperationHandle operation)
{
	if (!(key->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		syslog(LOG_ERR, "Key is not initialized\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		syslog(LOG_ERR, "Operation is initialized\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) {
		syslog(LOG_ERR, "Operation key is set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((operation->operation_info.mode == TEE_MODE_DIGEST) && key) {
		syslog(LOG_ERR, "Not expected a key\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (key->objectInfo.maxObjectSize > operation->operation_info.maxKeySize) {
		syslog(LOG_ERR, "Key does not fit to operation\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!valid_key_type_for_operation_algorithm(key->objectInfo.objectType,
						    operation->operation_info.algorithm)) {
		syslog(LOG_ERR, "Key does not match operation algorithm\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (!key_usege_allow_operation(key->objectInfo.objectUsage,
				       operation->operation_info.mode,
				       operation->operation_info.algorithm)) {
		syslog(LOG_ERR, "Key does not allow operation\n");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
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
	/* NOTICE: This func should Alloc all resources here, but now it is divited to
	 * setOperationKey -func and crypto init functions. This can be added TODO -list, when
	 * all crypto functions have a working implementation. Then it should be easy enough
	 * to collect all Malloc operations.. */

	TEE_OperationHandle tmp_handle = NULL;
	TEE_Result ret = TEE_SUCCESS;

	/* MOVE (when place know) */
	if (!openssl_init())
		return TEE_ERROR_GENERIC;

	if (!valid_mode_and_algorithm(algorithm, mode)) {
		syslog(LOG_ERR, "Not a valid mode, algorithm or mode for algorithm\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!valid_key_size_for_algorithm(algorithm, maxKeySize)) {
		syslog(LOG_ERR, "Not a valid key size for algorithm\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
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

	/* Function malloc space only for keys meta data for example openssl structs and
	 * not for the actual key components! This is here, because key is set prior operations */
	ret = malloc_key_meta_info(tmp_handle, algorithm);
	if (ret != TEE_SUCCESS)
		goto error; /* error message has been logged */

	/* Generic info about operation */
	tmp_handle->operation_info.mode = mode;
	tmp_handle->operation_info.algorithm = algorithm;
	tmp_handle->operation_info.maxKeySize = maxKeySize;
	if (alg_requires_2_keys(algorithm))
		tmp_handle->operation_info.handleState |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;
	tmp_handle->operation_info.operationClass = get_operation_class(algorithm);

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

	/* MOVE */
	openssl_cleanup();
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	/* NOTICE: This only reset CIPHER operation! So add our imp, if you something done */

	if (!operation)
		return;

	/* Clear operation state */
	operation->operation_info.handleState ^= TEE_HANDLE_FLAG_INITIALIZED;

	/* Clear crypto specific state */
	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {
		/* Brute force reset: Delete old context and malloc new. Easiest */
		EVP_CIPHER_CTX_cleanup(operation->key.ctx);
		EVP_CIPHER_CTX_free(operation->key.ctx);
		operation->key.ctx = NULL;

		TEE_CipherInit(operation, operation->key.IV, operation->key.IV_len);
	}
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	/* TODO: Add check for: The type, size, or usage of key is
	 * not compatible with the algorithm, mode, or size of the operation.
	 * TODO: Check and add correct flags end of operation */

	TEE_Result ret = TEE_SUCCESS;

	if (!operation) {
		syslog(LOG_ERR, "Set key error: Parameters problem\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	/* If key NULL, clear key from operation. */
	if (!key) {
		free_key(&operation->key);
		operation->operation_info.handleState = 0;
		goto retu;
	}

	if (operation->operation_info.algorithm == TEE_ALG_AES_XTS) {
		syslog(LOG_ERR, "Operation expecting two keys\n");
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}

	ret = valid_key_and_operation(key, operation);
	if (ret != TEE_SUCCESS)
		goto err;

	ret = malloc_and_init_keys_to_op(&operation->key, operation->operation_info.algorithm, key);
	if (ret != TEE_SUCCESS) {
		syslog(LOG_ERR, "Something went wrong at key set\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

retu:
	return ret;

err:
	/* Error has been written to syslog */
	TEE_Panic(ret);
	return 0; /* return for compiler */
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation, TEE_ObjectHandle key1,
				TEE_ObjectHandle key2)
{
	/* Notice: The TEE_SetOperationKey2 function initializes an existing operation with
	 * two keys. This is used only for the algorithm TEE_ALG_AES_XTS! */

	TEE_Attribute *sym_key1 = NULL;
	TEE_Attribute *sym_key2 = NULL;

	TEE_Result ret = TEE_SUCCESS;

	if (!operation || !key1 || !key2) {
		syslog(LOG_ERR, "Set key error: Parameters problem\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (operation->operation_info.algorithm != TEE_ALG_AES_XTS) {
		syslog(LOG_ERR, "Operation NOT expecting two keys\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	ret = valid_key_and_operation(key1, operation);
	if (ret != TEE_SUCCESS)
		goto err;

	ret = valid_key_and_operation(key2, operation);
	if (ret != TEE_SUCCESS)
		goto err;

	/* Provited key usage/type/size are OK.
	 * Next. Retriev keys from key obj */
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

	/* Calculate key length and malloc space for key */
	operation->key.sym_key_len = sym_key1->content.ref.length + sym_key2->content.ref.length;

	operation->key.sym_key = TEE_Malloc(operation->key.sym_key_len, 0);
	if (!operation->key.sym_key) {
		syslog(LOG_ERR, "Cannot malloc space for AES XTS symmetric key\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Hardcoded openssl solution! For AES XTS openssl requires twice as long key. So for
	 * example at aes128xts case key size would be 256. Tweak is provited with IV parameter */
	memcpy(operation->key.sym_key, sym_key1->content.ref.buffer, sym_key1->content.ref.length);
	memcpy((unsigned char *)operation->key.sym_key + sym_key1->content.ref.length,
		sym_key2->content.ref.buffer, sym_key2->content.ref.length);

	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

	return ret;

err:
	/* Error has been written to syslog */
	TEE_Panic(ret);
	return 0; /* return for compiler */
}


void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	/* NOTICE: Copy only cipher */

	if (!dstOperation || !srcOperation) {
		syslog(LOG_ERR, "Operation copy error: bad parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (dstOperation->operation_info.mode != srcOperation->operation_info.mode) {
		syslog(LOG_ERR, "Operation copy error: modes\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (dstOperation->operation_info.algorithm != srcOperation->operation_info.algorithm) {
		syslog(LOG_ERR, "Operation copy error: algorithms\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (srcOperation->operation_info.maxKeySize > dstOperation->operation_info.maxKeySize) {
		syslog(LOG_ERR, "Operation copy error: key size\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (srcOperation->operation_info.operationClass == TEE_OPERATION_CIPHER) {
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
	} else {
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
	}
}

void TEE_CipherInit(TEE_OperationHandle operation, void* IV, size_t IVLen)
{	
	const EVP_CIPHER *cipher = NULL;

	if (!IV || !operation) {
		syslog(LOG_ERR, "Error at cipher init\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		syslog(LOG_ERR, "Not a cipher class operation or already initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Malloc and cpy IV */
	if (!operation->key.IV) {
		operation->key.IV = TEE_Malloc(IVLen, 0);
		if (!operation->key.IV) {
			syslog(LOG_ERR, "Out of memory at cipher inint: IV malloc\n");
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
		}

		operation->key.IV_len = IVLen;
	}

	/* Crypto operation is "done" with OpenSSL EVP-api. Create and init EVP context */
	operation->key.ctx = EVP_CIPHER_CTX_new();
	if (!operation->key.ctx) {
		syslog(LOG_ERR, "Out of memory (EVP context)\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	set_symmetric_padding(operation->operation_info.algorithm, operation->key.ctx);

	cipher = load_evp_symmetric_cipher(operation->operation_info.algorithm,
					   operation->operation_info.maxKeySize);
	if (!cipher) {
		syslog(LOG_ERR, "Algorithm is not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

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

	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void* srcData, size_t srcLen,
			    void* destData, size_t *destLen)
{
	int int_destLen;

	if (!operation || !srcData || !destData || !destLen) {
		syslog(LOG_ERR, "Error with cipher update parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		syslog(LOG_ERR, "Not a cipher class operation or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	int_destLen = size_t2int(*destLen); /* EVP operates with int */

	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if ((EVP_CIPHER_CTX_block_size(operation->key.ctx) + srcLen - 1) > *destLen) {
			syslog(LOG_ERR, "Cipher buffer too small\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (EVP_EncryptUpdate(operation->key.ctx, destData, &int_destLen,
				      srcData, size_t2int(srcLen)) == 0) {
			syslog(LOG_ERR, "Something went wrong at enc update (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (srcLen > *destLen + EVP_CIPHER_CTX_block_size(operation->key.ctx)) {
			syslog(LOG_ERR, "Plain buffer too small\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (EVP_DecryptUpdate(operation->key.ctx, destData, &int_destLen,
				      srcData, size_t2int(srcLen)) == 0) {
			syslog(LOG_ERR, "Something went wrong at dec update (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else {
		/* Should never end up here! */
		syslog(LOG_ERR, "Something is wrong with cipher update\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	*destLen = int2size_t(int_destLen);

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void* srcData, size_t srcLen,
			     void* destData, size_t *destLen)
{
	int int_destLen = 0;
	int total_int_destLen = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!destData || !operation) {
		syslog(LOG_ERR, "Error with cipher final parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		syslog(LOG_ERR, "Not a cipher class operation or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (destLen)
		int_destLen = size_t2int(*destLen); /* EVP operates with int */

	/* Handle last src data */
	if (srcLen > 0) {

		ret = TEE_CipherUpdate(operation, srcData, srcLen, destData, destLen);
		if (ret != TEE_SUCCESS) {
			syslog(LOG_ERR, "Do final src data problem\n");			;
			goto retu;
		}

		total_int_destLen += int_destLen;
	}

	/* Do final */
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if (EVP_EncryptFinal_ex(operation->key.ctx, destData, &int_destLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at enc final (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (EVP_DecryptFinal_ex(operation->key.ctx, destData, &int_destLen) == 0) {
			syslog(LOG_ERR, "Something went wrong at dec final (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else {
		/* Should never end up here! */
		syslog(LOG_ERR, "Something is wrong with cipher do final\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	total_int_destLen += int_destLen;
	if (destLen)
		*destLen = int2size_t(total_int_destLen);

retu:

	return ret;
}

/*
TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation, TEE_Attribute* params,
				 uint32_t paramCount, void* srcData, size_t srcLen,
				 void* destData, size_t *destLen)
{
	switch (operation->operation_info.algorithm) {
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

	return TEE_SUCCESS;
}
*/







