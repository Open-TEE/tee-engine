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

/* Checklist for adding supportion for a new algorithm. If you do not remember to add our algorithm
 * identifier to following functions, operation generic functions will fail or undefined behavior:
 *
 * static bool		supported_algorithms(..)
 * static bool		valid_mode_and_algorithm(..)
 * static bool		valid_key_size_for_algorithm(..)
 * static TEE_Result	init_operation_meta_info(..)
 * static uint32_t	get_operation_class(..)
 * static bool		valid_key_type_for_operation_algorithm(..)
 * static uint32_t	get_actual_key_size(..)
 * TEE_Result		TEE_SetOperationKey(..)
 */

#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>

#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "tee_crypto_api.h"
#include "tee_memory.h"
#include "tee_storage_api.h"
#include "tee_object_handle.h"
#include "tee_panic.h"
#include "tee_data_types.h"
#include "openssl_1_0_2_beta_rsa_oaep.h"
#include "tee_logging.h"

#define BITS_TO_BYTES(bits) (bits / 8)
#define DIGEST_CTX(OPERATION_HANDLE) ((EVP_MD_CTX *)OPERATION_HANDLE->dig_ctx)
#define RSA_key(OPERATION_HANDLE) ((RSA *)(OPERATION_HANDLE->key.key))
#define DSA_key(OPERATION_HANDLE) ((DSA *)(OPERATION_HANDLE->key.key))
#define DH_key(OPERATION_HANDLE) ((DH *)(OPERATION_HANDLE->key.key))
#define SYM_ctx(OPERATION_HANDLE) ((EVP_CIPHER_CTX *)(OPERATION_HANDLE->key.ctx))
#define SYM_key(OPERATION_HANDLE) (OPERATION_HANDLE->key.key)
#define SYM_key_len(OPERATION_HANDLE) (OPERATION_HANDLE->key.key_len)
#define HMAC_ctx(OPERATION_HANDLE) ((HMAC_CTX *)(OPERATION_HANDLE->key.ctx))
#define CMAC_ctx(OPERATION_HANDLE) ((CMAC_CTX *)(OPERATION_HANDLE->key.ctx))

static const uint32_t TEE_OP_STATE_ACTIVE = 1;
static const uint32_t TEE_OP_STATE_INITIAL = 0;

struct operation_key {
	void *ctx;
	void *key;
	uint32_t key_len;
	void *IV;
	uint32_t IV_len;
};

struct __TEE_OperationHandle {
	TEE_OperationInfo operation_info;
	struct operation_key key;
	void *dig_ctx;
	uint32_t op_state;
	uint32_t key_size2; /* If operation has two key, this is second key len */
};

static bool __attribute__((constructor)) openssl_init()
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
		OT_LOG(LOG_ERR, "Openssl init: PRNG seed fail (openssl failure)\n");
		return false;
	}

	/* test PNRG */
	if (!RAND_bytes(test_buf, sizeof(test_buf))) {
		OT_LOG(LOG_ERR, "Openssl init: Problems with random generator (openssl failure)\n");
		return false;
	}

	return true;
}

static void __attribute__((destructor)) openssl_cleanup()
{
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_remove_state(0);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

/* This function is collection algorithms/key sizes that is supported/implemented */
static bool supported_algorithms(uint32_t alg, uint32_t key_size)
{
	switch (alg) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
		return false;

	/* Supported algorithms */
	case TEE_ALG_AES_XTS:
		if (key_size == 192)
			return false;

		return true;

	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
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
	case TEE_ALG_AES_CMAC:
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

static bool valid_key_size_for_algorithm(uint32_t alg, uint32_t key)
{
	switch (alg) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		/* No keys */
		return true;

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
		break;

	case TEE_ALG_HMAC_MD5:
		if (key >= 80 && key <= 512 && !(key % 8))
			return true;
		break;

	case TEE_ALG_HMAC_SHA1:
		if (key >= 112 && key <= 512 && !(key % 8))
			return true;
		break;

	case TEE_ALG_HMAC_SHA224:
		if (key >= 192 && key <= 512 && !(key % 8))
			return true;
		break;

	case TEE_ALG_HMAC_SHA256:
		if (key >= 256 && key <= 1024 && !(key % 8))
			return true;
		break;

	case TEE_ALG_HMAC_SHA384:
		if (key >= 64 && key <= 1024 && !(key % 8))
			return true;
		break;

	case TEE_ALG_HMAC_SHA512:
		if (key >= 64 && key <= 1024 && !(key % 8))
			return true;
		break;

	case TEE_ALG_DSA_SHA1:
		if (key >= 512 && key <= 1024 && !(key % 64))
			return true;
		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		if (key >= 256 && key <= 2048)
			return true;
		break;

	default:
		break;
	}

	OT_LOG(LOG_ERR, "valid_key_size_for_algorithm: Algorithm do not sup that key\n");
	return false;
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

/* This function type is BOOL only for debug purpose */
static bool cpy_key_comp_to_bn(BIGNUM **bn, uint32_t attrID, TEE_ObjectHandle key)
{
	TEE_Attribute *rsa_component = NULL;

	rsa_component = get_attr_by_ID(key, attrID);
	if (!rsa_component) {
		OT_LOG(LOG_ERR, "cpy RSA comp to op: RSA attribute ID is not found at key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*bn = BN_bin2bn(rsa_component->content.ref.buffer, rsa_component->content.ref.length, *bn);
	if (!*bn) {
		OT_LOG(LOG_ERR, "cpy RSA comp to op: bin2bn failed (openssl failure)\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return true;
}

static void rand_buf(void *buf, uint32_t len)
{
	if (!buf || len == 0)
		return;

	if (!RAND_bytes(buf, len))
		TEE_MemFill(buf, 0, len);
}

static void free_key_and_ctx(TEE_OperationHandle operation)
{
	if (!operation)
		return;

	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {

		/* Free EVP sturcture */
		EVP_CIPHER_CTX_cleanup(SYM_ctx(operation));
		EVP_CIPHER_CTX_free(SYM_ctx(operation));

		/* Free key */
		rand_buf(SYM_key(operation), SYM_key_len(operation));
		rand_buf(&SYM_key_len(operation), sizeof(SYM_key_len(operation)));
		TEE_Free(SYM_key(operation));

	} else if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST) {

		/* Only for documenting purpose. Digest structures is freed at TEE_FreeOP */

	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER) {

		RSA_free(RSA_key(operation));

	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE) {

		if (operation->operation_info.algorithm == TEE_ALG_DSA_SHA1)
			DSA_free(DSA_key(operation));
		else
			RSA_free(RSA_key(operation));

	} else if (operation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {

		DH_free(DH_key(operation));

	} else if (operation->operation_info.operationClass == TEE_OPERATION_MAC) {

		/* Free key */
		rand_buf(SYM_key(operation), SYM_key_len(operation));
		rand_buf(&SYM_key_len(operation), sizeof(SYM_key_len(operation)));
		TEE_Free(SYM_key(operation));

		/* Cleanup ctx */
		switch (operation->operation_info.algorithm) {
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

		case TEE_ALG_AES_CMAC:
			CMAC_CTX_free(CMAC_ctx(operation));
			break;

		case TEE_ALG_HMAC_MD5:
		case TEE_ALG_HMAC_SHA1:
		case TEE_ALG_HMAC_SHA224:
		case TEE_ALG_HMAC_SHA256:
		case TEE_ALG_HMAC_SHA384:
		case TEE_ALG_HMAC_SHA512:
			HMAC_CTX_cleanup(HMAC_ctx(operation));
			TEE_Free(HMAC_ctx(operation));
			break;

		default:
			OT_LOG(LOG_ERR, "max_mac_len: Alg not supported\n");
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}
	}

	/* Free IV */
	rand_buf(operation->key.IV, operation->key.IV_len);
	rand_buf(&operation->key.IV_len, sizeof(operation->key.IV_len));

	TEE_Free(operation->key.IV);
}

static bool alg_requires_2_keys(uint32_t alg)
{
	return (alg == TEE_ALG_AES_XTS) ? true : false;
}

static int uint322int(uint32_t cast_uint32)
{
	if (cast_uint32 > INT_MAX) {
		OT_LOG(LOG_ERR, "uint322int: uint32_t to int overflow!\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return cast_uint32;
}

static uint32_t int2uint32(int cast_int)
{
	if (cast_int < 0) {
		OT_LOG(LOG_ERR, "int2uint32: int to uint32_t underflow!\n");
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
		OT_LOG(LOG_ERR, "Seems so that algorithm can not match operation type\n");
		TEE_Panic(TEE_ERROR_GENERIC);
		return 0; /* return for compiler */
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

static bool key_usage_allow_operation(uint32_t obj_usage, uint32_t op_mode, uint32_t alg)
{
	/* RSA no padding is a special case */
	if (alg == TEE_ALG_RSA_NOPAD) {

		if ((obj_usage & TEE_USAGE_DECRYPT) && (obj_usage & TEE_USAGE_VERIFY) &&
		    (op_mode == TEE_MODE_DECRYPT)) {
			return true;
		} else if ((obj_usage & TEE_USAGE_ENCRYPT) && (obj_usage & TEE_USAGE_SIGN) &&
			   (op_mode == TEE_MODE_ENCRYPT)) {
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
		OT_LOG(LOG_ERR, "No need key-object for digest\n");
		TEE_Panic(TEE_ERROR_GENERIC);

	case TEE_MODE_DERIVE:
		if (obj_usage & TEE_USAGE_DERIVE)
			return true;

		return false;

	default:
		return false;
	}
}

static bool object_type_compatible_to_op(uint32_t obj_type, uint32_t op_mode)
{
	if (obj_type == TEE_TYPE_DSA_PUBLIC_KEY && op_mode != TEE_MODE_VERIFY)
		return false;

	if (obj_type == TEE_TYPE_RSA_PUBLIC_KEY &&
	    !(op_mode == TEE_MODE_VERIFY || op_mode == TEE_MODE_ENCRYPT))
		return false;

	return true;
}

static TEE_Result valid_key_and_operation(TEE_ObjectHandle key, TEE_OperationHandle operation)
{
	if (!(key->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Key is not initialized\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->op_state == TEE_OP_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "Operation in active state\n");
		return TEE_ERROR_BAD_STATE;
	}

	if ((operation->operation_info.operationClass == TEE_OPERATION_CIPHER ||
	     operation->operation_info.operationClass == TEE_OPERATION_MAC) &&
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG(LOG_ERR, "Operation is initialized\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) {
		OT_LOG(LOG_ERR, "Operation key is set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.mode == TEE_MODE_DIGEST) {
		OT_LOG(LOG_ERR, "Not expected a key\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (key->objectInfo.maxObjectSize > operation->operation_info.maxKeySize) {
		OT_LOG(LOG_ERR, "Key does not fit to operation\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!object_type_compatible_to_op(key->objectInfo.objectType,
					  operation->operation_info.mode)) {
		OT_LOG(LOG_ERR, "Not compatible operation mode for key\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (!valid_key_type_for_operation_algorithm(key->objectInfo.objectType,
						    operation->operation_info.algorithm)) {
		OT_LOG(LOG_ERR, "Key does not match operation algorithm\n");
		return TEE_ERROR_BAD_STATE;
	}

	if (!key_usage_allow_operation(key->objectInfo.objectUsage, operation->operation_info.mode,
				       operation->operation_info.algorithm)) {
		OT_LOG(LOG_ERR, "Key does not allow operation\n");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static uint32_t get_actual_key_size(uint32_t objectType, uint32_t maxObjectSize)
{
	if (objectType == TEE_TYPE_DES || objectType == TEE_TYPE_DES3) {
		if (maxObjectSize == 56)
			return maxObjectSize + 8;

		if (maxObjectSize == 112)
			return maxObjectSize + 16;

		if (maxObjectSize == 168)
			return maxObjectSize + 24;
	}

	return maxObjectSize;
}

/*********************************************************************************************
 *											     *
 * S Y M M E T R I C   f u n c t i o n s						     *
 * 											     *
 *********************************************************************************************/

static TEE_Result malloc_and_cpy_symmetric_key(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	TEE_Attribute *sym_key = NULL;

	sym_key = get_attr_by_ID(key, TEE_ATTR_SECRET_VALUE);
	if (!sym_key) {
		OT_LOG(LOG_ERR, "Malloc and cpy sym; Key does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	operation->key.key = TEE_Malloc(sym_key->content.ref.length, 0);
	if (!operation->key.key) {
		OT_LOG(LOG_ERR, "Malloc and cpy sym; Cannot malloc space for symmetric key\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	operation->key.key_len = sym_key->content.ref.length;

	memcpy(operation->key.key, sym_key->content.ref.buffer, sym_key->content.ref.length);

	return TEE_SUCCESS;
}

static void check_IV_and_malloc_cpy2op(TEE_OperationHandle operation, void *IV, uint32_t IV_len)
{
	uint32_t ctx_iv_len;

	/* checks that IV meet min len, if longer, no prob :/ */
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_AES_CCM:
		if (IV_len < 7 || IV_len > 13) {
			OT_LOG(LOG_ERR, "check malloc cpy IV: AES-CCM nonce problem\n");
			TEE_Panic(TEE_ERROR_BAD_STATE);
		}

		break;

	case TEE_ALG_AES_GCM:
		if (IV_len % 8) {
			OT_LOG(LOG_ERR, "check malloc cpy IV: AES-GCM IV problem\n");
			TEE_Panic(TEE_ERROR_BAD_STATE);
		}

		break;

	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		ctx_iv_len = int2uint32(EVP_CIPHER_CTX_iv_length((SYM_ctx(operation))));
		if (ctx_iv_len > IV_len) {
			OT_LOG(LOG_ERR, "check malloc cpy IV: Algorithm IV too short\n");
			TEE_Panic(TEE_ERROR_BAD_STATE);
		}

		break;

	default:
		return; /* No IV needed and skip IV cpy */
	}

	/* IV OK. Malloc and cpy */
	operation->key.IV = TEE_Malloc(IV_len, 0);
	if (!operation->key.IV) {
		OT_LOG(LOG_ERR, "check malloc cpy IV: IV malloc\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	memcpy(operation->key.IV, IV, IV_len);
	operation->key.IV_len = IV_len;
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

static const EVP_CIPHER *load_evp_sym_cipher(TEE_OperationHandle operation)
{
	uint32_t algorithm = operation->operation_info.algorithm;
	uint32_t key_size = operation->operation_info.keySize;

	/* Symmetric algorithms */
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

/*********************************************************************************************
 *											     *
 * D I G E S T   f u n c t i o n s							     *
 * 											     *
 *********************************************************************************************/

static TEE_Result init_digest_op(TEE_OperationHandle operation, uint32_t algorithm)
{
	const EVP_MD *digest;

	switch (algorithm) {
	case TEE_ALG_MD5:
		digest = EVP_md5();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	case TEE_ALG_SHA1:
		digest = EVP_sha1();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	case TEE_ALG_SHA224:
		digest = EVP_sha224();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	case TEE_ALG_SHA256:
		digest = EVP_sha256();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	case TEE_ALG_SHA384:
		digest = EVP_sha384();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	case TEE_ALG_SHA512:
		digest = EVP_sha512();
		operation->operation_info.digestLength = EVP_MD_size(digest);
		break;

	default:
		/* should never end up here */
		OT_LOG(LOG_ERR, "Init deigest op: Digest alg is not supported or found\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	operation->dig_ctx = (EVP_MD_CTX *)EVP_MD_CTX_create();
	if (!DIGEST_CTX(operation)) {
		OT_LOG(LOG_ERR, "Init deigest op: out of memory: EVP_MD_ctx\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (EVP_DigestInit_ex(DIGEST_CTX(operation), digest, NULL) != 1) {
		OT_LOG(LOG_ERR, "Init deigest op: Problem with digest init (openssl failure)\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Digest has not init function */
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	operation->operation_info.maxKeySize = 0; /* no key */

	return TEE_SUCCESS;
}

/*********************************************************************************************
 *											     *
 * A S Y M    f u n c t i o n s							             *
 * 											     *
 *********************************************************************************************/

static const EVP_MD *load_evp_asym_hash(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSA_NOPAD:
		return NULL;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return EVP_md5();

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		return EVP_sha1();

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		return EVP_sha224();

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		return EVP_sha256();

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		return EVP_sha384();

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return EVP_sha512();
	default:
		OT_LOG(LOG_ERR, "load_evp_asym_hash: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return NULL; /* suppress compiler */
}

static TEE_Result malloc_and_cpy_rsa_key(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	if (!RSA_key(operation)) {
		OT_LOG(LOG_ERR, "cpy RSA key: Not a proper operation handler\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	/* Every RSA object contain modulo and public exponent ( == TEE_TYPE_RSA_PUBLIC_KEY) */
	if (!cpy_key_comp_to_bn(&RSA_key(operation)->n, TEE_ATTR_RSA_MODULUS, key) ||
	    !cpy_key_comp_to_bn(&RSA_key(operation)->e, TEE_ATTR_RSA_PUBLIC_EXPONENT, key)) {
		OT_LOG(LOG_ERR, "cpy RSA key: Error with modulo|public exponent\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (key->objectInfo.objectType == TEE_TYPE_RSA_KEYPAIR) {

		/* Key pair minimum is modulo, public and private exponent */
		if (!cpy_key_comp_to_bn(&RSA_key(operation)->d, TEE_ATTR_RSA_PRIVATE_EXPONENT, key)) {
			OT_LOG(LOG_ERR, "cpy RSA key: Error with private exponent\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		/* If there is any other component provited, all should be provited */
		if (get_attr_by_ID(key, TEE_ATTR_RSA_PRIME1) ||
		    get_attr_by_ID(key, TEE_ATTR_RSA_PRIME2) ||
		    get_attr_by_ID(key, TEE_ATTR_RSA_EXPONENT1) ||
		    get_attr_by_ID(key, TEE_ATTR_RSA_EXPONENT1) ||
		    get_attr_by_ID(key, TEE_ATTR_RSA_COEFFICIENT)) {

			if (!cpy_key_comp_to_bn(&RSA_key(operation)->p, TEE_ATTR_RSA_PRIME1, key) ||
			    !cpy_key_comp_to_bn(&RSA_key(operation)->q, TEE_ATTR_RSA_PRIME2, key) ||
			    !cpy_key_comp_to_bn(&RSA_key(operation)->dmp1, TEE_ATTR_RSA_EXPONENT1, key) ||
			    !cpy_key_comp_to_bn(&RSA_key(operation)->dmq1, TEE_ATTR_RSA_EXPONENT2, key) ||
			    !cpy_key_comp_to_bn(&RSA_key(operation)->iqmp, TEE_ATTR_RSA_COEFFICIENT, key)) {
				OT_LOG(LOG_ERR, "cpy RSA key: Error with RSA other component\n");
				TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
			}
		}
	}

	return TEE_SUCCESS;
}

static uint32_t rsa_msg_max_len(TEE_OperationHandle operation, const EVP_MD *hash)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return RSA_size(RSA_key(operation)) - 11;

	case TEE_ALG_RSA_NOPAD:
		return RSA_size(RSA_key(operation));

	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:

		if (!hash) {
			OT_LOG(LOG_ERR, "rsa_msg_max_len: Expected EVP hash algorithm\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		/* Buf max size: RSA modulo - 2 * Hash Out Put - 2 */
		return (RSA_size(RSA_key(operation)) - (2 * EVP_MD_size(hash)) - 2);

	default:
		/* Should never end up here */
		OT_LOG(LOG_ERR, "rsa_msg_max_len: algorithm not supported\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	return 0; /* Suppress compiler warning */
}

static TEE_Result check_rsa_bufs_len(TEE_OperationHandle operation, const EVP_MD *hash,
				     uint32_t dst_buf_len, uint32_t src_buf_len)
{
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if (RSA_size(RSA_key(operation)) != uint322int(dst_buf_len)) {
			OT_LOG(LOG_ERR, "check_rsa_bufs_len: Dest buf should be rsa mod size\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (src_buf_len > rsa_msg_max_len(operation, hash)) {
			OT_LOG(LOG_ERR, "check_rsa_bufs_len: Src buf too small\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (rsa_msg_max_len(operation, hash) > dst_buf_len) {
			OT_LOG(LOG_ERR, "check_rsa_bufs_len: Dest buf too small\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (RSA_size(RSA_key(operation)) != uint322int(src_buf_len)) {
			OT_LOG(LOG_ERR, "check_rsa_bufs_len: Src buf should be rsa mod size\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static void get_rsa_oaep_label(TEE_Attribute *params, uint32_t paramCount,
			       unsigned char *oaep_label, int *oaep_label_len)
{
	size_t i;

	if (params) {
		for (i = 0; i < paramCount; ++i) {
			if (params[i].attributeID == TEE_ATTR_RSA_OAEP_LABEL) {
				oaep_label = params[i].content.ref.buffer;
				*oaep_label_len = params[i].content.ref.length;
				break;
			}
		}
	}

	if (!oaep_label && *oaep_label_len > 0) {
		OT_LOG(LOG_ERR, "get_rsa_oaep_label: Label buffer NULL, but len > 0\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

static bool add_rsa_cipher_padding(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
				   void *destData, uint32_t *destLen, TEE_Attribute *params,
				   uint32_t paramCount, const EVP_MD *hash)
{
	unsigned char *oaep_label = NULL;
	int oaep_label_len = 0;

	if (operation->operation_info.algorithm == TEE_ALG_RSA_NOPAD ||
	    operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		memcpy(destData, srcData, srcLen);
		return true;
	}

	get_rsa_oaep_label(params, paramCount, oaep_label, &oaep_label_len);

	if (!beta_RSA_padding_add_PKCS1_OAEP_mgf1(destData, *destLen, srcData, srcLen, oaep_label,
						  oaep_label_len, hash, NULL)) {
		OT_LOG(LOG_ERR, "add_rsa_cipher_padding: Padding failure (openssl)\n");
		return false;
	}

	return true;
}

static bool remove_rsa_cipher_padding(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
				      void *destData, uint32_t *destLen, TEE_Attribute *params,
				      uint32_t paramCount, const EVP_MD *hash)
{
	/* LEADING ZERO !! cipher + 1, cipher len - 1 */
	unsigned char *oaep_label = NULL;
	int oaep_label_len = 0;

	if (operation->operation_info.algorithm == TEE_ALG_RSA_NOPAD ||
	    operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		memcpy(destData, srcData, srcLen);
		return true;
	}

	get_rsa_oaep_label(params, paramCount, oaep_label, &oaep_label_len);

	if (-1 == beta_RSA_padding_check_PKCS1_OAEP_mgf1(destData, *destLen,
						    (unsigned char *)srcData + 1, srcLen - 1,
						    RSA_size(RSA_key(operation)),
						    oaep_label, oaep_label_len, hash, NULL)) {
		OT_LOG(LOG_ERR, "remove_rsa_cipher_padding: Padding failure (openssl)\n");
		return false;
	}

	return true;
}

static TEE_Result rsa_op_generic_pre_checks_and_setup(TEE_OperationHandle operation,
						      const EVP_MD **hash, void *srcData,
						      uint32_t srcLen, void *destData,
						      uint32_t *destLen,
						      unsigned char **rsa_mod_len_buf,
						      uint32_t *rsa_mod_len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!operation || !srcData || !destData || !destLen) {
		OT_LOG(LOG_ERR, "rsa_op_generic_pre_checks_and_setup: Error with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "rsa_op_generic_pre_checks_and_setup: Not a asymetric op "
				"or not initializes or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Load rsa cipher function can not fail */
	*hash = load_evp_asym_hash(operation);

	ret = check_rsa_bufs_len(operation, *hash, *destLen, srcLen);
	if (ret != TEE_SUCCESS)
		return ret; /* Err msg has been written to log */

	*rsa_mod_len = RSA_size(RSA_key(operation));
	*rsa_mod_len_buf = TEE_Malloc(*rsa_mod_len, 0);
	if (!*rsa_mod_len_buf) {
		OT_LOG(LOG_ERR, "rsa_op_generic_pre_checks_and_setup: Out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	return ret;
}

/*   S I G N / V E R I F Y   f u n c t i o n s   */

static int get_rsa_salt(TEE_Attribute *params, uint32_t paramCount)
{
	size_t i;

	if (params) {
		for (i = 0; i < paramCount; ++i) {
			if (params[i].attributeID == TEE_ATTR_RSA_PSS_SALT_LENGTH)
				return params[i].content.value.a;
		}
	}
	return -1;
}

static uint32_t get_openssl_NID_value(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return NID_md5;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		return NID_sha1;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		return NID_sha224;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		return NID_sha256;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		return NID_sha384;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return NID_sha512;

	default:
		return 0;
	}
}

static TEE_Result rsa_sign_ver_generic_checks_and_setup(TEE_OperationHandle operation, void *digest,
							uint32_t dig_len, void *signature,
							uint32_t sig_len, TEE_Attribute *params,
							uint32_t paramCount, int *salt,
							unsigned char **rsa_mod_len_buf,
							uint32_t *rsa_mod_len, const EVP_MD **hash,
							uint32_t *NID_value)
{
	if (!digest || !signature) {
		OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks: Digest or Sig buf NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Load/intialize salt */
	*salt = get_rsa_salt(params, paramCount);

	/* Load hash */
	*hash = load_evp_asym_hash(operation);

	/* Openssl NID value */
	*NID_value = get_openssl_NID_value(operation->operation_info.algorithm);

	/* Digest should match to algorithm */
	if (dig_len != int2uint32(EVP_MD_size(*hash))) {
		OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: "
				"Digest len err (not equal to alg)\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Initialize RSA modulo variable */
	*rsa_mod_len = RSA_size(RSA_key(operation));

	/* Signature buffer correct len */
	if (sig_len < *rsa_mod_len) {
		OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: "
				"Signature buf too small\n");
		if (operation->operation_info.mode == TEE_MODE_SIGN)
			return TEE_ERROR_SHORT_BUFFER;
		else
			TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Digest is fitting to rsa signature */
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:

		if (dig_len > *rsa_mod_len - 11) {
			OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: "
					"Dig too big for RSA key\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:

		if (*salt == -1)
			*salt = EVP_MD_size(*hash);

		if (uint322int(*rsa_mod_len) < (EVP_MD_size(*hash) + *salt + 2)) {
			OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: "
					"Dig too big for RSA key\n");
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		}

		break;

	default:
		OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: "
				"Digest len err (not equal to alg)\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Malloc temp buffer */
	*rsa_mod_len_buf = TEE_Malloc(*rsa_mod_len, 0);
	if (!*rsa_mod_len_buf) {
		OT_LOG(LOG_ERR, "rsa_sign_ver_generic_checks_and_setup: Out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	return TEE_SUCCESS;
}

static bool add_rsa_signature_padding(TEE_OperationHandle operation, void *EM, void *mHash,
				      uint32_t mHash_len, const EVP_MD *hash, int salt)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		/* Padding will be added during the encrypt */
		memcpy(EM, mHash, mHash_len);
		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (!RSA_padding_add_PKCS1_PSS_mgf1(RSA_key(operation), EM, mHash, hash, NULL,
						    salt)) {
			OT_LOG(LOG_ERR, "add_rsa_signuture_padding: Padding failed\n");
			return false;
		}

		break;

	default:
		OT_LOG(LOG_ERR, "add_rsa_signuture_padding: Alg not supported\n");
		return false;
	}

	return true;
}

static TEE_Result rsa_sign(TEE_OperationHandle operation, TEE_Attribute *params,
			   uint32_t paramCount, void *digest, uint32_t digestLen, void *signature,
			   uint32_t *signatureLen)
{
	TEE_Result ret = TEE_SUCCESS;
	int salt = 0;
	int write_bytes;
	const EVP_MD *hash = NULL;
	unsigned char *rsa_mod_len_buf = NULL;
	uint32_t rsa_mod_len, NID_value;

	ret = rsa_sign_ver_generic_checks_and_setup(operation, digest, digestLen, signature,
						    *signatureLen, params, paramCount, &salt,
						    &rsa_mod_len_buf, &rsa_mod_len, &hash,
						    &NID_value);
	if (ret != TEE_SUCCESS)
		return ret; /* Err msg has been written to log */

	if (!add_rsa_signature_padding(operation, rsa_mod_len_buf, digest, digestLen, hash, salt))
		TEE_Panic(TEE_ERROR_GENERIC); /* Err msg has been written to log */

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		write_bytes = RSA_sign(NID_value, rsa_mod_len_buf, digestLen,
				       signature, signatureLen, RSA_key(operation));

		if (write_bytes == 0) {
			OT_LOG(LOG_ERR, "rsa signature failed\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		write_bytes = RSA_private_encrypt(rsa_mod_len, rsa_mod_len_buf, signature,
						  RSA_key(operation), RSA_NO_PADDING);

		if (write_bytes == -1) {
			OT_LOG(LOG_ERR, "rsa signature failed\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		*signatureLen = write_bytes;
		break;

	default:
		OT_LOG(LOG_ERR, "Not sup asym sig alg\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	free(rsa_mod_len_buf);
	return ret;
}

static TEE_Result rsa_ver(TEE_OperationHandle operation, TEE_Attribute *params, uint32_t paramCount,
			  void *digest, uint32_t digestLen, void *signature, uint32_t signatureLen)
{
	TEE_Result ret = TEE_SUCCESS;
	int salt = 0;
	const EVP_MD *hash = NULL;
	unsigned char *rsa_mod_len_buf = NULL;
	uint32_t rsa_mod_len, NID_value;;

	ret = rsa_sign_ver_generic_checks_and_setup(operation, digest, digestLen, signature,
						    signatureLen, params, paramCount, &salt,
						    &rsa_mod_len_buf, &rsa_mod_len, &hash,
						    &NID_value);
	if (ret != TEE_SUCCESS)
		return ret; /* Err msg has been written to log */

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:

		if (RSA_verify(NID_value, digest, digestLen,
			       signature, signatureLen, RSA_key(operation)) == 0)
			ret = TEE_ERROR_SIGNATURE_INVALID;

		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:

		if (RSA_public_decrypt(signatureLen, signature, rsa_mod_len_buf,
				       RSA_key(operation), RSA_NO_PADDING) == -1) {
			OT_LOG(LOG_ERR, "decrypting failed\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		if (!RSA_verify_PKCS1_PSS_mgf1(RSA_key(operation), digest,
					       hash, hash, rsa_mod_len_buf, salt))
			ret = TEE_ERROR_SIGNATURE_INVALID;

		break;

	default:
		OT_LOG(LOG_ERR, "Not sup asym ver alg\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	free(rsa_mod_len_buf);
	return ret;
}

static TEE_Result malloc_and_cpy_dsa_key(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	if (!operation || !key) {
		OT_LOG(LOG_ERR, "malloc_and_cpy_dsa_key: Operation or key NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!cpy_key_comp_to_bn(&DSA_key(operation)->p, TEE_ATTR_DSA_SUBPRIME, key) ||
	    !cpy_key_comp_to_bn(&DSA_key(operation)->g, TEE_ATTR_DSA_BASE, key) ||
	    !cpy_key_comp_to_bn(&DSA_key(operation)->pub_key, TEE_ATTR_DSA_PUBLIC_VALUE, key) ||
	    !cpy_key_comp_to_bn(&DSA_key(operation)->q, TEE_ATTR_DSA_PRIME, key)) {
		OT_LOG(LOG_ERR, "malloc_and_cpy_dsa_key: Provide all DSA components\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (key->objectInfo.objectType == TEE_TYPE_DSA_KEYPAIR &&
	    !cpy_key_comp_to_bn(&DSA_key(operation)->priv_key, TEE_ATTR_DSA_PRIVATE_VALUE, key)) {
		OT_LOG(LOG_ERR, "malloc_and_cpy_dsa_key: Provide DSA private component\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	return TEE_SUCCESS;
}

TEE_Result dsa_sign(TEE_OperationHandle operation, void *digest, uint32_t digestLen,
		    void *signature, uint32_t *signatureLen)
{
	unsigned int sig_len = *signatureLen;

	if (!digest || !signature) {
		OT_LOG(LOG_ERR, "dsa_sign: Digest or Sig buf NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (uint322int(*signatureLen) < DSA_size(DSA_key(operation))) {
		OT_LOG(LOG_ERR, "dsa_sign: DSA sig buf too small\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!DSA_sign(0, digest, digestLen, signature, &sig_len, DSA_key(operation))) {
		OT_LOG(LOG_ERR, "dsa_sign: DSA signing error\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*signatureLen = sig_len;
	return TEE_SUCCESS;
}

TEE_Result dsa_ver(TEE_OperationHandle operation, void *digest, uint32_t digestLen, void *signature,
		   uint32_t signatureLen)
{
	if (!digest || !signature) {
		OT_LOG(LOG_ERR, "dsa_ver: Digest or Sig buf NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (1 != DSA_verify(0, digest, digestLen, signature, signatureLen, DSA_key(operation))) {
		OT_LOG(LOG_ERR, "dsa_ver: DSA verify error\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	return TEE_SUCCESS;
}

static void dup_rsa_key(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (RSA_key(srcOperation)->d) {
		RSA_key(dstOperation)->d = BN_dup(RSA_key(srcOperation)->d);
		if (!RSA_key(dstOperation)->d)
			goto err;
	}

	if (RSA_key(srcOperation)->e) {
		RSA_key(dstOperation)->e = BN_dup(RSA_key(srcOperation)->e);
		if (!RSA_key(dstOperation)->e)
			goto err;
	}

	if (RSA_key(srcOperation)->n) {
		RSA_key(dstOperation)->n = BN_dup(RSA_key(srcOperation)->n);
		if (!RSA_key(dstOperation)->n)
			goto err;
	}

	if (RSA_key(srcOperation)->p) {
		RSA_key(dstOperation)->p = BN_dup(RSA_key(srcOperation)->p);
		if (!RSA_key(dstOperation)->p)
			goto err;
	}

	if (RSA_key(srcOperation)->q) {
		RSA_key(dstOperation)->q = BN_dup(RSA_key(srcOperation)->q);
		if (!RSA_key(dstOperation)->q)
			goto err;
	}

	if (RSA_key(srcOperation)->dmp1) {
		RSA_key(dstOperation)->dmp1 = BN_dup(RSA_key(srcOperation)->dmp1);
		if (!RSA_key(dstOperation)->dmp1)
			goto err;
	}

	if (RSA_key(srcOperation)->dmq1) {
		RSA_key(dstOperation)->dmq1 = BN_dup(RSA_key(srcOperation)->dmq1);
		if (!RSA_key(dstOperation)->dmq1)
			goto err;
	}

	if (RSA_key(srcOperation)->iqmp) {
		RSA_key(dstOperation)->iqmp = BN_dup(RSA_key(srcOperation)->iqmp);
		if (!RSA_key(dstOperation)->iqmp)
			goto err;
	}

	return;

err:
	OT_LOG(LOG_ERR, "dup_rsa_key: out of memory\n");
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
}

static void dup_dsa_key(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (DSA_key(srcOperation)->g) {
		DSA_key(dstOperation)->g = BN_dup(DSA_key(srcOperation)->g);
		if (!DSA_key(dstOperation)->g)
			goto err;
	}

	if (DSA_key(srcOperation)->p) {
		DSA_key(dstOperation)->p = BN_dup(DSA_key(srcOperation)->p);
		if (!DSA_key(dstOperation)->p)
			goto err;
	}

	if (DSA_key(srcOperation)->q) {
		DSA_key(dstOperation)->q = BN_dup(DSA_key(srcOperation)->q);
		if (!DSA_key(dstOperation)->q)
			goto err;
	}

	if (DSA_key(srcOperation)->pub_key) {
		DSA_key(dstOperation)->pub_key = BN_dup(DSA_key(srcOperation)->pub_key);
		if (!DSA_key(dstOperation)->pub_key)
			goto err;
	}

	if (DSA_key(srcOperation)->priv_key) {
		DSA_key(dstOperation)->priv_key = BN_dup(DSA_key(srcOperation)->priv_key);
		if (!DSA_key(dstOperation)->priv_key)
			goto err;
	}

	return;

err:
	OT_LOG(LOG_ERR, "dup_dsa_key: out of memory\n");
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
}

/*********************************************************************************************
 *											     *
 * D E R I V E   f u n c t i o n s						             *
 * 											     *
 *********************************************************************************************/

static TEE_Result malloc_and_cpy_dh_key(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	if (!operation || !key) {
		OT_LOG(LOG_ERR, "malloc_and_cpy_dsa_key: Operation or key NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!cpy_key_comp_to_bn(&DH_key(operation)->p, TEE_ATTR_DH_PRIME, key) ||
	    !cpy_key_comp_to_bn(&DH_key(operation)->g, TEE_ATTR_DH_BASE, key) ||
	    !cpy_key_comp_to_bn(&DH_key(operation)->pub_key, TEE_ATTR_DH_PUBLIC_VALUE, key) ||
	    !cpy_key_comp_to_bn(&DH_key(operation)->priv_key, TEE_ATTR_DH_PRIVATE_VALUE, key)) {
		OT_LOG(LOG_ERR, "malloc_and_cpy_dh_key: Provide all DH components\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	return TEE_SUCCESS;
}

static TEE_Attribute *get_dh_pub_val(TEE_Attribute *params, uint32_t paramCount)
{
	size_t i;

	for (i = 0; i < paramCount; ++i) {
		if (params[i].attributeID == TEE_ATTR_DH_PUBLIC_VALUE)
			return &params[i];
	}

	return NULL;
}

static void dup_dh_key(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (DH_key(srcOperation)->p) {
		DH_key(dstOperation)->p = BN_dup(DH_key(srcOperation)->p);
		if (!DH_key(dstOperation)->p)
			goto err;
	}

	if (DH_key(srcOperation)->g) {
		DH_key(dstOperation)->g = BN_dup(DH_key(srcOperation)->g);
		if (!DH_key(dstOperation)->g)
			goto err;
	}

	if (DH_key(srcOperation)->priv_key) {
		DH_key(dstOperation)->priv_key = BN_dup(DH_key(srcOperation)->priv_key);
		if (!DH_key(dstOperation)->priv_key)
			goto err;
	}

	if (DH_key(srcOperation)->pub_key) {
		DH_key(dstOperation)->pub_key = BN_dup(DH_key(srcOperation)->pub_key);
		if (!DH_key(dstOperation)->pub_key)
			goto err;
	}

	return;

err:
	OT_LOG(LOG_ERR, "dup_dh_key: out of memory\n");
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
}

/*********************************************************************************************
 *											     *
 * M A C   f u n c t i o n s							             *
 * 											     *
 *********************************************************************************************/

static const EVP_CIPHER *load_evp_mac_cipher(TEE_OperationHandle operation)
{
	uint32_t algorithm = operation->operation_info.algorithm;
	uint32_t key_size = operation->operation_info.keySize;

	switch (algorithm) {
	case TEE_ALG_AES_CMAC:
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
	default:
		OT_LOG(LOG_ERR, "load_evp_mac_cipher: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return NULL; /* Suppress compiler warning */
}

static const EVP_MD *load_evp_mac_hash(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_HMAC_MD5:
		return EVP_md5();

	case TEE_ALG_HMAC_SHA1:
		return EVP_sha1();

	case TEE_ALG_HMAC_SHA224:
		return EVP_sha224();

	case TEE_ALG_HMAC_SHA256:
		return EVP_sha256();

	case TEE_ALG_HMAC_SHA384:
		return EVP_sha384();

	case TEE_ALG_HMAC_SHA512:
		return EVP_sha512();

	default:
		OT_LOG(LOG_ERR, "load_mac_hash_or_cipher: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return NULL; /* Suppress compiler warning */
}
static int max_mac_len(TEE_OperationHandle operation)
{
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

	case TEE_ALG_AES_CMAC:
		if (operation->operation_info.keySize == 128)
			return EVP_CIPHER_block_size(load_evp_mac_cipher(operation));

		if (operation->operation_info.keySize == 192)
			return EVP_CIPHER_block_size(load_evp_mac_cipher(operation));

		if (operation->operation_info.keySize == 256)
			return EVP_CIPHER_block_size(load_evp_mac_cipher(operation));

		OT_LOG(LOG_ERR, "max_mac_len: No sup CMAC key\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		return EVP_MD_size(load_evp_mac_hash(operation));

	default:
		OT_LOG(LOG_ERR, "max_mac_len: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return 0; /* Suppress compiler warning */
}

/*********************************************************************************************
 *											     *
 * G E N E R A L   f u n c t i o n s						             *
 * 											     *
 *********************************************************************************************/

static TEE_Result init_operation_meta_info(TEE_OperationHandle operation, uint32_t algorithm)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		operation->key.ctx = (HMAC_CTX *)TEE_Malloc(sizeof(HMAC_CTX), 0);
		if (!HMAC_ctx(operation)) {
			OT_LOG(LOG_ERR, "TEE_MACInit: Hmac ctx out of memory\n");
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
		}

		break;

	case TEE_ALG_AES_CMAC:
		operation->key.ctx = CMAC_CTX_new();
		if (!CMAC_ctx(operation)) {
			OT_LOG(LOG_ERR, "TEE_MACInit: CMAC ctx out of memory\n");
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
		}

		break;

	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;

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
		operation->key.ctx = (EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new();
		if (!SYM_ctx(operation)) {
			OT_LOG(LOG_ERR, "Init key meta: Sym ctx malloc (openssl failure)\n");
			ret = TEE_ERROR_OUT_OF_MEMORY;
		}

		break;

	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		ret = init_digest_op(operation, algorithm);
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
		operation->key.key = (RSA *)RSA_new();
		if (!RSA_key(operation)) {
			OT_LOG(LOG_ERR, "Init key meta: RSA malloc (openssl failure)\n");
			ret = TEE_ERROR_OUT_OF_MEMORY;
		}
		/* Special: Asymmetric function do not have INIT -function */
		operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;

		break;

	case TEE_ALG_DSA_SHA1:
		operation->key.key = (DSA *)DSA_new();
		if (!DSA_key(operation)) {
			OT_LOG(LOG_ERR, "Init key meta: DSA malloc (openssl failure)\n");
			ret = TEE_ERROR_OUT_OF_MEMORY;
		}
		/* Special: Asymmetric function do not have INIT -function */
		operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;

		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		operation->key.key = (DH *)DH_new();
		if (!DH_key(operation)) {
			OT_LOG(LOG_ERR, "Init key meta: DH malloc (openssl failure)\n");
			ret = TEE_ERROR_OUT_OF_MEMORY;
		}
		/* Special: Derive do not have INIT -function */
		operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;

		break;

	default:
		OT_LOG(LOG_ERR, "Init key meta: Something very wrong\n");
		ret = TEE_ERROR_NOT_SUPPORTED;
	}

	return ret;
}

static void clear_key_from_operation(TEE_OperationHandle operation)
{
	/* Clear old key and ctx */
	free_key_and_ctx(operation);

	operation->op_state = TEE_OP_STATE_INITIAL;
	operation->operation_info.handleState = 0;

	/* Init new ctx */
	if (TEE_SUCCESS !=
	    init_operation_meta_info(operation, operation->operation_info.algorithm)) {
		OT_LOG(LOG_ERR, "clear_key_from_operation: Operation meta initiation fail\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}

/*************************************************************************************************
*												 *
*												 *
*												 *
*												 *
* ############################################################################################## *
* #											       # *
* #  ----------------------------------------------------------------------------------------  # *
* #  |										            |  # *
* #  | #    #   #  # ## I n t e r n a l   A P I   f u n c t i o n s ## #  #   #    #     #  |  # *
* #  |										            |  # *
* #  ----------------------------------------------------------------------------------------  # *
* #											       # *
* ############################################################################################## *
*												 *
*												 *
*												 *
*												 *
*************************************************************************************************/

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation, uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize)
{
	/* NOTICE: This func should Alloc all resources here, but now it is divited this func and
	 * setOperationKey -func. This function alloc and init structures that is needed for op
	 * execution e.g. EVP contexts structures. Mallocing for actual key components takes place
	 * at setOpKey -func */

	TEE_OperationHandle tmp_handle = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!valid_mode_and_algorithm(algorithm, mode)) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation: Not a valid mode,"
				"algorithm or mode for algorithm\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!valid_key_size_for_algorithm(algorithm, maxKeySize)) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation: Not a valid key size for algorithm\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!supported_algorithms(algorithm, maxKeySize)) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation: Algorithm not (yet) implemented\n");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	tmp_handle = TEE_Malloc(sizeof(struct __TEE_OperationHandle), 0);
	if (!tmp_handle) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation: Out of memory (operation handler)\n");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	/* Function malloc space only for keys meta data for example openssl structs and
	 * not for the actual key components! */
	ret = init_operation_meta_info(tmp_handle, algorithm);
	if (ret != TEE_SUCCESS)
		goto error; /* error message has been logged */

	/* Generic info about operation. Filled out only neccessary fields. */
	tmp_handle->operation_info.operationClass = get_operation_class(algorithm);
	tmp_handle->operation_info.mode = mode;
	tmp_handle->operation_info.algorithm = algorithm;
	tmp_handle->operation_info.maxKeySize = maxKeySize;
	tmp_handle->operation_info.keySize = 0;
	if (alg_requires_2_keys(algorithm))
		tmp_handle->operation_info.handleState |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

	tmp_handle->op_state = TEE_OP_STATE_INITIAL;

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
	free_key_and_ctx(operation);

	/* Free digest */
	if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST)
		EVP_MD_CTX_destroy(DIGEST_CTX(operation));

	/* Free operation handle */
	rand_buf(operation, sizeof(struct __TEE_OperationHandle));
	TEE_Free(operation);
	operation = NULL;
}

void TEE_GetOperationInfo(TEE_OperationHandle operation, TEE_OperationInfo *operationInfo)
{
	if (!operation || !operationInfo) {
		OT_LOG(LOG_ERR, "TEE_GetOperationInfo: Problem with parameters\n");
		return;
	}

	memcpy(operationInfo, &operation->operation_info, sizeof(TEE_OperationInfo));
}

TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
					TEE_OperationInfoMultiple *operationInfoMultiple,
					uint32_t *operationSize)
{
	if (!operation || !operationInfoMultiple || !operationSize) {
		OT_LOG(LOG_ERR, "TEE_GetOperationInfoMultiple: Problem with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Mutual info from operationInfo-struct */
	operationInfoMultiple->algorithm = operation->operation_info.algorithm;
	operationInfoMultiple->digestLength = operation->operation_info.digestLength;
	operationInfoMultiple->handleState = operation->operation_info.handleState;
	operationInfoMultiple->maxKeySize = operation->operation_info.maxKeySize;
	operationInfoMultiple->mode = operation->operation_info.mode;
	operationInfoMultiple->operationClass = operation->operation_info.operationClass;

	/* Multi info fields */
	operationInfoMultiple->operationState = operation->op_state;

	/* Fill key info struct */
	if (operation->operation_info.mode == TEE_OPERATION_DIGEST) {
		operationInfoMultiple->numberOfKeys = 0;
	} else {
		operationInfoMultiple->numberOfKeys = 1;
		operationInfoMultiple->keyInformation[0].keySize =
		    operation->operation_info.keySize;

		if (alg_requires_2_keys(operation->operation_info.algorithm)) {
			operationInfoMultiple->numberOfKeys = 2;
			operationInfoMultiple->keyInformation[1].keySize = operation->key_size2;
		}
	}

	/* operationSize: What is this? */
	*operationSize = 0;

	return TEE_SUCCESS;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	if (!operation || !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_ResetOperation: Operation NULL or key not set\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	/* Clear crypto specific state */
	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {

		/* Clear operation state */
		operation->operation_info.handleState ^= TEE_HANDLE_FLAG_INITIALIZED;
		operation->op_state = TEE_OP_STATE_INITIAL;

		/* Not optimized. Quick and works (perspective of implementing) */
		EVP_CIPHER_CTX_cleanup(operation->key.ctx);
		EVP_CIPHER_CTX_free(operation->key.ctx);
		operation->key.ctx = (EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new();
		if (!SYM_ctx(operation)) {
			OT_LOG(LOG_ERR, "TEE_ResetOperation: Sym ctx malloc (openssl failure)\n");
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
		}

	} else if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST) {

		EVP_MD_CTX_destroy(DIGEST_CTX(operation)); /* No documented return value */
		if (TEE_SUCCESS != init_digest_op(operation, operation->operation_info.algorithm)) {
			OT_LOG(LOG_ERR, "TEE_ResetOperation: Reseting digest op\n");
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}

	} else if (operation->operation_info.operationClass == TEE_OPERATION_MAC) {

		/* Clear operation state */
		operation->operation_info.handleState ^= TEE_HANDLE_FLAG_INITIALIZED;
		operation->op_state = TEE_OP_STATE_INITIAL;

		switch (operation->operation_info.algorithm) {
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

		case TEE_ALG_AES_CMAC:
			CMAC_CTX_cleanup(CMAC_ctx(operation));
			break;

		case TEE_ALG_HMAC_MD5:
		case TEE_ALG_HMAC_SHA1:
		case TEE_ALG_HMAC_SHA224:
		case TEE_ALG_HMAC_SHA256:
		case TEE_ALG_HMAC_SHA384:
		case TEE_ALG_HMAC_SHA512:
			HMAC_CTX_cleanup(HMAC_ctx(operation));
			break;

		default:
			OT_LOG(LOG_ERR, "TEE_ResetOperation: Mac alg is not sup\n");
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}

	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER) {

		/* Only for documenting purpose. This is single stage operation */

	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE) {

		/* Only for documenting purpose. This is single stage operation */

	} else if (operation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {

		/* Only for documenting purpose. This is single stage operation */

	} else {
		OT_LOG(LOG_ERR, "TEE_ResetOperation: Operation not sup\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation, TEE_ObjectHandle key)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!operation || operation->op_state == TEE_OP_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey: Operation NULL or active state\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	/* If key NULL, clear key from operation. */
	if (!key) {
		clear_key_from_operation(operation);
		goto retu;
	}

	if (operation->operation_info.algorithm == TEE_ALG_AES_XTS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey: Operation expecting two keys\n");
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}

	ret = valid_key_and_operation(key, operation);
	if (ret != TEE_SUCCESS)
		goto err;

	/* Malloc space and cpy key(s) */
	switch (operation->operation_info.algorithm) {
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
		ret = malloc_and_cpy_symmetric_key(operation, key);
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
		ret = malloc_and_cpy_rsa_key(operation, key);
		break;

	case TEE_ALG_DSA_SHA1:
		ret = malloc_and_cpy_dsa_key(operation, key);
		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		ret = malloc_and_cpy_dh_key(operation, key);
		break;

	default:
		OT_LOG(LOG_ERR, "Set op key: Algorithm not supported\n");
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	operation->operation_info.keySize =
	    get_actual_key_size(key->objectInfo.objectType, key->objectInfo.maxObjectSize);

retu:
	return ret;

err:
	/* Error has been written to OT_LOG */
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

	if (!key1 && !key2) {
		clear_key_from_operation(operation);
		goto retu;
	}

	if (!operation || !key1 || !key2) {
		OT_LOG(LOG_ERR, "Set op key2: Parameters problem\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (operation->operation_info.algorithm != TEE_ALG_AES_XTS) {
		OT_LOG(LOG_ERR, "Set op key2: Operation NOT expecting two keys\n");
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
		OT_LOG(LOG_ERR, "Set op key2: Key1 does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	sym_key2 = get_attr_by_ID(key2, TEE_ATTR_SECRET_VALUE);
	if (!sym_key2) {
		OT_LOG(LOG_ERR, "Set op key2: Key2 does not contain symmetric key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	/* Calculate key length and malloc space for key */
	operation->key.key_len = sym_key1->content.ref.length + sym_key2->content.ref.length;

	operation->key.key = TEE_Malloc(operation->key.key_len, 0);
	if (!operation->key.key) {
		OT_LOG(LOG_ERR, "Set op key2: Cannot malloc space for AES XTS symmetric key\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	/* Hardcoded openssl solution! For AES XTS openssl requires twice as long key. So for
	 * example at aes128xts case key size would be 256. Tweak is provited with IV parameter */
	memcpy(operation->key.key, sym_key1->content.ref.buffer, sym_key1->content.ref.length);
	memcpy((unsigned char *)operation->key.key + sym_key1->content.ref.length,
	       sym_key2->content.ref.buffer, sym_key2->content.ref.length);

	operation->operation_info.keySize = sym_key1->content.ref.length * 8;
	operation->key_size2 = sym_key2->content.ref.length;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

retu:
	return ret;

err:
	/* Error has been written to OT_LOG */
	TEE_Panic(ret);
	return 0; /* return for compiler */
}

void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (!dstOperation || !srcOperation) {
		OT_LOG(LOG_ERR, "TEE_CopyOperation: bad parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (dstOperation->operation_info.mode != srcOperation->operation_info.mode) {
		OT_LOG(LOG_ERR, "TEE_CopyOperation: modes\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (dstOperation->operation_info.algorithm != srcOperation->operation_info.algorithm) {
		OT_LOG(LOG_ERR, "TEE_CopyOperation: algorithms\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (srcOperation->operation_info.operationClass != TEE_OPERATION_DIGEST &&
	    srcOperation->operation_info.maxKeySize > dstOperation->operation_info.maxKeySize) {
		OT_LOG(LOG_ERR, "TEE_CopyOperation: key size\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!(srcOperation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		clear_key_from_operation(dstOperation);
		return;
	}

	/* Copy crypto specific state */
	if (srcOperation->operation_info.operationClass == TEE_OPERATION_CIPHER) {

		/* cpy key */
		memcpy(dstOperation->key.key, srcOperation->key.key, srcOperation->key.key_len);
		dstOperation->key.key_len = srcOperation->key.key_len;

		if (srcOperation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)
			TEE_CipherInit(dstOperation, srcOperation->key.IV,
				       srcOperation->key.IV_len);

	} else if (srcOperation->operation_info.operationClass == TEE_OPERATION_DIGEST) {

		if (EVP_MD_CTX_copy_ex(dstOperation->dig_ctx, srcOperation->dig_ctx) != 1) {
			OT_LOG(LOG_ERR, "TEE_CopyOperation: ctx dup (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else if (srcOperation->operation_info.operationClass == TEE_OPERATION_MAC) {

		/* cpy key */
		memcpy(dstOperation->key.key, srcOperation->key.key, srcOperation->key.key_len);
		dstOperation->key.key_len = srcOperation->key.key_len;

		if (srcOperation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
			switch (srcOperation->operation_info.algorithm) {
			case TEE_ALG_DES_CBC_MAC_NOPAD:
			case TEE_ALG_AES_CBC_MAC_NOPAD:
			case TEE_ALG_AES_CBC_MAC_PKCS5:
			case TEE_ALG_DES_CBC_MAC_PKCS5:
			case TEE_ALG_DES3_CBC_MAC_NOPAD:
			case TEE_ALG_DES3_CBC_MAC_PKCS5:
				TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);

			case TEE_ALG_AES_CMAC:
				if (!CMAC_CTX_copy(dstOperation->key.ctx, srcOperation->key.ctx)) {
					OT_LOG(LOG_ERR, "TEE_CopyOperation: CMAC copy error\n");
					TEE_Panic(TEE_ERROR_GENERIC);
				}

				break;

			case TEE_ALG_HMAC_MD5:
			case TEE_ALG_HMAC_SHA1:
			case TEE_ALG_HMAC_SHA224:
			case TEE_ALG_HMAC_SHA256:
			case TEE_ALG_HMAC_SHA384:
			case TEE_ALG_HMAC_SHA512:
				if (!HMAC_CTX_copy(dstOperation->key.ctx, srcOperation->key.ctx)) {
					OT_LOG(LOG_ERR, "TEE_CopyOperation: HMAC copy error\n");
					TEE_Panic(TEE_ERROR_GENERIC);
				}

				break;

			default:
				OT_LOG(LOG_ERR, "TEE_CopyOperation: Alg not supported\n");
				TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
			}
		}

	} else if (srcOperation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER) {

		dup_rsa_key(dstOperation, srcOperation);

	} else if (srcOperation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE) {

		if (srcOperation->operation_info.algorithm == TEE_ALG_DSA_SHA1)
			dup_dsa_key(dstOperation, srcOperation);
		else
			dup_rsa_key(dstOperation, srcOperation);

	} else if (srcOperation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {

		dup_dh_key(dstOperation, srcOperation);

	} else {
		OT_LOG(LOG_ERR, "TEE_CopyOperation: Operation not sup\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	/* Operation state that needs to be copied */
	dstOperation->op_state = srcOperation->op_state;
	dstOperation->key_size2 = srcOperation->key_size2;
	dstOperation->operation_info.handleState = srcOperation->operation_info.handleState;
	dstOperation->operation_info.keySize = srcOperation->operation_info.keySize;
	dstOperation->operation_info.requiredKeyUsage =
	    srcOperation->operation_info.requiredKeyUsage;
}

void TEE_DigestUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize)
{
	if (!operation || !chunk) {
		OT_LOG(LOG_ERR, "Digest update: Problem with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!DIGEST_CTX(operation) ||
	    operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Digest update: Operation state\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (EVP_DigestUpdate(DIGEST_CTX(operation), chunk, chunkSize) != 1) {
		OT_LOG(LOG_ERR, "Digest update: Update problem (openssl failure)\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	operation->op_state = TEE_OP_STATE_ACTIVE;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, void *chunk, uint32_t chunkLen,
			     void *hash, uint32_t *hashLen)
{
	unsigned int int_hashLen;

	if (!operation || !hash || !hashLen) {
		OT_LOG(LOG_ERR, "Digest final: Problem with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!DIGEST_CTX(operation) ||
	    operation->operation_info.operationClass != TEE_OPERATION_DIGEST ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG(LOG_ERR, "Digest final: Operation state\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (operation->operation_info.digestLength > *hashLen) {
		OT_LOG(LOG_ERR, "Digest final: Hash buffer too small\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	int_hashLen = uint322int(*hashLen);

	/* Handle digest data */
	if (chunkLen > 0)
		TEE_DigestUpdate(operation, chunk, chunkLen);

	/* Finalize and return hash */
	if (EVP_DigestFinal_ex(DIGEST_CTX(operation), hash, &int_hashLen) != 1) {
		OT_LOG(LOG_ERR, "Digest final: Update problem (openssl failure)\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	*hashLen = int2uint32(int_hashLen);

	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}

void TEE_CipherInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
	const EVP_CIPHER *cipher = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!operation) {
		OT_LOG(LOG_ERR, "TEE_CipherInit: Error at parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR,
		       "TEE_CipherInit: Not a cipher operation or initialized or no key\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (!SYM_ctx(operation)) {
		OT_LOG(LOG_ERR, "TEE_CipherInit: EVP ctx is NULL\n");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	if (operation->op_state == TEE_OP_STATE_ACTIVE) {
		/* operation is active -> reset */
		TEE_ResetOperation(operation);
	}

	cipher = load_evp_sym_cipher(operation);
	if (!cipher) {
		OT_LOG(LOG_ERR, "TEE_CipherInit: Algorithm is not supported\n");
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	/* EVP logic: return 1 for success and 0 for failure. */
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if (EVP_EncryptInit_ex(SYM_ctx(operation), cipher, NULL, NULL, NULL) == 0) {
			OT_LOG(LOG_ERR, "TEE_CipherInit: Enc operation init (openssl failure)\n");
			ret = TEE_ERROR_GENERIC;
			goto err;
		}

		/* If IV is set (malloc), init is called from reset function and
		 * in this case checks has been performed */
		if (!operation->key.IV)
			check_IV_and_malloc_cpy2op(operation, IV, IVLen);

		if (EVP_EncryptInit_ex(SYM_ctx(operation),
				       NULL, NULL, SYM_key(operation), IV) == 0) {
			OT_LOG(LOG_ERR, "TEE_CipherInit: Enc operation init (openssl failure)\n");
			ret = TEE_ERROR_GENERIC;
			goto err;
		}

	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (EVP_DecryptInit_ex(SYM_ctx(operation), cipher, NULL, NULL, NULL) == 0) {
			OT_LOG(LOG_ERR, "TEE_CipherInit: Dec operation init (openssl failure)\n");
			ret = TEE_ERROR_GENERIC;
			goto err;
		}

		/* If IV is set (malloc), init is called from reset function and
		 * in this case checks has been performed */
		if (!operation->key.IV)
			check_IV_and_malloc_cpy2op(operation, IV, IVLen);

		if (EVP_DecryptInit_ex(SYM_ctx(operation),
				       NULL, NULL, SYM_key(operation), IV) == 0) {
			OT_LOG(LOG_ERR, "TEE_CipherInit: Dec operation init (openssl failure)\n");
			ret = TEE_ERROR_GENERIC;
			goto err;
		}

	} else {
		/* Should never end up here! */
		OT_LOG(LOG_ERR, "TEE_CipherInit: Something is wrong with TEE_CipherInit\n");
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	set_symmetric_padding(operation->operation_info.algorithm, SYM_ctx(operation));
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	operation->op_state = TEE_OP_STATE_ACTIVE;

	return;

err:
	/* error msg has logged */
	TEE_Panic(ret);
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			    void *destData, uint32_t *destLen)
{
	int int_destLen;

	if (!operation || !srcData || !destData || !destLen) {
		OT_LOG(LOG_ERR, "Cipher update: Error with cipher update parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    operation->op_state != TEE_OP_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "Cipher update: Not a cipher op or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	int_destLen = uint322int(*destLen); /* EVP operates with int */

	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if (srcLen > *destLen) {
			OT_LOG(LOG_ERR, "Cipher update: Cipher buffer too small\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (EVP_EncryptUpdate(SYM_ctx(operation), destData, &int_destLen, srcData,
				      uint322int(srcLen)) == 0) {
			OT_LOG(LOG_ERR, "Cipher update: Enc operation failed (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (srcLen > *destLen + EVP_CIPHER_CTX_block_size(operation->key.ctx)) {
			OT_LOG(LOG_ERR, "Cipher update: Plain buffer too small\n");
			return TEE_ERROR_SHORT_BUFFER;
		}

		if (EVP_DecryptUpdate(SYM_ctx(operation), destData, &int_destLen, srcData,
				      uint322int(srcLen)) == 0) {
			OT_LOG(LOG_ERR, "Cipher update: Dec operation failed (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else {
		/* Should never end up here! */
		OT_LOG(LOG_ERR, "Cipher update: Something is wrong with cipher update\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	*destLen = int2uint32(int_destLen);

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			     void *destData, uint32_t *destLen)
{
	int int_destLen = 0;
	int total_int_destLen = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!destData || !operation || !destLen) {
		OT_LOG(LOG_ERR, "Cipher final: Error with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
	    operation->op_state != TEE_OP_STATE_ACTIVE) {
		OT_LOG(LOG_ERR, "Cipher final: Not a cipher op or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	int_destLen = uint322int(*destLen); /* EVP operates with int */

	/* Handle last src data */
	if (srcLen > 0) {

		ret = TEE_CipherUpdate(operation, srcData, srcLen, destData, destLen);
		if (ret != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "Cipher final: src data problem\n");
			return ret;
		}

		total_int_destLen += *destLen;
		int_destLen -= *destLen;
	}

	/* Do final */
	if (operation->operation_info.mode == TEE_MODE_ENCRYPT) {

		if (EVP_EncryptFinal_ex(SYM_ctx(operation),
					(unsigned char *)destData + total_int_destLen,
					&int_destLen) == 0) {
			OT_LOG(LOG_ERR, "Cipher final: Enc operation failed (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else if (operation->operation_info.mode == TEE_MODE_DECRYPT) {

		if (EVP_DecryptFinal_ex(SYM_ctx(operation),
					(unsigned char *)destData + total_int_destLen,
					&int_destLen) == 0) {
			OT_LOG(LOG_ERR, "Cipher final: Dec operation failed (openssl failure)\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

	} else {
		/* Should never end up here! */
		OT_LOG(LOG_ERR, "Cipher final: Something is wrong with cipher do final\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	total_int_destLen += int_destLen;
	*destLen = int2uint32(total_int_destLen);

	TEE_ResetOperation(operation);
	return ret;
}

void TEE_MACInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen)
{
	IV = IV;
	IVLen = IVLen;

	if (!operation) {
		OT_LOG(LOG_ERR, "TEE_MACInit: Operation NULL\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_MACInit: Not a mac operation or initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	if (operation->op_state == TEE_OP_STATE_ACTIVE)
		TEE_ResetOperation(operation);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

	case TEE_ALG_AES_CMAC:

		if (!CMAC_Init(CMAC_ctx(operation), SYM_key(operation), SYM_key_len(operation),
			       load_evp_mac_cipher(operation), NULL)) {
			OT_LOG(LOG_ERR, "TEE_MACInit: CMAC init fail\n");
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}

		break;

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:

		HMAC_CTX_init(HMAC_ctx(operation));
		if (!HMAC_Init_ex(HMAC_ctx(operation), SYM_key(operation), SYM_key_len(operation),
				  load_evp_mac_hash(operation), NULL)) {
			OT_LOG(LOG_ERR, "TEE_MACInit: HMAC init fail\n");
			TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
		}

		break;

	default:
		OT_LOG(LOG_ERR, "TEE_MACInit: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	/* Common functionality */
	operation->op_state = TEE_OP_STATE_ACTIVE;
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
}

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize)
{
	if (!operation || !chunk) {
		OT_LOG(LOG_ERR, "TEE_MACUpdate: Operation or chunk null\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->op_state != TEE_OP_STATE_ACTIVE ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_MACUpdate: Not a mac operation or "
				"not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

	case TEE_ALG_AES_CMAC:
		if (!CMAC_Update(CMAC_ctx(operation), chunk, chunkSize)) {
			OT_LOG(LOG_ERR, "TEE_MACUpdate: CMAC update error\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}

		break;

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		HMAC_Update(HMAC_ctx(operation), chunk, chunkSize);
		break;

	default:
		OT_LOG(LOG_ERR, "TEE_MACUpdate: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation, void *message, uint32_t messageLen,
			       void *mac, uint32_t *macLen)
{
	size_t cmac_len_out;

	if (!operation || !macLen) {
		OT_LOG(LOG_ERR, "TEE_MACComputeFinal: Operation or MacLen is null\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_MAC ||
	    operation->op_state != TEE_OP_STATE_ACTIVE ||
	    operation->operation_info.mode != TEE_MODE_MAC ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_MACComputeFinal: Not a mac operation or "
				"not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	/* Handle last data */
	if (message)
		TEE_MACUpdate(operation, message, messageLen);

	/* Do final and get mac */
	if (int2uint32(max_mac_len(operation)) > *macLen) {
		OT_LOG(LOG_ERR, "mac_final: MAC buf too small\n");
		return TEE_ERROR_SHORT_BUFFER;
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);

	case TEE_ALG_AES_CMAC:
		cmac_len_out = *macLen;
		if (!CMAC_Final(CMAC_ctx(operation), mac, &cmac_len_out)) {
			OT_LOG(LOG_ERR, "mac_final: CMAC final failed\n");
			TEE_Panic(TEE_ERROR_GENERIC);
		}
		*macLen = cmac_len_out;
		break;

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		HMAC_Final(HMAC_ctx(operation), mac, macLen);
		break;

	default:
		OT_LOG(LOG_ERR, "TEE_MACComputeFinal: Alg not supported\n");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	TEE_ResetOperation(operation);

	return TEE_SUCCESS;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, void *message, uint32_t messageLen,
			       void *mac, uint32_t macLen)
{
	void *comp_mac = NULL;
	uint32_t comp_mac_len;
	TEE_Result ret = TEE_SUCCESS;

	if (!operation) {
		OT_LOG(LOG_ERR, "TEE_MACCompareFinal: Operation is null\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	comp_mac_len = max_mac_len(operation);
	comp_mac = TEE_Malloc(comp_mac_len, 0);
	if (!comp_mac) {
		OT_LOG(LOG_ERR, "TEE_MACCompareFinal: Out of memory\n");
		TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
	}

	ret = TEE_MACComputeFinal(operation, message, messageLen, comp_mac, &comp_mac_len);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_MACCompareFinal: Something went wrong\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	if (CRYPTO_memcmp(mac, comp_mac, macLen) != 0) {
		OT_LOG(LOG_ERR, "TEE_MACCompareFinal: MACs do not match\n");
		ret = TEE_ERROR_MAC_INVALID;
	}

	TEE_ResetOperation(operation);

	/* Rand and free mac buf */
	rand_buf(comp_mac, comp_mac_len);
	TEE_Free(comp_mac);

	return ret;
}

/* GP TEE AE API is not supported */
TEE_Result TEE_AEInit(TEE_OperationHandle operation, void *nonce, uint32_t nonceLen,
		      uint32_t tagLen, uint32_t AADLen, uint32_t payloadLen)
{
	operation = operation;
	nonce = nonce;
	nonceLen = nonceLen;
	tagLen = tagLen;
	AADLen = AADLen;
	payloadLen = payloadLen;

	return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation, void *AADdata, uint32_t AADdataLen)
{
	operation = operation;
	AADdata = AADdata;
	AADdataLen = AADdataLen;
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			void *destData, uint32_t *destLen)
{
	operation = operation;
	srcData = srcData;
	srcLen = srcLen;
	destData = destData;
	destLen = destLen;

	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag, uint32_t *tagLen)
{
	operation = operation;
	srcData = srcData;
	srcLen = srcLen;
	destData = destData;
	destLen = destLen;
	tag = tag;
	tagLen = tagLen;

	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag, uint32_t tagLen)
{
	operation = operation;
	srcData = srcData;
	srcLen = srcLen;
	destData = destData;
	destLen = destLen;
	tag = tag;
	tagLen = tagLen;

	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation, TEE_Attribute *params,
				 uint32_t paramCount, void *srcData, uint32_t srcLen,
				 void *destData, uint32_t *destLen)
{
	TEE_Result ret = TEE_SUCCESS;
	const EVP_MD *hash = NULL;
	int write_bytes = 0;
	unsigned char *rsa_mod_len_buf = NULL;
	uint32_t rsa_mod_len;

	if (!operation || operation->operation_info.mode != TEE_MODE_ENCRYPT) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt: Not a valid operationhandler "
				"or wrong operation mode\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	ret = rsa_op_generic_pre_checks_and_setup(operation, &hash, srcData, srcLen, destData,
						  destLen, &rsa_mod_len_buf, &rsa_mod_len);
	if (ret != TEE_SUCCESS)
		return ret; /* Err msg has been written to log */

	/* Add padding, if needed */
	if (!add_rsa_cipher_padding(operation, srcData, srcLen, rsa_mod_len_buf, &rsa_mod_len,
				    params, paramCount, hash))
		TEE_Panic(TEE_ERROR_GENERIC); /* Err msg has been written to log */

	/* Encryption */
	if (operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		write_bytes = RSA_public_encrypt(srcLen, srcData, destData, RSA_key(operation),
						 RSA_PKCS1_PADDING);
	} else {
		write_bytes = RSA_public_encrypt(rsa_mod_len, rsa_mod_len_buf, destData,
						 RSA_key(operation), RSA_NO_PADDING);
	}

	if (write_bytes == -1) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt: Encryption failed (openssl failure)\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	*destLen = int2uint32(write_bytes);
	free(rsa_mod_len_buf);
	return ret;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation, TEE_Attribute *params,
				 uint32_t paramCount, void *srcData, uint32_t srcLen,
				 void *destData, uint32_t *destLen)
{
	TEE_Result ret = TEE_SUCCESS;
	const EVP_MD *hash = NULL;
	int write_bytes = 0;
	unsigned char *rsa_mod_len_buf = NULL;
	uint32_t rsa_mod_len;

	if (!operation || operation->operation_info.mode != TEE_MODE_DECRYPT) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt: Not a valid operationhandler "
				"or wrong operation mode\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	ret = rsa_op_generic_pre_checks_and_setup(operation, &hash, srcData, srcLen, destData,
						  destLen, &rsa_mod_len_buf, &rsa_mod_len);
	if (ret != TEE_SUCCESS)
		return ret; /* Err msg has been written to log */

	/* Decryption */
	if (operation->operation_info.algorithm == TEE_ALG_RSAES_PKCS1_V1_5) {
		write_bytes = RSA_private_decrypt(srcLen, srcData, rsa_mod_len_buf,
						  RSA_key(operation), RSA_PKCS1_PADDING);
	} else {
		write_bytes = RSA_private_decrypt(srcLen, srcData, rsa_mod_len_buf,
						  RSA_key(operation), RSA_NO_PADDING);
	}

	if (write_bytes == -1) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt: Decryption failed (openssl failure)\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	/* Remove padding, if needed */
	if (!remove_rsa_cipher_padding(operation, rsa_mod_len_buf, rsa_mod_len, destData, destLen,
				       params, paramCount, hash))
		TEE_Panic(TEE_ERROR_GENERIC); /* Err msg has been written to log */

	*destLen = int2uint32(write_bytes);
	free(rsa_mod_len_buf);
	return ret;
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation, TEE_Attribute *params,
				    uint32_t paramCount, void *digest, uint32_t digestLen,
				    void *signature, uint32_t *signatureLen)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!operation || !signatureLen || operation->operation_info.mode != TEE_MODE_SIGN) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricSignDigest: Not a valid operationhandler "
				"or wrong operation mode or error with parameters\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricSignDigest: Not a asymetric sign op "
				"or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.algorithm == TEE_ALG_DSA_SHA1)
		ret = dsa_sign(operation, digest, digestLen, signature, signatureLen);
	else
		ret = rsa_sign(operation, params, paramCount, digest, digestLen, signature,
			       signatureLen);

	return ret;
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation, TEE_Attribute *params,
				      uint32_t paramCount, void *digest, uint32_t digestLen,
				      void *signature, uint32_t signatureLen)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!operation || operation->operation_info.mode != TEE_MODE_VERIFY) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricVerifyDigest: Not a valid operationhandler "
				"or wrong operation mode\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_AsymmetricVerifyDigest: Not a asymetric sign op "
				"or not initialized or no key\n");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.algorithm == TEE_ALG_DSA_SHA1)
		ret = dsa_ver(operation, digest, digestLen, signature, signatureLen);
	else
		ret = rsa_ver(operation, params, paramCount, digest, digestLen, signature,
			      signatureLen);

	return ret;
}

void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params, uint32_t paramCount,
		   TEE_ObjectHandle derivedKey)
{
	TEE_Attribute *dh_pub_val = NULL;
	TEE_Attribute *der_key_gen_sec = NULL;
	BIGNUM *bn_dh_pub_val = NULL;
	int shared_secret_size = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!operation || !params || !derivedKey) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: operation or params or derivekey NULL\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto retu;
	}

	if (operation->operation_info.operationClass != TEE_OPERATION_KEY_DERIVATION ||
	    operation->operation_info.mode != TEE_MODE_DERIVE ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Not a derive op or not initialized or no key\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto retu;
	}

	/* Derive key object can hold a shared secret */
	if (derivedKey->maxObjSizeBytes < int2uint32(DH_size(DH_key(operation)))) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Shared secret does not fit to derivekey obj\n");
		ret = TEE_ERROR_SHORT_BUFFER;
		goto retu;
	}

	/* Does key object contain generic secret attribute and it is cor len */
	der_key_gen_sec = get_attr_by_ID(derivedKey, TEE_ATTR_SECRET_VALUE);
	if (!der_key_gen_sec) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Provide generic object with secret attribute\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto retu;
	}

	if (der_key_gen_sec->content.ref.length < int2uint32(DH_size(DH_key(operation)))) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Generic secrect obj secret buf too small\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto retu;
	}

	/* Compute secret */
	dh_pub_val = get_dh_pub_val(params, paramCount);
	if (!dh_pub_val) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Provide shared public value\n");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto retu;
	}

	bn_dh_pub_val = BN_bin2bn(dh_pub_val->content.ref.buffer,
				  dh_pub_val->content.ref.length, bn_dh_pub_val);
	if (!bn_dh_pub_val) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: bin2bn failed (openssl failure)\n");
		ret = TEE_ERROR_GENERIC;
		goto retu;
	}

	shared_secret_size = DH_compute_key(der_key_gen_sec->content.ref.buffer,
					    bn_dh_pub_val, DH_key(operation));
	if (shared_secret_size == -1) {
		OT_LOG(LOG_ERR, "TEE_DeriveKey: Shared secret computation fail\n");
		ret = TEE_ERROR_GENERIC;
		goto retu;
	}

	der_key_gen_sec->content.ref.length = shared_secret_size;

retu:
	BN_free(bn_dh_pub_val);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen)
{
	if (!randomBuffer)
		return;

	if (!RAND_bytes(randomBuffer, randomBufferLen)) {
		OT_LOG(LOG_ERR, "TEE_GenerateRandom: Rand data generation failed\n");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}
