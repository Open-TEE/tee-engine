/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#include <mbedtls/error.h>

#include "crypto_utils.h"
#include "operation_handle.h"
#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "storage/object_handle.h"
#include "tee_logging.h"

// Value not used in GP specs
static uint32_t not_valid_ecc_key_size = 4345623455;

static int key_usage_allow_operation(uint32_t obj_usage,
				     uint32_t operation_mode,
				     uint32_t algorithm)
{
	/* RSA no padding is a special case */
	if (algorithm == TEE_ALG_RSA_NOPAD) {

		if ((obj_usage & (TEE_USAGE_DECRYPT | TEE_USAGE_VERIFY)) &&
		    (operation_mode == TEE_MODE_DECRYPT))
			return 0;
		else if ((obj_usage & (TEE_USAGE_ENCRYPT | TEE_USAGE_SIGN)) &&
			 (operation_mode == TEE_MODE_ENCRYPT))
			return 0;
		else
			return 1;
	}

	switch (operation_mode) {
	case TEE_MODE_ENCRYPT:
		if (obj_usage & TEE_USAGE_ENCRYPT)
			return 0;
		return 1;

	case TEE_MODE_DECRYPT:
		if (obj_usage & TEE_USAGE_DECRYPT)
			return 0;
		return 1;

	case TEE_MODE_SIGN:
		if (obj_usage & TEE_USAGE_SIGN)
			return 0;

		return 1;

	case TEE_MODE_VERIFY:
		if (obj_usage & TEE_USAGE_VERIFY)
			return 0;

		return 1;

	case TEE_MODE_MAC:
		if (obj_usage & TEE_USAGE_MAC)
			return 0;

		return 1;

	case TEE_MODE_DIGEST:
		TEE_Panic(TEE_ERROR_GENERIC); /* Should never happen */
		break;

	case TEE_MODE_DERIVE:
		if (obj_usage & TEE_USAGE_DERIVE)
			return 0;

		return 1;

	default:
		return 1;
	}

	return 1;
}

static int valid_key_type_for_operation_algorithm(uint32_t key_type,
						  uint32_t operation_algorithm)
{
	// Note: All algorithms. Missing optional elliptic curve algorithms
	// TODO: Add elliptic stuff
	
	switch (key_type) {
	case TEE_TYPE_GENERIC_SECRET:
		return 0;

	case TEE_TYPE_AES:
		switch (operation_algorithm) {
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
			return 0;
		default:
			return 1;
		}

	case TEE_TYPE_DES:
		switch (operation_algorithm) {
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
			return 0;
		default:
			return 1;
		}

	case TEE_TYPE_DES3:
		switch (operation_algorithm) {
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			return 0;
		default:
			return 1;
		}

	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
		switch (operation_algorithm) {
		case TEE_ALG_HMAC_MD5:
		case TEE_ALG_HMAC_SHA1:
		case TEE_ALG_HMAC_SHA224:
		case TEE_ALG_HMAC_SHA256:
		case TEE_ALG_HMAC_SHA384:
		case TEE_ALG_HMAC_SHA512:
			return 0;
		default:
			return 1;
		}

	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_RSA_PUBLIC_KEY:
		switch (operation_algorithm) {
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
			return 0;
		default:
			return 1;
		}

	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_DSA_KEYPAIR:
		if (operation_algorithm == TEE_ALG_DSA_SHA1)
			return 0;
		return 1;

	case TEE_TYPE_DH_KEYPAIR:
		if (operation_algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET)
			return 0;
		return 1;
		
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		if (operation_algorithm == TEE_ALG_ECDH_DERIVE_SHARED_SECRET)
			return 0;
		return 1;
		
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
		switch (operation_algorithm) {
		case TEE_ALG_ECDSA_SHA1:
		case TEE_ALG_ECDSA_SHA224:
		case TEE_ALG_ECDSA_SHA256:
		case TEE_ALG_ECDSA_SHA384:
		case TEE_ALG_ECDSA_SHA512:
			return 0;
		default:
			return 1;
		}
		
	default:
		return 1;
	}
}

static int object_type_compatible_to_op(uint32_t obj_type, uint32_t operation_mode)
{
	if (obj_type == TEE_TYPE_DSA_PUBLIC_KEY && operation_mode != TEE_MODE_VERIFY)
		return false;

	if (obj_type == TEE_TYPE_RSA_PUBLIC_KEY &&
	    !(operation_mode == TEE_MODE_VERIFY || operation_mode == TEE_MODE_ENCRYPT))
		return false;

	if (obj_type == TEE_TYPE_ECDSA_PUBLIC_KEY && operation_mode != TEE_MODE_VERIFY)
		return false;
	
	return true;
}

/* TODO check the sizes of 224 and 384 */
#define MD5_SIZE 16
#define SHA1_SIZE 20
#define SHA224_SIZE 28
#define SHA256_SIZE 32
#define SHA384_SIZE 48
#define SHA512_SIZE 64

uint32_t valid_ecc_curve(TEE_Attribute *curve_attr)
{
	return valid_ecc_curve_and_keysize(curve_attr, not_valid_ecc_key_size);
}



uint32_t valid_ecc_curve_and_keysize(TEE_Attribute *curve_attr, uint32_t key_size)
{
	switch (curve_attr->content.value.a) {
	case TEE_ECC_CURVE_NIST_P192:
		if (key_size == not_valid_ecc_key_size || 192 == key_size)
			return 0;
		return 1;
		
	case TEE_ECC_CURVE_NIST_P224:
		if (key_size == not_valid_ecc_key_size || 224 == key_size)
			return 0;
		return 1;
	case TEE_ECC_CURVE_NIST_P256:
		if (key_size == not_valid_ecc_key_size || 256 == key_size)
			return 0;
		return 1;
		
	case TEE_ECC_CURVE_NIST_P384:
		if (key_size == not_valid_ecc_key_size || 384 == key_size)
			return 0;
		return 1;
		
	case TEE_ECC_CURVE_NIST_P521:
		if (key_size == not_valid_ecc_key_size || 521 == key_size)
			return 0;
		return 1;
		
	default:
		OT_LOG_ERR("ECC curve is not supported [%u] "
			   "(NOTE: expected curve in \"a\"-value)",
			   curve_attr->content.value.a);
		return 1;
	}
}

size_t get_alg_hash_lenght(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return MD5_SIZE;

	case TEE_ALG_SHA1:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_ECDSA_SHA1:
		return SHA1_SIZE;

	case TEE_ALG_SHA224:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_ECDSA_SHA224:		
		return SHA224_SIZE;

	case TEE_ALG_SHA256:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_ECDSA_SHA256:
		return SHA256_SIZE;

	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_ECDSA_SHA384:
		return SHA384_SIZE;

	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_ECDSA_SHA512:
		return SHA512_SIZE;

	default:
		return 0;
	}
}

uint32_t get_operation_class(uint32_t algorithm)
{
	switch (algorithm) {
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
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		return TEE_OPERATION_ASYMMETRIC_SIGNATURE;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		return TEE_OPERATION_KEY_DERIVATION;

	default:
		OT_LOG(LOG_ERR, "Not supported algorithm");
		TEE_Panic(TEE_ERROR_GENERIC);
		return 0; /* return for compiler */
	}
}

/* This function is collection algorithms/key sizes that is supported/implemented */
bool supported_algorithms(uint32_t algorithm, uint32_t key_size, uint32_t *key_count)
{
	// Currently not need
	key_size = key_size;
	
	switch (algorithm) {

	// AES: Encrypt and decrypt
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_GCM:
		*key_count = 1;
		return true;

		/* HASH */
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		*key_count = 0;
		return true;
		
		/* HMAC */
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*key_count = 1;
		return true;

		/* Signature and Verify */
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		*key_count = 1;
		return true;

		/* RSA: Encrypt and decrypt */
	case TEE_ALG_RSAES_PKCS1_V1_5:
		*key_count = 1;
		return true;

	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		*key_count = 1;
		return true;

	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		*key_count = 1;
		return true;
		
	default:
		return false;
	}

	return false; /* For compiler, never reached */
}

bool valid_key_size_for_algorithm(uint32_t algorithm, uint32_t key)
{
	switch (algorithm) {
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_GCM:
		if (key == 128 || key == 192 || key == 256)
			return true;
		return false;
		
		
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		/* No keys */
		return true;

	case TEE_ALG_HMAC_MD5:
		if (key >= 64 && key <= 512 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_HMAC_SHA1:
		if (key >= 80 && key <= 512 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_HMAC_SHA224:
		if (key >= 112 && key <= 512 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_HMAC_SHA256:
		if (key >= 192 && key <= 1024 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_HMAC_SHA384:
		if (key >= 256 && key <= 1024 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_HMAC_SHA512:
		if (key >= 256 && key <= 1024 && !(key % 8))
			return true;
		return false;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		if (key >= 256 && key <= 2048)
			return true;
		return false;

	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		if (key == 192 || key == 224 ||
		    key == 256 || key == 384 ||
		    key == 521)
			return true;
		return false;

	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		if (key >= 8 && key <= 4096 && !(key % 8))
			return true;
		return false;
	default:
		return false;
	}
}

int valid_mode_and_algorithm(uint32_t algorithm, uint32_t mode)
{
	/* TEE Core API: Table 6-4: TEE_AllocateOperation Allowed Modes
	 * Note: No elliptic curve algortihms */

	switch (mode) {
	case TEE_MODE_ENCRYPT:
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
		case TEE_ALG_RSAES_PKCS1_V1_5:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		case TEE_ALG_RSA_NOPAD:
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_DECRYPT:
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
		case TEE_ALG_RSAES_PKCS1_V1_5:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		case TEE_ALG_RSA_NOPAD:
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_SIGN:
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
		case TEE_ALG_DSA_SHA1:
		case TEE_ALG_ECDSA_SHA1:
		case TEE_ALG_ECDSA_SHA224:
		case TEE_ALG_ECDSA_SHA256:
		case TEE_ALG_ECDSA_SHA384:
		case TEE_ALG_ECDSA_SHA512:
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_VERIFY:
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
		case TEE_ALG_DSA_SHA1:
		case TEE_ALG_ECDSA_SHA1:
		case TEE_ALG_ECDSA_SHA224:
		case TEE_ALG_ECDSA_SHA256:
		case TEE_ALG_ECDSA_SHA384:
		case TEE_ALG_ECDSA_SHA512:
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_MAC:
		switch (algorithm) {
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
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_DIGEST:
		switch (algorithm) {
		case TEE_ALG_MD5:
		case TEE_ALG_SHA1:
		case TEE_ALG_SHA224:
		case TEE_ALG_SHA256:
		case TEE_ALG_SHA384:
		case TEE_ALG_SHA512:
			return 0;
		default:
			return 1;
		}

	case TEE_MODE_DERIVE:
		switch (algorithm) {
		case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
			return 0;
		default:
			return 1;
		}

	default:
		return 1;
	}
}

TEE_Result valid_key_and_operation(TEE_ObjectHandle key,
				   TEE_OperationHandle operation)
{
	if (!(key->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("OperationKeyError: Key object is not initialized");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.operationState == TEE_OPERATION_STATE_ACTIVE) {
		OT_LOG_ERR("OperationKeyError: Operation state is TEE_OPERATION_STATE_ACTIVE");
		return TEE_ERROR_BAD_STATE;
	}

	if ((operation->operation_info.operationClass == TEE_OPERATION_CIPHER ||
	     operation->operation_info.operationClass == TEE_OPERATION_MAC) &&
	    operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("OperationKeyError: Cipher and Mac operation "
			   "handle already TEE_HANDLE_FLAG_INITIALIZED (operationClass[%u])",
			   operation->operation_info.operationClass);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (operation->operation_info.mode == TEE_MODE_DIGEST) {
		OT_LOG_ERR("OperationKeyError: Digest does not require key");
		return TEE_ERROR_BAD_STATE;
	}

	if (key->objectInfo.maxObjectSize > operation->operation_info.maxKeySize) {
		OT_LOG_ERR("OperationKeyError: Object key maxKeySize too big (key[%u]; operation[%u]",
			   key->objectInfo.maxObjectSize, operation->operation_info.maxKeySize);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!object_type_compatible_to_op(key->objectInfo.objectType,
					  operation->operation_info.mode)) {
		OT_LOG_ERR("OperationKeyError: Key object type conflicts with operation mode (keyObjectType[%u]; opeationMode[%u])",
			   key->objectInfo.objectType, operation->operation_info.mode);
		return TEE_ERROR_BAD_STATE;
	}

	if (valid_key_type_for_operation_algorithm(key->objectInfo.objectType,
						   operation->operation_info.algorithm)) {
		OT_LOG_ERR("OperationKeyError: Key object type conflict with operation algorithm (keyObjectType[%u]; opeationAlg[%u])",
			   key->objectInfo.objectType, operation->operation_info.algorithm);
		return TEE_ERROR_BAD_STATE;
	}

	if (key_usage_allow_operation(key->objectInfo.objectUsage,
				      operation->operation_info.mode,
				      operation->operation_info.algorithm)) {
		OT_LOG_ERR("OperationKeyError: Key object usage conflict with operation mode or/and operation algorithm (keyObjectUsage[%u]; opeationMode[%u]; opeationAlg[%u])",
			   key->objectInfo.objectUsage, operation->operation_info.mode, operation->operation_info.algorithm);
		return TEE_ERROR_BAD_STATE;
	}
	
	return TEE_SUCCESS;
}

void print_mbedtls_to_syslog(int mbedtls_error)
{
	size_t buf_len_err_mbedtls = 200;
	char buf_err_mbedtls[buf_len_err_mbedtls];

	mbedtls_strerror(mbedtls_error, buf_err_mbedtls, buf_len_err_mbedtls);
	OT_LOG_ERR("MBEDTLS Error [%s]", buf_err_mbedtls);
}
