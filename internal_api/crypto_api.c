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

#include <string.h>

#include "crypto_api.h"
#include "tee_memory.h"

/*
 * ## Variables ##
 */

struct __TEE_OperationHandle{
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t keySize;
	uint32_t requiredKeyUsage;
	uint32_t handleState;
	void* key;
};




/*
 * ## NON internal api functions ##
 */

static bool valid_mode_for_algorithm(algorithm_Identifier alg,
				    TEE_OperationMode mode)
{
	switch(mode) {
	case TEE_MODE_ENCRYPT:
		switch(alg) {
		case TEE_ALG_AES_ECB_NOPAD: return true;
		case TEE_ALG_AES_CBC_NOPAD: return true;
		case TEE_ALG_AES_CTR: return true;
		case TEE_ALG_AES_CTS: return true;
		case TEE_ALG_AES_XTS: return true;
		case TEE_ALG_AES_CCM: return true;
		case TEE_ALG_AES_GCM: return true;
		case TEE_ALG_DES_ECB_NOPAD: return true;
		case TEE_ALG_DES_CBC_NOPAD: return true;
		case TEE_ALG_DES3_ECB_NOPAD: return true;
		case TEE_ALG_DES3_CBC_NOPAD: return true;
		case TEE_ALG_RSAES_PKCS1_V1_5: return true;
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512: return true;
		case TEE_ALG_RSA_NOPAD: return true;
		default: return false;
		}

	case TEE_MODE_DECRYPT:
		switch(alg) {
		case TEE_ALG_AES_ECB_NOPAD: return true;
		case TEE_ALG_AES_CBC_NOPAD: return true;
		case TEE_ALG_AES_CTR: return true;
		case TEE_ALG_AES_CTS: return true;
		case TEE_ALG_AES_XTS: return true;
		case TEE_ALG_AES_CCM: return true;
		case TEE_ALG_AES_GCM: return true;
		case TEE_ALG_DES_ECB_NOPAD: return true;
		case TEE_ALG_DES_CBC_NOPAD: return true;
		case TEE_ALG_DES3_ECB_NOPAD: return true;
		case TEE_ALG_DES3_CBC_NOPAD: return true;
		case TEE_ALG_RSAES_PKCS1_V1_5: return true;
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384: return true;
		//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512: return true;
		case TEE_ALG_RSA_NOPAD: return true;
		default: return false;
		}

	case TEE_MODE_SIGN:
		switch(alg) {
		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512: return true;
		case TEE_ALG_DSA_SHA1: return true;
		default: return false;
		}

	case TEE_MODE_VERIFY:
		switch(alg) {
		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384: return true;
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384: return true;
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512: return true;
		case TEE_ALG_DSA_SHA1: return true;
		default: return false;
		}

	case TEE_MODE_MAC:
		switch(alg) {
		case TEE_ALG_DES_CBC_MAC_NOPAD: return true;
		case TEE_ALG_AES_CBC_MAC_NOPAD: return true;
		case TEE_ALG_AES_CBC_MAC_PKCS5: return true;
		case TEE_ALG_AES_CMAC: return true;
		case TEE_ALG_DES_CBC_MAC_PKCS5: return true;
		case TEE_ALG_DES3_CBC_MAC_NOPAD: return true;
		case TEE_ALG_DES3_CBC_MAC_PKCS5: return true;
		case TEE_ALG_HMAC_MD5: return true;
		case TEE_ALG_HMAC_SHA1: return true;
		case TEE_ALG_HMAC_SHA224: return true;
		case TEE_ALG_HMAC_SHA256: return true;
		case TEE_ALG_HMAC_SHA384: return true;
		case TEE_ALG_HMAC_SHA512: return true;
		default: return false;
		}

	case TEE_MODE_DIGEST:
		switch(alg) {
		case TEE_ALG_MD5: return true;
		case TEE_ALG_SHA1: return true;
		case TEE_ALG_SHA224: return true;
		case TEE_ALG_SHA256: return true;
		case TEE_ALG_SHA384: return true;
		case TEE_ALG_SHA512: return true;
		default: return false;
		}

	case TEE_MODE_DERIVE:
		switch (alg) {
		case TEE_ALG_DH_DERIVE_SHARED_SECRET: return true;
		default: return false;
		}
	default: return false;
	}
}

static bool valid_mode(TEE_OperationMode mode)
{
	return (mode < NUM_TEE_OperationMode) ? true : false;
}

static bool valid_algorithm(algorithm_Identifier alg)
{
	switch(alg) {
	case TEE_ALG_AES_ECB_NOPAD: return true;
	case TEE_ALG_AES_CBC_NOPAD: return true;
	case TEE_ALG_AES_CTR: return true;
	case TEE_ALG_AES_CTS: return true;
	case TEE_ALG_AES_XTS: return true;
	case TEE_ALG_AES_CBC_MAC_NOPAD: return true;
	case TEE_ALG_AES_CBC_MAC_PKCS5: return true;
	case TEE_ALG_AES_CMAC: return true;
	case TEE_ALG_AES_CCM: return true;
	case TEE_ALG_AES_GCM: return true;
	case TEE_ALG_DES_ECB_NOPAD: return true;
	case TEE_ALG_DES_CBC_NOPAD: return true;
	case TEE_ALG_DES_CBC_MAC_NOPAD: return true;
	case TEE_ALG_DES_CBC_MAC_PKCS5: return true;
	case TEE_ALG_DES3_ECB_NOPAD: return true;
	case TEE_ALG_DES3_CBC_NOPAD: return true;
	case TEE_ALG_DES3_CBC_MAC_NOPAD: return true;
	case TEE_ALG_DES3_CBC_MAC_PKCS5: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384: return true;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512: return true;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1: return true;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224: return true;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256: return true;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384: return true;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512: return true;
	case TEE_ALG_RSAES_PKCS1_V1_5: return true;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1: return true;
	//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224: return true;
	//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256: return true;
	//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384: return true;
	//case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512: return true;
	case TEE_ALG_RSA_NOPAD: return true;
	case TEE_ALG_DSA_SHA1: return true;
	case TEE_ALG_DH_DERIVE_SHARED_SECRET: return true;
	case TEE_ALG_MD5: return true;
	case TEE_ALG_SHA1: return true;
	case TEE_ALG_SHA224: return true;
	case TEE_ALG_SHA256: return true;
	case TEE_ALG_SHA384: return true;
	case TEE_ALG_SHA512: return true;
	case TEE_ALG_HMAC_MD5: return true;
	case TEE_ALG_HMAC_SHA1: return true;
	case TEE_ALG_HMAC_SHA224: return true;
	case TEE_ALG_HMAC_SHA256: return true;
	case TEE_ALG_HMAC_SHA384: return true;
	case TEE_ALG_HMAC_SHA512: return true;
	default: return false;
	}
}






/*
 * ## Internal api functions ##
 */

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm,
				 uint32_t mode,
				 uint32_t maxKeySize)
{
	void* tmp_key;
	TEE_OperationHandle tmp_handle;

	if (valid_algorithm(algorithm))
		return TEE_ERROR_NOT_SUPPORTED;

	if (valid_mode(mode))
		return TEE_ERROR_NOT_SUPPORTED;

	if (valid_mode_for_algorithm(algorithm, mode))
		return TEE_ERROR_NOT_SUPPORTED;

	tmp_handle = TEE_Malloc(sizeof(struct __TEE_OperationHandle), 0);
	if (tmp_handle == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Adding 8 to maxKeySize is for rounding. TEE_Malloc parameter
	 * is given in BYTES and maxKeySize is given in BITS.
	 * This is always rounded up.
	 */
	tmp_key = TEE_Malloc((maxKeySize + 8) / 8, 0);
	if (tmp_key == NULL) {
		TEE_Free(tmp_handle);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	tmp_handle->mode = mode;
	tmp_handle->algorithm = algorithm;
	tmp_handle->key = tmp_key;
	*operation = tmp_handle;

	return TEE_SUCCESS;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	if (operation == NULL) {
		/* panic(TEE_ERROR_BAD_PARAMETERS) */
	}

	TEE_Free(operation->key);
	TEE_Free(operation);
}

void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	if (dstOperation == NULL || srcOperation == NULL) {
		/* panic(TEE_ERROR_BAD_PARAMETERS); */
	}

	if (dstOperation->mode != srcOperation->mode) {
		/* panic(TEE_ERROR_BAD_STATE); */
	}

	if (dstOperation->algorithm != srcOperation->algorithm) {
		/* panic(TEE_ERROR_BAD_STATE); */
	}

	if (srcOperation->maxKeySize > dstOperation->maxKeySize) {
		/* panic(TEE_ERROR_BAD_PARAMETERS); */
	}

	memcpy(dstOperation, srcOperation, sizeof(struct __TEE_OperationHandle));
}
