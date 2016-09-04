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

#include <mbedtls/rsa.h>

#include "operation_handle.h"
#include "crypto_utils.h"
#include "../tee_crypto_api.h"
#include "../tee_panic.h"
#include "../../include/tee_shared_data_types.h"



static TEE_Result do_rsa_pkcs_signature(TEE_OperationHandle operation,
					void *digest,
					uint32_t digestLen,
					void *signature,
					uint32_t *signatureLen)
{
	if (digestLen > (operation->key_data->key_lenght - 11))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->key_data->key_lenght > *signatureLen)
		return TEE_ERROR_SHORT_BUFFER;

	/* Old implementation
	if (crypto_rsa_pkcs_sign(operation->key->key_lenght,
				 map_rsaHash2Hash(operation->operation_info.algorithm),
				 (uint8_t *)digest, digestLen, (uint8_t *)signature,
				 operation->key->key.rsa.n,
				 operation->key->key.rsa.e,
				 operation->key->key.rsa.p,
				 operation->key->key.rsa.q,
				 operation->key->key.rsa.d) != OK)
		TEE_Panic(TEE_ERROR_GENERIC);
*/
	*signatureLen = operation->key_data->key_lenght;

	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_verify(TEE_OperationHandle operation,
				     void *digest,
				     uint32_t digestLen,
				     void *signature,
				     uint32_t signatureLen)
{
	if (digestLen > (operation->key_data->key_lenght - 11) ||
	    operation->key_data->key_lenght != signatureLen)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
/* Old implementation
	if (crypto_rsa_pkcs_verify(operation->key->key_lenght,
				   map_rsaHash2Hash(operation->operation_info.algorithm),
				   (uint8_t *)digest, digestLen, (uint8_t *)signature,
				   operation->key->key.rsa.n,
				   operation->key->key.rsa.e))
		return TEE_ERROR_SIGNATURE_INVALID;
	else
		return TEE_SUCCESS;
*/
}

static TEE_Result do_rsa_pkcs_encrypt(TEE_OperationHandle operation,
				      void *srcData,
				      uint32_t srcLen,
				      void *destData,
				      uint32_t *destLen)
{
	/* palintext_size_bytes must be > 0 and <= key_size_bytes - 11 */
	if (srcLen == 0 || srcLen > (operation->key_data->key_lenght - 11))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->key_data->key_lenght > *destLen)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
/* Old implementation
	if (crypto_rsa_pkcs_encrypt(operation->key->key_lenght,
				    (uint8_t *)srcData, srcLen,
				    (uint8_t *)destData,
				    0,
				    operation->key->key.rsa.n,
				    operation->key->key.rsa.e) != OK)
		TEE_Panic(TEE_ERROR_GENERIC);
*/
	*destLen = operation->key_data->key_lenght;
	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_decrypt(TEE_OperationHandle operation,
				      void *srcData,
				      uint32_t srcLen,
				      void *destData,
				      uint32_t *destLen)
{
	/* ciphertext points to memory of key_size_bytes in size */
	if (srcLen != operation->key_data->key_lenght)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* plaintext points to memory of key_size_bytes in size at input (since actual size is unknown) */
	if (*destLen != operation->key_data->key_lenght)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
/* Old implementation
	if (crypto_rsa_pkcs_decrypt(operation->key->key_lenght,
				    (uint8_t *)srcData,
				    (uint8_t *)destData, destLen,
				    operation->key->key.rsa.n,
				    operation->key->key.rsa.e,
				    operation->key->key.rsa.p,
				    operation->key->key.rsa.q,
				    operation->key->key.rsa.d) != OK)
		TEE_Panic(TEE_ERROR_GENERIC);
*/
	return TEE_SUCCESS;
}






/*
 * GP TEE Core API functions
 */

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
				 TEE_Attribute *params,
				 uint32_t paramCount,
				 void *srcData,
				 uint32_t srcLen,
				 void *destData,
				 uint32_t *destLen)
{
	if (operation == NULL || srcData == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.mode != TEE_MODE_ENCRYPT ||
	    operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return do_rsa_pkcs_encrypt(operation, srcData, srcLen, destData, destLen);
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
				 TEE_Attribute *params,
				 uint32_t paramCount,
				 void *srcData,
				 uint32_t srcLen,
				 void *destData,
				 uint32_t *destLen)
{
	if (operation == NULL || srcData == NULL || destData == NULL || destLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.mode != TEE_MODE_DECRYPT ||
	    operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return do_rsa_pkcs_decrypt(operation, srcData, srcLen, destData, destLen);
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
				    TEE_Attribute *params,
				    uint32_t paramCount,
				    void *digest,
				    uint32_t digestLen,
				    void *signature,
				    uint32_t *signatureLen)
{

	if (operation == NULL || signatureLen == NULL || signature == NULL || digest == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.mode != TEE_MODE_SIGN ||
	    operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_signature(operation, digest, digestLen, signature, signatureLen);

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
				      TEE_Attribute *params,
				      uint32_t paramCount,
				      void *digest,
				      uint32_t digestLen,
				      void *signature,
				      uint32_t signatureLen)
{
	if (operation == NULL || digest == NULL || signature == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (operation->operation_info.mode != TEE_MODE_VERIFY ||
	    operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
	    !(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_verify(operation, digest, digestLen, signature, signatureLen);

	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}
