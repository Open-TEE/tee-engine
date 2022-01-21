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

/* Note: General operation functions from the Cryptographic operations API found in this file */

#include <string.h>
#include <stdlib.h>

#include "crypto_ae.h"
#include "crypto_asym.h"
#include "crypto_cipher.h"
#include "crypto_digest.h"
#include "crypto_mac.h"
#include "crypto_utils.h"
#include "operation_handle.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"
#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "tee_storage_api.h"
#include "tee_memory.h"
#include "tee_logging.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/* Extern variables. */
mbedtls_entropy_context ot_mbedtls_entropy;
mbedtls_ctr_drbg_context ot_mbedtls_ctr_drbg;

static bool __attribute__((constructor)) mbetls_init()
{
	const char *pers = "opentee_general";

	mbedtls_ctr_drbg_init(&ot_mbedtls_ctr_drbg);
	mbedtls_entropy_init(&ot_mbedtls_entropy);

	if(mbedtls_ctr_drbg_seed(&ot_mbedtls_ctr_drbg, mbedtls_entropy_func, &ot_mbedtls_entropy,
				 (const unsigned char *)pers, strlen(pers))) {
		OT_LOG(LOG_ERR, "Failed mbedtls_ctr_drbg_seed");
		return false;
	}

	return true;
}

static void __attribute__((destructor)) mbetls_cleanup()
{
	mbedtls_ctr_drbg_free(&ot_mbedtls_ctr_drbg);
	mbedtls_entropy_free(&ot_mbedtls_entropy);
}

static void remove_operation_key(TEE_OperationHandle operation)
{
	if (operation->key_data == NULL)
		return;

	free_gp_key(operation->key_data);
	operation->operation_info.handleState &= TEE_HANDLE_FLAG_KEY_SET;
	operation->key_data = (struct gp_key *)NULL;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	if (operation == NULL)
		return;

	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {
		remove_operation_key(operation);
		free_gp_cipher(operation);

	} else if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST) {
		free_gp_digest(operation);

	} else if (operation->operation_info.operationClass == TEE_OPERATION_MAC) {
		free_gp_mac(operation);

	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER ||
		   operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE) {
		free_gp_asym(operation);

	} else if (operation->operation_info.operationClass == TEE_OPERATION_AE) {
		free_gp_ae(operation);
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {
		free_gp_asym(operation);
		
	} else {
		OT_LOG(LOG_ERR, "Not supported operation class [%u]",
		       operation->operation_info.operationClass);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	remove_operation_key(operation);
	free(operation);
	operation = 0;
}

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm,
				 uint32_t mode,
				 uint32_t maxKeySize)
{
	// Function should do the static alloc for crypto operation 

	TEE_OperationHandle tmp_handle = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t key_count;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AllocateOperation panicking due operation handle NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (!supported_algorithms(algorithm, maxKeySize, &key_count)) {
		OT_LOG_ERR("TEE_AllocateOperation algorithm [%u] AND/OR "
			   "maxKeySize [%u] not supported", algorithm, maxKeySize);
		return TEE_ERROR_NOT_SUPPORTED;
	}
	
	if (valid_mode_and_algorithm(algorithm, mode)) {
		OT_LOG_ERR("TEE_AllocateOperation algorithm [%u] and "
			   "mode [%u] combination is not valid", algorithm, mode);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!valid_key_size_for_algorithm(algorithm, maxKeySize)) {
		OT_LOG_ERR("TEE_AllocateOperation algorithm [%u] and "
			   "maxKeySize [%u] combination is not valid", algorithm, maxKeySize);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	tmp_handle = (struct __TEE_OperationHandle *)
		     TEE_Malloc(sizeof(struct __TEE_OperationHandle), 1);
	if (tmp_handle == NULL) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		OT_LOG_ERR("TEE_AllocateOperation out of memoery");
		goto err;
	}

	// Generic info about operation. Fill out only neccessary fields.
	tmp_handle->operation_info.operationClass = get_operation_class(algorithm);
	tmp_handle->operation_info.mode = mode;
	tmp_handle->operation_info.algorithm = algorithm;
	tmp_handle->operation_info.maxKeySize = maxKeySize;
	tmp_handle->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
	tmp_handle->operation_info.numberOfKeys = key_count;
	tmp_handle->operation_info.keyInformation[0].keySize = 0;
	tmp_handle->operation_info.keyInformation[0].requiredKeyUsage = 0;
	if (key_count == 2) {
		tmp_handle->operation_info.handleState |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;
		tmp_handle->operation_info.keyInformation[1].keySize = 0;
		tmp_handle->operation_info.keyInformation[1].requiredKeyUsage = 0;
	}

	// Alloc operation needed meta info.
	// Note: Not allocing space for operation keys
	switch (algorithm) {
	case TEE_ALG_AES_GCM:
		ret = init_gp_ae(tmp_handle);
		if (ret != TEE_SUCCESS)
			goto err;
		
		break;
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:	
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		//Nothing to do!
		break;

	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		ret = init_gp_digest(tmp_handle);
		if (ret != TEE_SUCCESS)
			goto err;

		break;

	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		ret = mac_gp_init(tmp_handle);
		if (ret != TEE_SUCCESS)
			goto err;

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
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		ret = init_gp_asym(tmp_handle);
		if (ret != TEE_SUCCESS)
			goto err;
		break;

	default:
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}
	
	*operation = tmp_handle;
	return ret;

err:
	TEE_FreeOperation(tmp_handle);
	*operation = 0;
	return ret;
}

void TEE_GetOperationInfo(TEE_OperationHandle operation,
			  TEE_OperationInfo *operationInfo)
{
	TEE_OperationInfo rv_info;
	
	if (operation == NULL) {
		OT_LOG_ERR("TEE_GetOperationInfo due panics operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operationInfo == NULL) {
		OT_LOG_ERR("TEE_GetOperationInfo due panics operationInfo NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	//Internal check
	if (operation->operation_info.numberOfKeys != 1) {
		OT_LOG_ERR("TEE_GetOperationInfo internal error");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
	
	rv_info.algorithm = operation->operation_info.algorithm;
	rv_info.digestLength = operation->operation_info.digestLength;
	rv_info.handleState = operation->operation_info.handleState;
	rv_info.keySize = operation->operation_info.keyInformation[0].keySize;
	rv_info.requiredKeyUsage = operation->operation_info.keyInformation[0].requiredKeyUsage;
	rv_info.maxKeySize = operation->operation_info.maxKeySize;
	rv_info.mode = operation->operation_info.mode;
	rv_info.operationClass = operation->operation_info.operationClass;

	memset(operationInfo, 0, sizeof(TEE_OperationInfo));
	memcpy(operationInfo, &rv_info, sizeof(TEE_OperationInfo));
}

TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
					TEE_OperationInfoMultiple *operationInfoMultiple,
					size_t *operationSize)
{
	if (operation == NULL) {
		OT_LOG_ERR("TEE_GetOperationInfoMultiple due panics operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operationInfoMultiple == NULL) {
		OT_LOG_ERR("TEE_GetOperationInfoMultiple due panics operationInfoMultiple NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operationSize == NULL) {
		OT_LOG_ERR("TEE_GetOperationInfoMultiple due panics operationSize NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	//Internal check
	if (operation->operation_info.numberOfKeys > 1) {
		OT_LOG_ERR("TEE_GetOperationInfoMultiple internal error");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
	
	memset(operationInfoMultiple, 0, sizeof(TEE_OperationInfoMultiple));
	memcpy(operationInfoMultiple, &operation->operation_info, sizeof(TEE_OperationInfoMultiple));
	
	//TODO (NOTE): Not sure about what is this
	*operationSize = 0;
	
	return TEE_SUCCESS;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	if (operation == NULL) {
		OT_LOG_ERR("TEE_ResetOperation panics due operation handle NULL");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_ResetOperation panics due key is not set");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	// Clear crypto specific state
	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {

		reset_gp_cipher(operation);

		operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
		operation->operation_info.handleState = TEE_HANDLE_FLAG_KEY_SET;
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST) {

		reset_gp_digest(operation);
		
		// Just setting operation state
		operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;

	} else if (operation->operation_info.operationClass == TEE_OPERATION_MAC) {

		// Just setting operation state 
		reset_gp_mac(operation);
		operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
		operation->operation_info.handleState = TEE_HANDLE_FLAG_KEY_SET;
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER ||
		   operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE) {

		/* Only for documenting purpose. This is single stage operation */
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_AE) {

		reset_gp_ae(operation);
		
		operation->operation_info.operationState = TEE_OPERATION_STATE_INITIAL;
		operation->operation_info.handleState = TEE_HANDLE_FLAG_KEY_SET;
		operation->operation_info.digestLength = 0;
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {

		/* Only for documenting purpose. This is single stage operation */

	} else {
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key)
{
	TEE_Result ret = TEE_SUCCESS;

	if (operation == NULL) {
		OT_LOG_ERR("TEE_SetOperationKey panicking due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationState != TEE_OPERATION_STATE_INITIAL) {
		OT_LOG_ERR("TEE_SetOperationKey panicking due operation state not TEE_OPERATION_STATE_INITIAL"); 
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->operation_info.algorithm == TEE_ALG_AES_XTS) {
		OT_LOG_ERR("TEE_SetOperationKey panicking due operation algorithm TEE_ALG_AES_XTS");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	// If key NULL, clear key from operation
	if (key == NULL) {
		remove_operation_key(operation);
		return TEE_SUCCESS;
	}
	
	ret = valid_key_and_operation(key, operation);
	if (ret != TEE_SUCCESS) {
		OT_LOG_ERR("TEE_SetOperationKey panicking (search \"OperationKeyError\" from syslog)");
		TEE_Panic(ret); //Error logged
	}

	if (operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET) {
		remove_operation_key(operation);
	}
	
	//Algorithm specific operations
	if (operation->operation_info.operationClass == TEE_OPERATION_CIPHER) {

		assign_key_cipher(operation, key);
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_DIGEST) {
		//No key

	} else if (operation->operation_info.operationClass == TEE_OPERATION_MAC) {

		assign_key_mac(operation, key);
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_CIPHER ||
		   operation->operation_info.operationClass == TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
		   operation->operation_info.operationClass == TEE_OPERATION_KEY_DERIVATION) {

		if (!assign_asym_key(operation, key)) {
			return TEE_ERROR_GENERIC;
		}
		
	} else if (operation->operation_info.operationClass == TEE_OPERATION_AE) {

		assign_key_ae(operation, key);
		
	} else {
		OT_LOG(LOG_ERR, "Not supported operation class");
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	operation->key_data = key->key;
	key->key->reference_count++;	
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	operation->operation_info.keyInformation[0].keySize = BYTES_TO_BITS(key->key->key_lenght);
	operation->operation_info.keyInformation[0].requiredKeyUsage = 0;
	operation->operation_info.numberOfKeys = 1;

	return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
				TEE_ObjectHandle key1,
				TEE_ObjectHandle key2)
{
	operation = operation;
	key1 = key1;
	key2 = key2;
	
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation)
{
	dstOperation = dstOperation;
	srcOperation = srcOperation;

	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}
