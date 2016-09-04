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
#include <mbedtls/ecdsa.h>

#include "operation_handle.h"
#include "crypto_utils.h"
#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "../../include/tee_shared_data_types.h"
#include "tee_logging.h"

//TODO: Maybe we should collect common functionality to function (RSA)

static mbedtls_md_type_t map_gp_pkcs_hash(uint32_t pkcs_algorithm)
{
	switch (pkcs_algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		return MBEDTLS_MD_MD5;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		return MBEDTLS_MD_SHA1;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		return MBEDTLS_MD_SHA224;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		return MBEDTLS_MD_SHA256;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		return MBEDTLS_MD_SHA384;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return MBEDTLS_MD_SHA512;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return MBEDTLS_MD_NONE;
}

static TEE_Result do_rsa_pkcs_signature(TEE_OperationHandle operation,
					void *digest,
					uint32_t digestLen,
					void *signature,
					uint32_t *signatureLen)
{
	uint32_t maxDigestLen;
	int rv_mbedtls;
	
	maxDigestLen = operation->key_data->key_lenght - 11;
	
	if (digestLen > maxDigestLen) {
		OT_LOG_ERR("Error (rsa signature): Digest lenght too big for RSA key "
			   "(digestLen[%u]; maxDigestLenForKey[%u])",
			   digestLen, maxDigestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->key_data->key_lenght > *signatureLen) {
		OT_LOG_ERR("Error (rsa signature): Signature buffer short (provided[%u]; required[%u])",
			   operation->key_data->key_lenght, *signatureLen);
		return TEE_ERROR_SHORT_BUFFER;
	}

	//OpenTEE internal sanity check. 
	rv_mbedtls = mbedtls_rsa_check_pubkey(&operation->key_data->key.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA verify; RSA key corrupted)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_rsa_rsassa_pkcs1_v15_sign(&operation->key_data->key.rsa.ctx,
						       mbedtls_ctr_drbg_random,
						       &ot_mbedtls_ctr_drbg,
						       map_gp_pkcs_hash(operation->operation_info.algorithm),
						       get_alg_hash_lenght(operation->operation_info.algorithm),
						       digest,
						       signature);
	
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal crypto error (RSA signature)");
		return TEE_ERROR_GENERIC;
	}
	
	*signatureLen = operation->key_data->key_lenght;	
	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_verify(TEE_OperationHandle operation,
				     void *digest,
				     uint32_t digestLen,
				     void *signature,
				     uint32_t signatureLen)
{
	uint32_t maxDigestLen;
	int rv_mbedtls;
	mbedtls_md_type_t md_type;
	
	maxDigestLen = operation->key_data->key_lenght - 11;
	
	if (digestLen > maxDigestLen) {
		OT_LOG_ERR("Error (rsa verify): Digest lenght too big for RSA key "
			   "(digestLen[%u]; maxDigestLenForKey[%u])",
			   digestLen, maxDigestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}	
	
	if (operation->key_data->key_lenght != signatureLen) {
		OT_LOG_ERR("Error (rsa verify): Verify buffer short/big (provided[%u]; required[%u])",
			   operation->key_data->key_lenght, signatureLen);
		return TEE_ERROR_SHORT_BUFFER;
	}

	//OpenTEE internal sanity check. 
	rv_mbedtls = mbedtls_rsa_check_privkey(&operation->key_data->key.rsa.ctx);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: internal crypto error (RSA verify; RSA key corrupted)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_rsa_rsassa_pkcs1_v15_verify(&operation->key_data->key.rsa.ctx,
							 map_gp_pkcs_hash(operation->operation_info.algorithm),
							 digestLen,
							 digest,
							 signature);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal crypto error (RSA verify)");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_encrypt(TEE_OperationHandle operation,
				      void *srcData,
				      uint32_t srcLen,
				      void *destData,
				      uint32_t *destLen)
{	
	uint32_t maxSrcLen;
	int rv_mbedtls;

	maxSrcLen = operation->key_data->key_lenght - 11;

	if (srcLen == 0) {
		OT_LOG_ERR("Error (rsa encrypt): srcLen is 0");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcLen > maxSrcLen) {
		OT_LOG_ERR("Error (rsa encrypt): srcLen too big (provided[%u]; max[%u])",
			   srcLen, maxSrcLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->key_data->key_lenght > *destLen) {
		OT_LOG_ERR("Error (rsa encrypt): destLen too small (provided[%u]; required[%u])",
			   *destLen, operation->key_data->key_lenght);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	}

	rv_mbedtls = mbedtls_rsa_set_padding(&operation->key_data->key.rsa,
					     MBEDTLS_RSA_PKCS_V15, 0);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
		return TEE_ERROR_GENERIC;
	}
	
	rv_mbedtls = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&operation->key_data->key.rsa.ctx,
							 mbedtls_ctr_drbg_random,
							 &ot_mbedtls_ctr_drbg,
							 srcLen, srcData, destData);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA encrypt error (1)");
		return TEE_ERROR_GENERIC;
	} 

	*destLen = operation->key_data->key_lenght;
	return TEE_SUCCESS;
}

static TEE_Result do_rsa_pkcs_decrypt(TEE_OperationHandle operation,
				      void *srcData,
				      uint32_t srcLen,
				      void *destData,
				      uint32_t *destLen)
{
	int rv_mbedtls;

	if (srcLen != operation->key_data->key_lenght) {
		OT_LOG_ERR("Error (rsa decrypt): srcLen too big/small (provided[%u]; required[%u])",
			   srcLen, operation->key_data->key_lenght);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (*destLen > operation->key_data->key_lenght) {
		OT_LOG_ERR("Error (rsa decrypt): destLen too small (provided[%u]; required[%u])",
			   *destLen, operation->key_data->key_lenght);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	}
	
	rv_mbedtls = mbedtls_rsa_set_padding(&operation->key_data->key.rsa,
					     MBEDTLS_RSA_PKCS_V15, 0);
	if (rv_mbedtls) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
		return TEE_ERROR_GENERIC;
	}
		
	rv_mbedtls = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&operation->key_data->key.rsa.ctx,
							 mbedtls_ctr_drbg_random,
							 &ot_mbedtls_ctr_drbg,
							 destLen, srcData, destData, *destLen);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("ERROR: Internal RSA decrypt error (1)");
		return TEE_ERROR_GENERIC;
	} 
	
	return TEE_SUCCESS;
}


/*
 * crypto_asm.h functionality
 */
TEE_Result init_gp_asym(TEE_OperationHandle operation)
{
	int rv_mbedtls;
	
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		/*
		rv_mbedtls = mbedtls_rsa_set_padding(&operation->key_data->key.rsa,
						     MBEDTLS_RSA_PKCS_V15, 0);
		if (rv_mbedtls) {
			print_mbedtls_to_syslog(rv_mbedtls);
			OT_LOG_ERR("ERROR: Internal error when setting RSA padding");
			return TEE_ERROR_GENERIC;
			}*/
			
		break;
		
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		//Nothing
		break;
	default:
		OT_LOG_ERR("Not supported algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
	
	operation->operation_info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
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
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_ENCRYPT) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation mode NOT TEE_MODE_ENCRYPT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation "
			   "class NOT TEE_OPERATION_ASYMMETRIC_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	
	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return do_rsa_pkcs_encrypt(operation, srcData, srcLen, destData, destLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricEncrypt panics due not supported "
			   "algorithm [%u]", operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	OT_LOG_ERR("TEE_AsymmetricEncrypt something wrong (internal)");
	return TEE_ERROR_GENERIC;// Never end up here
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
				 TEE_Attribute *params,
				 uint32_t paramCount,
				 void *srcData,
				 uint32_t srcLen,
				 void *destData,
				 uint32_t *destLen)
{
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (srcData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due srcData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);	
	} else if (destData == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due destData NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);		
	} else if (destLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due destLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_DECRYPT) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation mode not TEE_MODE_DECRYPT");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation class not TEE_OPERATION_ASYMMETRIC_CIPHER");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		return do_rsa_pkcs_decrypt(operation, srcData, srcLen, destData, destLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricDecrypt panics due algorithm not supported [%u]",
			   operation->operation_info.algorithm);
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
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signatureLen == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due signatureLen NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signature == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due signature NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (digest == NULL) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due digest NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_SIGN) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation mode is not TEE_MODE_SIGN");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due "
			   "operation class is not TEE_OPERATION_ASYMMETRIC_SIGNATURE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due operation key is NOT set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} 
	
	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm)) {
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due digestLen mismatch "
			   "(expected[%u]; provided[%u])",
			   get_alg_hash_lenght(operation->operation_info.algorithm),
			   digestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_signature(operation, digest, digestLen, signature, signatureLen);
	default:
		OT_LOG_ERR("TEE_AsymmetricSignDigest panics due algorithm not supported "
			   "(algorithm[%u])",operation->operation_info.algorithm);
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
	if (operation == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (digest == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due digest NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (signature == NULL) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due signature NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_VERIFY) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation mode not TEE_MODE_VERIFY");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation "
			   "class not TEE_OPERATION_ASYMMETRIC_SIGNATURE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation not initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due operation key is not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (digestLen != get_alg_hash_lenght(operation->operation_info.algorithm)) {
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due digestLen mismatch "
			   "(expected[%u]; provided[%u])",
			   get_alg_hash_lenght(operation->operation_info.algorithm),
			   digestLen);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	switch (operation->operation_info.algorithm) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return do_rsa_pkcs_verify(operation, digest, digestLen, signature, signatureLen);

	default:
		OT_LOG_ERR("TEE_AsymmetricVerifyDigest panics due algorithm not supported "
			   "(algorithm[%u])",operation->operation_info.algorithm);
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}

	return TEE_ERROR_GENERIC; /* Never end up here */
}
