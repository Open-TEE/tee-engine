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

#ifndef __TEE_CRYPTO_API_H__
#define __TEE_CRYPTO_API_H__

#include <stdbool.h>

#include "tee_data_types.h"
#include "tee_storage_api.h"

/*
 * ## Data types ##
 */

typedef enum {
	TEE_MODE_ENCRYPT = 0,
	TEE_MODE_DECRYPT = 1,
	TEE_MODE_SIGN = 2,
	TEE_MODE_VERIFY = 3,
	TEE_MODE_MAC = 4,
	TEE_MODE_DIGEST = 5,
	TEE_MODE_DERIVE = 6
} TEE_OperationMode;

typedef struct {
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t keySize;
	uint32_t requiredKeyUsage;
	uint32_t handleState;
} TEE_OperationInfo;

typedef struct {
	uint32_t keySize;
	uint32_t requiredKeyUsage;
} TEE_OperationInfoKey;

typedef struct {
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t handleState;
	uint32_t operationState;
	uint32_t numberOfKeys;
	TEE_OperationInfoKey keyInformation[1]; /* why one? */
} TEE_OperationInfoMultiple;

typedef struct __TEE_OperationHandle *TEE_OperationHandle;

/*
 * ## Generic Operation Functions ##
 */

/*!
 * \brief TEE_AllocateOperation
 * \param operation
 * \param algorithm
 * \param mode
 * \param maxKeySize
 * \return
 */
TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation, uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize);

/*!
 * \brief TEE_FreeOperation
 * \param operation
 */
void TEE_FreeOperation(TEE_OperationHandle operation);

/*!
 * \brief TEE_GetOperationInfo
 * \param operation
 * \param operationInfo
 */
void TEE_GetOperationInfo(TEE_OperationHandle operation, TEE_OperationInfo *operationInfo);

/*!
 * \brief TEE_GetOperationInfoMultiple
 * \param operation
 * \param operationInfoMultiple
 * \param operationSize
 * \return
 */
TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
					TEE_OperationInfoMultiple *operationInfoMultiple,
					uint32_t *operationSize);

/*!
 * \brief TEE_ResetOperation
 * \param operation
 */
void TEE_ResetOperation(TEE_OperationHandle operation);

/*!
 * \brief TEE_SetOperationKey
 * \param operation
 * \param key
 * \return
 */
TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation, TEE_ObjectHandle key);

/*!
 * \brief TEE_SetOperationKey2
 * \param operation
 * \param key1
 * \param key2
 * \return
 */
TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation, TEE_ObjectHandle key1,
				TEE_ObjectHandle key2);

/*!
 * \brief TEE_CopyOperation
 * \param dstOperation
 * \param srcOperation
 */
void TEE_CopyOperation(TEE_OperationHandle dstOperation, TEE_OperationHandle srcOperation);

/*
 * ## Message Digest Functions ##
 */

/*!
 * \brief TEE_DigestUpdate
 * \param operation
 * \param chunk
 * \param chunkSize
 */
void TEE_DigestUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize);

/*!
 * \brief TEE_DigestDoFinal
 * \param operation
 * \param chunk
 * \param chunkLen
 * \param hash
 * \param hashLen
 * \return
 */
TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, void *chunk, uint32_t chunkLen,
			     void *hash, uint32_t *hashLen);

/*
 * ## Symmetric Cipher Functions ##
 */

/*!
 * \brief TEE_CipherInit
 * \param operation
 * \param IV
 * \param IVLen
 */
void TEE_CipherInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen);

/*!
 * \brief TEE_CipherUpdate
 * \param operation
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \return
 */
TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			    void *destData, uint32_t *destLen);

/*!
 * \brief TEE_CipherDoFinal
 * \param operation
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \return
 */
TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			     void *destData, uint32_t *destLen);

/*
 * ## MAC Functions ##
 */

/*!
 * \brief TEE_MACInit
 * \param operation
 * \param IV
 * \param IVLen
 */
void TEE_MACInit(TEE_OperationHandle operation, void *IV, uint32_t IVLen);

/*!
 * \brief TEE_MACUpdate
 * \param operation
 * \param chunk
 * \param chunkSize
 */
void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, uint32_t chunkSize);

/*!
 * \brief TEE_MACComputeFinal
 * \param operation
 * \param message
 * \param messageLen
 * \param mac
 * \param macLen
 * \return
 */
TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation, void *message, uint32_t messageLen,
			       void *mac, uint32_t *macLen);

/*!
 * \brief TEE_MACCompareFinal
 * \param operation
 * \param message
 * \param messageLen
 * \param mac
 * \param macLen
 * \return
 */
TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, void *message, uint32_t messageLen,
			       void *mac, uint32_t macLen);

/*
 * ## Authenticated Encryption Functions (GB TEE AE API is not supported!) ##
 */

/*!
 * \brief TEE_AEInit
 * \param operation
 * \param nonce
 * \param nonceLen
 * \param tagLen
 * \param AADLen
 * \param payloadLen
 * \return
 */
TEE_Result TEE_AEInit(TEE_OperationHandle operation, void *nonce, uint32_t nonceLen,
		      uint32_t tagLen, uint32_t AADLen, uint32_t payloadLen);

/*!
 * \brief TEE_AEUpdateAAD
 * \param operation
 * \param AADdata
 * \param AADdataLen
 */
void TEE_AEUpdateAAD(TEE_OperationHandle operation, void *AADdata, uint32_t AADdataLen);

/*!
 * \brief TEE_AEUpdate
 * \param operation
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \return
 */
TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			void *destData, uint32_t *destLen);

/*!
 * \brief TEE_AEEncryptFinal
 * \param operation
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \param tag
 * \param tagLen
 * \return
 */
TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag, uint32_t *tagLen);

/*!
 * \brief TEE_AEDecryptFinal
 * \param operation
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \param tag
 * \param tagLen
 * \return
 */
TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation, void *srcData, uint32_t srcLen,
			      void *destData, uint32_t *destLen, void *tag, uint32_t tagLen);

/*
 * ## Asymmetric Functions ##
 */

/*!
 * \brief TEE_AsymmetricEncrypt
 * \param operation
 * \param params
 * \param paramCount
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \return
 */
TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation, TEE_Attribute *params,
				 uint32_t paramCount, void *srcData, uint32_t srcLen,
				 void *destData, uint32_t *destLen);

/*!
 * \brief TEE_AsymmetricDecrypt
 * \param operation
 * \param params
 * \param paramCount
 * \param srcData
 * \param srcLen
 * \param destData
 * \param destLen
 * \return
 */
TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation, TEE_Attribute *params,
				 uint32_t paramCount, void *srcData, uint32_t srcLen,
				 void *destData, uint32_t *destLen);

/*!
 * \brief TEE_AsymmetricSignDigest
 * \param operation
 * \param params
 * \param paramCount
 * \param digest
 * \param digestLen
 * \param signature
 * \param signatureLen
 * \return
 */
TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation, TEE_Attribute *params,
				    uint32_t paramCount, void *digest, uint32_t digestLen,
				    void *signature, uint32_t *signatureLen);

/*!
 * \brief TEE_AsymmetricVerifyDigest
 * \param operation
 * \param params
 * \param paramCount
 * \param digest
 * \param digestLen
 * \param signature
 * \param signatureLen
 * \return
 */
TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation, TEE_Attribute *params,
				      uint32_t paramCount, void *digest, uint32_t digestLen,
				      void *signature, uint32_t signatureLen);

/*
 * ## Key Derivation Functions ##
 */

/*!
 * \brief TEE_DeriveKey
 * \param operation
 * \param params
 * \param paramCount
 * \param derivedKey
 */
void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params, uint32_t paramCount,
		   TEE_ObjectHandle derivedKey);

/*
 * ## Random Data Generation Function ##
 */

/*!
 * \brief TEE_GenerateRandom
 * \param randomBuffer
 * \param randomBufferLen
 */
void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen);

/*
 * ## Cryptographic Algorithms Specification ##
 */

typedef enum {
	TEE_ALG_AES_ECB_NOPAD = 0x10000010,
	TEE_ALG_AES_CBC_NOPAD = 0x10000110,
	TEE_ALG_AES_CTR = 0x10000210,
	TEE_ALG_AES_CTS = 0x10000310,
	TEE_ALG_AES_XTS = 0x10000410,
	TEE_ALG_AES_CBC_MAC_NOPAD = 0x30000110,
	TEE_ALG_AES_CBC_MAC_PKCS5 = 0x30000510,
	TEE_ALG_AES_CMAC = 0x30000610,
	TEE_ALG_AES_CCM = 0x40000710,
	TEE_ALG_AES_GCM = 0x40000810,
	TEE_ALG_DES_ECB_NOPAD = 0x10000011,
	TEE_ALG_DES_CBC_NOPAD = 0x10000111,
	TEE_ALG_DES_CBC_MAC_NOPAD = 0x30000111,
	TEE_ALG_DES_CBC_MAC_PKCS5 = 0x30000511,
	TEE_ALG_DES3_ECB_NOPAD = 0x10000013,
	TEE_ALG_DES3_CBC_NOPAD = 0x10000113,
	TEE_ALG_DES3_CBC_MAC_NOPAD = 0x30000113,
	TEE_ALG_DES3_CBC_MAC_PKCS5 = 0x30000513,
	TEE_ALG_RSASSA_PKCS1_V1_5_MD5 = 0x70001830,
	TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 = 0x70002830,
	TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 = 0x70003830,
	TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830,
	TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 = 0x70005830,
	TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 = 0x70006830,
	TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 = 0x70212930,
	TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 = 0x70313930,
	TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 = 0x70414930,
	TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 = 0x70515930,
	TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 = 0x70616930,
	TEE_ALG_RSAES_PKCS1_V1_5 = 0x60000130,
	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 = 0x60210230,
	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 = 0x60310230,
	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 = 0x60410230,
	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 = 0x60510230,
	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 = 0x60610230,
	TEE_ALG_RSA_NOPAD = 0x60000030,
	TEE_ALG_DSA_SHA1 = 0x70002131,
	TEE_ALG_DH_DERIVE_SHARED_SECRET = 0x80000032,
	TEE_ALG_MD5 = 0x50000001,
	TEE_ALG_SHA1 = 0x50000002,
	TEE_ALG_SHA224 = 0x50000003,
	TEE_ALG_SHA256 = 0x50000004,
	TEE_ALG_SHA384 = 0x50000005,
	TEE_ALG_SHA512 = 0x50000006,
	TEE_ALG_HMAC_MD5 = 0x30000001,
	TEE_ALG_HMAC_SHA1 = 0x30000002,
	TEE_ALG_HMAC_SHA224 = 0x30000003,
	TEE_ALG_HMAC_SHA256 = 0x30000004,
	TEE_ALG_HMAC_SHA384 = 0x30000005,
	TEE_ALG_HMAC_SHA512 = 0x30000006,
} algorithm_Identifier;

#endif /* __TEE_CRYPTO_API_H__ */
