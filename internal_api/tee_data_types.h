/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#ifndef __TEE_INTERNAL_DATA_TYPES_H__
#define __TEE_INTERNAL_DATA_TYPES_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../include/tee_shared_data_types.h"

typedef struct {
	uint32_t login;
	TEE_UUID uuid;
} TEE_Identity;


typedef union {
	struct {
		void* buffer;
		size_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;

typedef struct __TEE_TASessionHandle* TEE_TASessionHandle;

typedef struct __TEE_PropSetHandle* TEE_PropSetHandle;

/* clang-format off */
/* Paramater Types */
#define TEE_PARAM_TYPE_NONE		0x00000000
#define TEE_PARAM_TYPE_VALUE_INPUT	0x00000001
#define TEE_PARAM_TYPE_VALUE_OUTPUT	0x00000002
#define TEE_PARAM_TYPE_VALUE_INOUT	0x00000003
#define TEE_PARAM_TYPE_MEMREF_INPUT	0x00000005
#define TEE_PARAM_TYPE_MEMREF_OUTPUT	0x00000006
#define TEE_PARAM_TYPE_MEMREF_INOUT	0x00000007

/* Session Login Methods (core api) */
#define TEE_LOGIN_PUBLIC		0x00000000
#define TEE_LOGIN_USER			0x00000001
#define TEE_LOGIN_GROUP			0x00000002
#define TEE_LOGIN_APPLICATION		0x00000004
#define TEE_LOGIN_APPLICATION_USER	0x00000005
#define TEE_LOGIN_APPLICATION_GROUP	0x00000006
#define TEE_LOGIN_TRUSTED_APP		0xF0000000

/* Property Set Pseudo-Handle Constants */
#define TEE_PROPSET_CURRENT_TA		(TEE_PropSetHandle)0xFFFFFFFF
#define TEE_PROPSET_CURRENT_CLIENT	(TEE_PropSetHandle)0xFFFFFFFE
#define TEE_PROPSET_TEE_IMPLEMENTATION	(TEE_PropSetHandle)0xFFFFFFFD

#define TEE_ACCESS_READ			0x00000001
#define TEE_ACCESS_WRITE		0x00000002
#define TEE_ACCESS_ANY_OWNER		0x00000004

/* Memory Access Rights Constants */
#define TEE_MEMORY_ACCESS_READ		0x00000001
#define TEE_MEMORY_ACCESS_WRITE		0x00000002
#define TEE_MEMORY_ACCESS_ANY_OWNER	0x00000004

#define TEE_PARAM_TYPES(param0Type, param1Type, param2Type, param3Type) \
	((param0Type) | ((param1Type) << 4) | ((param2Type) << 8) | ((param3Type) << 12))

#define TEE_PARAM_TYPE_GET(paramsType, index) (((paramsType) >> (index * 4)) & 0xF)

/* Internal API: Table 6-10: List of Object Types */
typedef enum {
	TEE_TYPE_AES = 0xA0000010,
	TEE_TYPE_DES = 0xA0000011,
	TEE_TYPE_DES3 =	0xA0000013,
	TEE_TYPE_HMAC_MD5 = 0xA0000001,
	TEE_TYPE_HMAC_SHA1 = 0xA0000002,
	TEE_TYPE_HMAC_SHA224 = 0xA0000003,
	TEE_TYPE_HMAC_SHA256 = 0xA0000004,
	TEE_TYPE_HMAC_SHA384 = 0xA0000005,
	TEE_TYPE_HMAC_SHA512 = 0xA0000006,
	TEE_TYPE_RSA_PUBLIC_KEY = 0xA0000030,
	TEE_TYPE_RSA_KEYPAIR = 0xA1000030,
	TEE_TYPE_DSA_PUBLIC_KEY = 0xA0000031,
	TEE_TYPE_DSA_KEYPAIR = 0xA1000031,
	TEE_TYPE_DH_KEYPAIR = 0xA1000032,
	TEE_TYPE_ECDSA_PUBLIC_KEY = 0xA0000041,
	TEE_TYPE_ECDSA_KEYPAIR = 0xA1000041,
	TEE_TYPE_ECDH_PUBLIC_KEY = 0xA0000042,
	TEE_TYPE_ECDH_KEYPAIR = 0xA1000042,
	TEE_TYPE_GENERIC_SECRET = 0xA0000000,
	TEE_TYPE_CORRUPTED_OBJECT = 0xA00000BE,
	TEE_TYPE_DATA = 0xA00000BF
} object_type;

typedef enum {
	TEE_ATTR_SECRET_VALUE = 0xC0000000,
	TEE_ATTR_RSA_MODULUS = 0xD0000130,
	TEE_ATTR_RSA_PUBLIC_EXPONENT = 0xD0000230,
	TEE_ATTR_RSA_PRIVATE_EXPONENT = 0xC0000330,
	TEE_ATTR_RSA_PRIME1 = 0xC0000430,
	TEE_ATTR_RSA_PRIME2 = 0xC0000530,
	TEE_ATTR_RSA_EXPONENT1 = 0xC0000630,
	TEE_ATTR_RSA_EXPONENT2 = 0xC0000730,
	TEE_ATTR_RSA_COEFFICIENT = 0xC0000830,
	TEE_ATTR_DSA_PRIME = 0xD0001031,
	TEE_ATTR_DSA_SUBPRIME = 0xD0001131,
	TEE_ATTR_DSA_BASE = 0xD0001231,
	TEE_ATTR_DSA_PUBLIC_VALUE = 0xD0000131,
	TEE_ATTR_DSA_PRIVATE_VALUE = 0xC0000231,
	TEE_ATTR_DH_PRIME = 0xD0001032,
	TEE_ATTR_DH_SUBPRIME = 0xD0001132,
	TEE_ATTR_DH_BASE = 0xD0001232,
	TEE_ATTR_DH_X_BITS = 0xF0001332,
	TEE_ATTR_DH_PUBLIC_VALUE = 0xD0000132,
	TEE_ATTR_DH_PRIVATE_VALUE = 0xC0000232,
	TEE_ATTR_RSA_OAEP_LABEL = 0xD0000930,
	TEE_ATTR_RSA_PSS_SALT_LENGTH = 0xF0000A30,
	TEE_ATTR_ECC_PUBLIC_VALUE_X = 0xD0000141,
	TEE_ATTR_ECC_PUBLIC_VALUE_Y = 0xD0000241,
	TEE_ATTR_ECC_PRIVATE_VALUE = 0xC0000341,
	TEE_ATTR_ECC_CURVE = 0xF0000441
} obj_func_atribute;

typedef enum {
	TEE_ATTR_FLAG_VALUE = 0x20000000,
	TEE_ATTR_FLAG_PUBLIC = 0x10000000
} attr_id_flag;

typedef enum {
	TEE_ECC_CURVE_NIST_P192 = 0x00000001,
	TEE_ECC_CURVE_NIST_P224 = 0x00000002,
	TEE_ECC_CURVE_NIST_P256 = 0x00000003,
	TEE_ECC_CURVE_NIST_P384 = 0x00000004,
	TEE_ECC_CURVE_NIST_P521 = 0x00000005
} obj_ecc_curve;

/* clang-format on */
#endif
