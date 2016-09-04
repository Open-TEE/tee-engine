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

#ifndef __CRYPTO_ASYM_H__
#define __CRYPTO_ASYM_H__

#include <mbedtls/rsa.h>
#include "tee_crypto_api.h"
#include "tee_shared_data_types.h"

// mbedtls RSA key components sizes. NOTE: How we did get these values? It was done by generating
// RSA key with mbedtls and then calculated sizes from generated key.
#define mbedtls_RSA_LONGEST_COMPONENT(modulo)	(modulo)
#define mbedtls_RSA_PUBLIC_EXP_t		int
#define mbedtls_RSA_PUBLIC_EXP			sizeof(mbedtls_RSA_PUBLIC_EXP_t)
#define mbedtls_RSA_PRIVATE_EXP(modulo)		(modulo / 2)
#define mbedtls_RSA_PRIME_1(modulo)		(modulo / 2)
#define mbedtls_RSA_PRIME_2(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_1(modulo)		(modulo / 2)
#define mbedtls_RSA_EXPONENT_2(modulo)		(modulo / 2)
#define mbedtls_RSA_COEFFICIENT(modulo)		(modulo / 2)

struct rsa_components {
	TEE_Attribute *modulo;
	TEE_Attribute *public_exp;
	TEE_Attribute *private_exp;
	TEE_Attribute *prime1;
	TEE_Attribute *prime2;
	TEE_Attribute *coff;
	TEE_Attribute *exp1;
	TEE_Attribute *exp2;
};

TEE_Result init_gp_asym(TEE_OperationHandle operation);

void free_gp_asym(TEE_OperationHandle operation);

bool assign_rsa_key_to_ctx(TEE_Attribute *attrs, uint32_t attrCount,
			   mbedtls_rsa_context *ctx,
			   uint32_t rsa_obj_type);

void get_valid_rsa_components(TEE_Attribute *attrs, uint32_t attrCount,
			      struct rsa_components *rsa_comps);

#endif /* __CRYPTO_ASYM_H__ */
