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

#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "../tee_crypto_api.h"
#include "../tee_data_types.h"

#define BITS_TO_BYTES(bits) (bits / 8)
#define BYTES_TO_BITS(bytes) (bytes * 8)

extern mbedtls_entropy_context ot_mbedtls_entropy;
extern mbedtls_ctr_drbg_context ot_mbedtls_ctr_drbg;

int valid_mode_and_algorithm(uint32_t algorithm, uint32_t mode);

bool valid_key_size_for_algorithm(uint32_t algorithm, uint32_t key);

bool supported_algorithms(uint32_t algorithm, uint32_t key_size);

uint32_t get_operation_class(uint32_t algorithm);

bool alg_requires_2_keys(uint32_t algorithm);

uint32_t get_alg_hash_lenght(uint32_t algorithm);

TEE_Result valid_key_and_operation(TEE_ObjectHandle key, TEE_OperationHandle operation);

void print_mbedtls_to_syslog(int mbedtls_error);

#endif
