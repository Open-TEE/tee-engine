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

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>

#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "tee_logging.h"
#include "crypto_utils.h"
#include "operation_handle.h"
#include "storage/object_handle.h"
#include "storage/storage_utils.h"

void TEE_DeriveKey(TEE_OperationHandle operation,
		   TEE_Attribute *params,
		   uint32_t paramCount,
		   TEE_ObjectHandle derivedKey)
{
	mbedtls_mpi z, d;
	mbedtls_ecp_point Q;
	int rv_mbedtls;

	TEE_Attribute *derivedKey_x, *derivedKey_y,
		*generic_sec_attr, *operation_d;
	
	
	if (!operation) {
		OT_LOG_ERR("TEE_DeriveKey panics due operation NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!params) {
		OT_LOG_ERR("TEE_DeriveKey panics due params NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!derivedKey) {
		OT_LOG_ERR("TEE_DeriveKey panics due derivedKey NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.operationClass != TEE_OPERATION_KEY_DERIVATION) {
		OT_LOG_ERR("TEE_DeriveKey panics due operation class not TEE_OPERATION_KEY_DERIVATION");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (operation->operation_info.mode != TEE_MODE_DERIVE) {
		OT_LOG_ERR("TEE_DeriveKey panics due operation mode not TEE_MODE_DERIVE");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (!(operation->operation_info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		OT_LOG_ERR("TEE_DeriveKey panics due operation key not set");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (derivedKey->objectInfo.objectType != TEE_TYPE_GENERIC_SECRET) {
		OT_LOG_ERR("TEE_DeriveKey panics due derivedKey object type not TEE_TYPE_GENERIC_SECRET");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	} else if (derivedKey->objectInfo.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		OT_LOG_ERR("TEE_DeriveKey panics due derivedKey already initialized");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	if (operation->key_data->key_lenght > derivedKey->key->key_max_length) {
		OT_LOG_ERR("TEE_DeriveKey panics due derivedKey key too big");
		TEE_Panic(TEE_ERROR_SHORT_BUFFER);
	}

	operation_d = get_attr_from_attrArr(TEE_ATTR_ECC_PRIVATE_VALUE,
					    operation->key_data->gp_attrs.attrs,
					    operation->key_data->gp_attrs.attrs_count);
	generic_sec_attr = get_attr_from_attrArr(TEE_ATTR_SECRET_VALUE,
						 derivedKey->key->gp_attrs.attrs,
						 derivedKey->key->gp_attrs.attrs_count);
	derivedKey_x = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_X, params, paramCount);
	derivedKey_y = get_attr_from_attrArr(TEE_ATTR_ECC_PUBLIC_VALUE_Y, params, paramCount);
	if (!derivedKey_x || !derivedKey_y) {
		OT_LOG_ERR("TEE_DeriveKey panics due missing mandatory parameter "
		       "(TEE_ATTR_ECC_PUBLIC_VALUE_X[%p]; TEE_ATTR_ECC_PUBLIC_VALUE_Y[%p])",
		       derivedKey_x, derivedKey_y);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}

	//Opentee internal sanity check
	if (!generic_sec_attr || !operation_d) {
		OT_LOG_ERR("Missing component (TEE_ATTR_SECRET_VALUE[%p]; "
			   "TEE_ATTR_ECC_PRIVATE_VALUE[%p]",generic_sec_attr, operation_d);
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	mbedtls_mpi_init(&z);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	mbedtls_mpi_lset(&Q.private_Z, 1);
	rv_mbedtls = mbedtls_mpi_read_binary(&Q.private_X, derivedKey_x->content.ref.buffer, derivedKey_x->content.ref.length);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Out of memory (ECDH public X)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	rv_mbedtls = mbedtls_mpi_read_binary(&Q.private_Y, derivedKey_y->content.ref.buffer, derivedKey_y->content.ref.length);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Out of memory (ECDH public Y)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_mpi_read_binary(&d, operation_d->content.ref.buffer, operation_d->content.ref.length);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Out of memory usable (ECDH private component)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
 
	//Opentee internal sanity check
	rv_mbedtls = mbedtls_ecp_check_pubkey(operation->ctx.ecc.grp, &Q);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Public key not usable (ECDH public)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	//Opentee internal sanity check
	rv_mbedtls = mbedtls_ecp_check_privkey(operation->ctx.ecc.grp, &d);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Private key not usable (ECDH private)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
	
	rv_mbedtls = mbedtls_ecdh_compute_shared(operation->ctx.ecc.grp,
						 &z,
						 &Q,
						 &d,
						 mbedtls_ctr_drbg_random,
						 &ot_mbedtls_ctr_drbg);
	if (rv_mbedtls != 0) {
		print_mbedtls_to_syslog(rv_mbedtls);
		OT_LOG_ERR("Something went wrong (ECDH shared)");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	generic_sec_attr->content.ref.length = mbedtls_mpi_size(&z);
	if (mbedtls_mpi_write_binary(&z, generic_sec_attr->content.ref.buffer, generic_sec_attr->content.ref.length)) {
		OT_LOG(LOG_ERR, "Panicking due mbedtls_mpi_read_binary failed");
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	derivedKey->objectInfo.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	derivedKey->objectInfo.keySize = BYTES_TO_BITS((uint32_t)mbedtls_mpi_size(&z));
	derivedKey->key->reference_count++;
	derivedKey->key->key_lenght = (uint32_t)mbedtls_mpi_size(&z);

	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Q);
}
