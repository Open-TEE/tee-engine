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

#ifndef __CRYPTO_CIPHER_H__
#define __CRYPTO_CIPHER_H__

#include "tee_crypto_api.h"
#include "tee_shared_data_types.h"

TEE_Result init_gp_cipher(TEE_OperationHandle operation);

void free_gp_cipher(TEE_OperationHandle operation);

void reset_gp_cipher(TEE_OperationHandle operation);

void assign_key_cipher(TEE_OperationHandle operation, TEE_ObjectHandle key);

#endif /* __CRYPTO_CIPHER_H__ */
