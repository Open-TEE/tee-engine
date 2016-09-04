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

#include <mbedtls/ctr_drbg.h>

#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "crypto_utils.h"
#include "tee_logging.h"

void TEE_GenerateRandom(void *randomBuffer,
			size_t randomBufferLen)
{
	if (randomBuffer == NULL) {
		OT_LOG_ERR("TEE_GenerateRandom panics due randomBuffer is NULL");
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	}
	
	if (mbedtls_ctr_drbg_random(&ot_mbedtls_ctr_drbg,
				    (unsigned char *)randomBuffer,
				    (size_t)randomBufferLen)) {
		OT_LOG_ERR("TEE_GenerateRandom panics due internal (mbedtls) error");
		TEE_Panic(TEE_ERROR_GENERIC);
	}
}
