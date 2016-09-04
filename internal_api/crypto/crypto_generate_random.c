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

#include "../tee_crypto_api.h"
#include "../tee_panic.h"

void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen)
{
	if (randomBuffer == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	/* TODO: What is different rdrand vs crypto_drng
	 * rdrand(randomBuffer,randomBufferLen);*/
	if (crypto_drng(randomBufferLen, (uint8_t *)randomBuffer))
		TEE_Panic(TEE_ERROR_GENERIC);
}
