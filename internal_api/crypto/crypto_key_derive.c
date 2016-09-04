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

#include "tee_crypto_api.h"
#include "tee_panic.h"
#include "tee_logging.h"

void TEE_DeriveKey(TEE_OperationHandle operation,
		   TEE_Attribute *params,
		   uint32_t paramCount,
		   TEE_ObjectHandle derivedKey)
{
	// TODO: Function
	
	OT_LOG_ERR("TEE_DeriveKey panics due not implemented");

	TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
}
