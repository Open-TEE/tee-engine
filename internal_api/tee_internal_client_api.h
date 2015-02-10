/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#ifndef __TEE_INTERNAL_CLIENT_API_H__
#define __TEE_INTERNAL_CLIENT_API_H__

#include "tee_data_types.h"
#include "com_protocol.h" /* MRG_Payload */

TEE_Result TEE_OpenTASession(TEE_UUID *destination, uint32_t cancellationRequestTimeout,
			     uint32_t paramTypes, TEE_Param params[4],
			     TEE_TASessionHandle *session, uint32_t *returnOrigin);

void TEE_CloseTASession(TEE_TASessionHandle session);

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session, uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes, TEE_Param params[4],
			       uint32_t *returnOrigin);

/* brief!
 * makes call to manager, with payloads to send and receive
 *
 * commandID - command to manager
 * payload - data to pass to command
 * returnPayload - if payload is returned, caller of this function need to free returnPayload->data
 * returnOrigin - error status from the command executed by manager
 */

TEE_Result TEE_InvokeMGRCommand(uint32_t cancellationRequestTimeout,
			       uint32_t commandID,
				   MGR_Payload *payload,
				   MGR_Payload *returnPayload,
				   TEE_Result *returnOrigin);

#endif /* __TEE_INTERNAL_CLIENT_API_H__ */
