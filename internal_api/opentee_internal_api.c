/*****************************************************************************
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

#include "opentee_internal_api.h"
#include "callbacks.h"

TEE_Result TEE_InvokeMGRCommand(uint32_t cancellationRequestTimeout, uint32_t commandID,
				struct com_mgr_invoke_cmd_payload *payload,
				struct com_mgr_invoke_cmd_payload *returnPayload)
{

	TEE_Result (*invoke_mgr_command)(uint32_t cancellationRequestTimeout, uint32_t commandID,
					 struct com_mgr_invoke_cmd_payload *payload,
					 struct com_mgr_invoke_cmd_payload *returnPayload) =
	    fn_ptr_invoke_mgr_command();

	return invoke_mgr_command(cancellationRequestTimeout, commandID, payload, returnPayload);
}
