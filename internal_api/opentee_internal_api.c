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
