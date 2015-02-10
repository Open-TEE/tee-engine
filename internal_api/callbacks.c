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

#include <string.h>

#include "callbacks.h"

static struct internal_api_callbacks callbacks;

void reg_internal_api_callbacks(struct internal_api_callbacks *calls)
{
	memcpy(&callbacks, calls, sizeof(struct internal_api_callbacks));
}

void *fn_ptr_open_ta_session()
{
	return callbacks.fn_ptr_open_ta_session;
}

void *fn_ptr_close_ta_session()
{
	return callbacks.fn_ptr_close_ta_session;
}

void *fn_ptr_invoke_ta_command()
{
	return callbacks.fn_ptr_invoke_ta_command;
}

void *fn_ptr_invoke_mgr_command()
{
	return callbacks.fn_ptr_invoke_mgr_command;
}

void *fn_ptr_get_cancel_flag()
{
	return callbacks.fn_ptr_get_cancel_flag;
}

void *fn_ptr_mask_cancellation()
{
	return callbacks.fn_ptr_mask_cancellation;
}

void *fn_ptr_unmask_cancellation()
{
	return callbacks.fn_ptr_unmask_cancellation;
}
