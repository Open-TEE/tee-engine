/*****************************************************************************
** Copyright (C) 2014 Tanel Dettenborn.	                                    **
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

#include "callbacks.h"
#include "tee_cancellation.h"
#include "tee_logging.h"
#include "tee_panic.h"

bool TEE_GetCancellationFlag(void)
{
	bool (*get_cancellation_flag)() = fn_ptr_get_canel_flag();

	return get_cancellation_flag() ? false : true;
}

bool TEE_UnmaskCancellation(void)
{
	bool (*unmask_cancelation)() = fn_ptr_unmask_cancellation();

	return unmask_cancelation();
}

bool TEE_MaskCancellation(void)
{
	bool (*mask_cancelation)() = fn_ptr_mask_cancellation();

	return mask_cancelation();
}
