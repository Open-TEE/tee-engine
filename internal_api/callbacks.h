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

#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

struct internal_api_callbacks {
	/* Internal Client API needed callbacks */
	void *fn_ptr_open_ta_session;
	void *fn_ptr_close_ta_session;
	void *fn_ptr_invoke_ta_command;
	void *fn_ptr_invoke_mgr_command;

	/* Cancellation API */
	void *fn_ptr_get_cancel_flag;
	void *fn_ptr_mask_cancellation;
	void *fn_ptr_unmask_cancellation;
};

void reg_internal_api_callbacks(struct internal_api_callbacks *calls);

/* Internal Client API needed callbacks */
void *fn_ptr_open_ta_session();
void *fn_ptr_close_ta_session();
void *fn_ptr_invoke_ta_command();
void *fn_ptr_invoke_mgr_command();

/* Cancellation API */
void *fn_ptr_get_cancel_flag();
void *fn_ptr_mask_cancellation();
void *fn_ptr_unmask_cancellation();

#endif /* __CALLBACKS_H__ */
