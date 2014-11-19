/*****************************************************************************
** Copyright (C) 2014 Brian McGillion.                                      **
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

#ifndef __TEE_TA_PROCESS_H__
#define __TEE_TA_PROCESS_H__

#include "com_protocol.h"
#include "core_control_resources.h"

/*!
 * \brief The ta_loop_arg struct
 * Clone is accepting one function parameter.
 */
struct ta_loop_arg {
	/*! The control paramters that are used to manage the core processes */
	struct core_control *ctl_params;
	/*! The socket on which to communicate with the manager */
	int com_sock;
	/*! session message from CA or TA */
	void *recv_open_msg;
};

/*!
 * \brief ta_process_loop
 * The main loop of the TA process. Ta_process_loop function is TA execution entry function
 * \param arg \sa struct ta_loop_arg
 * \return should never return
 */
int ta_process_loop(void *arg);

#endif
