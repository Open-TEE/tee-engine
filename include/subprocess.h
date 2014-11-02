/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#ifndef __TEE_SUBPROCESS_H__
#define __TEE_SUBPROCESS_H__

#include "core_control_resources.h"

typedef int (*main_loop_cb)(struct core_control *control_paramaters);

/*!
 * \brief lib_main_loop
 * This is the main processing loop of the library that is being loaded.
 * \param control_paramaters Paramaters that define the running of the core processes
 * \return This function should never return unless a major error occurs, and then -1.
 */
int lib_main_loop(struct core_control *control_paramaters);

#endif
