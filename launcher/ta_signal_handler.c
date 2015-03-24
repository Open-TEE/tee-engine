/*****************************************************************************
** Copyright (C) 2015 Tanel Dettenborn.                                     **
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

#include <signal.h>
#include "ta_signal_handler.h"

void ta_signal_handler(struct core_control *control_params)
{
	/* Copy signal vector and reset self pipe so we do not miss any events */
	sig_atomic_t cpy_sig_vec = control_params->sig_vector;

	control_params->reset_signal_self_pipe();

	/* Do the signal handling */

	cpy_sig_vec = cpy_sig_vec;
}
