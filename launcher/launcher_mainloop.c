/*****************************************************************************
** Copyright (C) 2013 Brian McGillion                                       **
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


#include "subprocess.h"
#include "syslog.h"

int lib_main_loop(sig_status_cb check_signal_status, int sockpair_fd)
{
	check_signal_status = check_signal_status;
	sockpair_fd = sockpair_fd;

	syslog(LOG_ERR, "Loaded the launcher application");

	while (1)
		;
}
