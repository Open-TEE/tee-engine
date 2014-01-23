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

#include <syslog.h>
#include <stdlib.h>

#include "ta_process.h"
#include "dynamic_loader.h"

int ta_process_loop(const char *lib_path, int sockfd)
{
	TEEC_Result ret;
	struct ta_interface *interface;

	ret = load_ta(lib_path, &interface);
	if (ret != TEE_SUCCESS) {
		/* TODO write the error to the sockfd so the manager is notified and can notify
		 * the client application.
		 */
		syslog(LOG_ERR, "Failed to load the TA");
		exit(1);
	}

	/* Should never reach here */
	return -1;
}
