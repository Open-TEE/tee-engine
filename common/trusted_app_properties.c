/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

/* Placeholder */

#include <string.h>
#include "trusted_app_properties.h"

static char *ta_path_and_name = "/home/tdettenb/code/opentee2/gcc-debug/libtest_applet.so";

int get_ta_properties(TEE_UUID *get_ta_uuid, struct trusted_app_properties *ta_properties)
{
	get_ta_uuid = get_ta_uuid;

	ta_properties->instance_keep_alive = false;
	ta_properties->singleton_instance = false;
	ta_properties->multi_session = false;
	memcpy(&ta_properties->ta_so_name_with_path, ta_path_and_name, MAX_TA_PATH_NAME);

	return 0;
}
