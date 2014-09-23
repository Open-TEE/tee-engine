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

#ifndef __TA_ELF_STUFF__
#define __TA_ELF_STUFF__

#include "general_data_types.h"

#define MAX_TA_PATH_NAME 255

struct trusted_app_properties {
	bool singleton_instance;
	bool instance_keep_alive;
	bool multi_session;
	TEE_UUID uuid;
	char ta_so_name_with_path[MAX_TA_PATH_NAME];
};

/* Retun 1, if TA is not found at TA folder */
int get_ta_properties(TEE_UUID *get_ta_uuid, struct trusted_app_properties *ta_properties);

#endif /* __TA_ELF_STUFF__ */
