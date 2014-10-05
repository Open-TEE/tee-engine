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

#ifndef __TRUSTED_APP_PROPERTIES_H__
#define	__TRUSTED_APP_PROPERTIES_H__

#include "../internal_api/data_types.h"
#include "../include/trusted_app_properties.h"
#include "../manager/epoll_wrapper.h"

#define TA_MAX_FILE_NAME 255

struct trusted_app_properties {
	bool singleton_instance;
	bool instance_keep_alive;
	bool multi_session;
	TEE_UUID uuid;
	char ta_so_name[TA_MAX_FILE_NAME];
};

int init_ta_properti_notify();
void *get_ta_props(TEE_UUID *get_ta_uuid);
void handle_inotify_fd(struct epoll_event *e_event);

#endif /* __TRUSTED_APP_PROPERTIES_H__ */
