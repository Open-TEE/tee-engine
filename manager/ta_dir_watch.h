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

#ifndef __TA_DIR_WATCH_H__
#define	__TA_DIR_WATCH_H__

#include "epoll_wrapper.h"
#include "tee_ta_propertie.h"

#define TA_MAX_FILE_NAME 255

struct trusted_app_propertie {
	struct gpd_ta_config user_config;
	char ta_so_name[TA_MAX_FILE_NAME];
};

int init_ta_dir_watch(int *man_ta_dir_watch_fd);
void ta_watch_cleanup();
void handle_dir_watch_fd(struct epoll_event *e_event, int *man_ta_dir_watch_fd);
void *get_ta_props(TEE_UUID *get_ta_uuid);
int	lock_ta_watch_mutex();
int unlock_ta_watch_mutex();

#endif /* __TA_DIR_WATCH_H__ */
