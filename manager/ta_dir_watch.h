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
#define __TA_DIR_WATCH_H__

/*! \file ta_dir_watch.h
    \brief This is a bit stand alone module and it is only meant to use in OpenTEE manager process.
    How to use this module:
    1. Define variable for fd (probaly INT)
    2. Call ta_dir_watch_init()
    3. Have a loop where you have epoll_wait() function call
    4. If epoll event occurred (data in fd), call ta_dir_watch_event()
*/

#include "epoll_wrapper.h"
#include "tee_ta_properties.h"
#include "core_control_resources.h"

#define TA_MAX_FILE_NAME 255

/*!
 * \brief The trusted_app_propertie struct
 */
struct trusted_app_propertie {
	struct gpd_ta_config user_config;
	char ta_so_name[TA_MAX_FILE_NAME];
};

/*!
 * \brief ta_dir_watch_init
 * Initializes structeres and register structures
 * \param control_params Paramaters that control the core process
 * \param man_ta_dir_watch_fd Returns fd, which will be written if file system operation occured
 * \return On success 0
 */
int ta_dir_watch_init(struct core_control *control_params, int *man_ta_dir_watch_fd);

/*!
 * \brief ta_dir_watch_cleanup
 * Releases data structures and watchers
 */
void ta_dir_watch_cleanup();

/*!
 * \brief ta_dir_watch_event
 * Function handles inotification event.
 * \param e_event Epoll event for checking epoll status
 * \param man_ta_dir_watch_fd Manager ta_dir_watch notify fd. FD might get closed and then
 * re-init, if inotify overflow occurs
 */
void ta_dir_watch_event(struct epoll_event *e_event, int *man_ta_dir_watch_fd);

/*!
 * \brief ta_dir_watch_props
 * Return querried propertie. See example usage.
 * \param get_ta_uuid
 * \return NULL if ta not found
 *
 * \code
 * struct trusted_app_propertie *ta = NULL;
 *
 * if (ta_dir_watch_lock_mutex()) {
 *	ta = ta_dir_watch_props(uuid);
 *	if (!ta) {
 *		OT_LOG(LOG_ERR, "TA not found");
 *		ta_dir_watch_unlock_mutex();
 *		return;
 *	}
 *
 *	... Do something with ta propertie ...
 *	... TA data will not change if it proctected with mutex ...
 *
 *	ta_dir_watch_unlock_mutex();
 * }
 */
struct trusted_app_propertie *ta_dir_watch_props(TEE_UUID *get_ta_uuid);

/*!
 * \brief ta_dir_watch_lock_mutex
 * Use mutex for protecting ta dir watch data structure. See example above.
 * \return If mutex locked, return 0
 */
int ta_dir_watch_lock_mutex();

/*!
 * \brief ta_dir_watch_unlock_mutex
 * \return
 */
int ta_dir_watch_unlock_mutex();

#endif /* __TA_DIR_WATCH_H__ */
