/*****************************************************************************
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

#ifndef __TA_IO_THREAD_H__
#define __TA_IO_THREAD_H__

#include "epoll_wrapper.h"
#include "ta_ctl_resources.h"

/*!
 * \brief free_task
 * Releases ta_task structure
 * \param released_task
 */
void free_task(struct ta_task *released_task);

/*!
 * \brief receive_from_manager
 * Receive a message from manager socket and place message todo queue
 * \param event Manager socket fd
 * \param man_sockfd
 */
void receive_from_manager(struct epoll_event *event, int man_sockfd);

/*!
 * \brief reply_to_manager
 * Take a done queue message and send it to manager
 * \param event event_fd
 * \param man_sockfd
 */
void reply_to_manager(struct epoll_event *event, int man_sockfd);

#endif /* __TA_IO_THREAD_H__ */
