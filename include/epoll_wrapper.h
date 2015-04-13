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

#ifndef __TEE_EPOLL_WRAPPER__
#define __TEE_EPOLL_WRAPPER__

#include <sys/epoll.h>
#include <stdint.h>

/*!
 * \brief init_epoll
 * Create an epoll instance that can be monitored
 * \return 0 on success, -1 otherwise
 */
int init_epoll();

/*!
 * \brief epoll_reg
 * Register a file descriptor for monitoring by epoll
 * \param fd The file descriptor to register, which will be also stored in data
 * \param events The epoll events to listen for
 * \return 0 on success -1 otherwise
 */
int epoll_reg_fd(int fd, uint32_t events);

/*!
 * \brief epoll_reg_data
 * Register a file descriptor with epoll and store the data in data.ptr
 * \param fd The file descriptor to monitor
 * \param events The events on the descriptor to monitor
 * \param data The data to be stored in the data.ptr element, which will be checked on return
 * \return 0 on success -1 otherwise
 */
int epoll_reg_data(int fd, uint32_t events, void *data);

/*!
 * \brief epoll_unreg
 * Unregister a file descriptor from listening.
 * \param fd The file descriptor that we are no longer interested in
 * \return 0 in success, -1 otherwise
 */
int epoll_unreg(int fd);

/*!
 * \brief wrap_epoll_wait
 * Call a blocking wait for an epoll event to occur on of of the monitored descriptors
 * \param events The events that are currently active in the epoll monitor
 * \param max_events The max number of events to return in a single go
 * \return 0 on success
 */
int wrap_epoll_wait(struct epoll_event *events, int max_events);

/*!
 * \brief cleanup_epoll
 * Releasing resources that epoll is reserved
 */
void cleanup_epoll();

#endif
