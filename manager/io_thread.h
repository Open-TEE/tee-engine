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

#ifndef __IO_THREAD__
#define __IO_THREAD__

#include "epoll_wrapper.h"
#include "extern_resources.h"

/*!
 * \brief free_manager_msg
 * Releases manager_msg structure
 * \param released_msg
 */
void free_manager_msg(struct manager_msg *released_msg);

/*!
 * \brief handle_done_queue
 * Done queue event fd has triggered epoll and it is sign that there is
 * something in done queue that need to be processed. Processed in this context
 * is meaning that message needs to send out.
 * \param event Epoll event
 */
void handle_done_queue(struct epoll_event *event);

/*!
 * \brief handle_public_fd
 * Handles new connection which is incomming to public fd.
 * \param event
 */
void handle_public_fd(struct epoll_event *event);

/*!
 * \brief read_fd_and_add_todo_queue
 * Reads message from fd and adding message to do queue.
 * \param event
 */
void read_fd_and_add_todo_queue(struct epoll_event *event);

/*!
 * \brief handle_close_sock
 * Closes a socket, which is used by logic thread
 * \param event
 */
void handle_close_sock(struct epoll_event *event);

#endif /* __IO_THREAD__ */
