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

#ifndef __IO_THREAD_TUI__
#define __IO_THREAD_TUI__

//#include "core_control_resources.h"
#include "epoll_wrapper.h"
#include "extern_resources.h"
#include <stdbool.h>


/*!
 * \brief is_tui_socket_fd
 * Tells if given socket is a trusted ui socket
 * \param socketfd File descriptor to be tested
 */
bool is_tui_socket_fd(int socketfd);

/*!
 * \brief accept_tui_display_fd
 * Handle new connection to Trusted UI Display socket.
 * \param event
 */
void accept_tui_display_fd(struct epoll_event *event);

/*!
 * \brief accept_tui_display_fd
 * Handle data from Trusted UI Display socket.
 * \param event
 */
void handle_tui_display_data(struct epoll_event *event);

#endif /* __IO_THREAD_TUI__ */
