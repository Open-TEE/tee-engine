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

#ifndef __TEE_PROCESS_MANAGER__
#define __TEE_PROCESS_MANAGER__

#include <stdint.h>

/*!
 * \brief proc_t
 * define an opaque structure to handle the process related information
 */
typedef struct __proc *proc_t;

/*!
 * \brief create_uninitialized_proc
 * Create an empty process structure.  This will be used when a client has connected but has not
 * yet initialized a session. As such we have little in the way of information about the client
 * other than a connected socket.
 * \param proc The process structure that is to be created
 * \param sockfd The connected socket to the client
 * \return 0 on success and proc will be non null
 */
int create_uninitialized_client_proc(proc_t *proc, int sockfd);

/*!
 * \brief pm_handle_connection
 * There has been some traffic on a file descriptor and we should handle it
 * \param events the events that occured to trigger the epoll event
 * \param proc_ptr a pointer to the process that has caused the wakeup
 */
void pm_handle_connection(uint32_t events, void *proc_ptr);

#endif
