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

#ifndef __TEE_SOCKET_HELP_H__
#define __TEE_SOCKET_HELP_H__

#include <sys/types.h>
#include <sys/socket.h>

struct control_fd {
	struct cmsghdr header;
	int fd;
};

/*!
 * \brief send_fd
 * Send a file descriptor over a socket to another process
 * \param sockfd The socket to use for transport
 * \param fd_to_send The fd to be sent
 * \return 0 on success, -1 othersie
 */
int send_fd(int sockfd, int fd_to_send);

/*!
 * \brief recv_fd
 * receive a file descriptior from another process over a socket
 * \param sockfd The socket connected to the other process
 * \param recvd_fd The fd to receive
 * \return 0 on success, -1 otherwise
 */
int recv_fd(int sockfd, int *recvd_fd);

#endif
