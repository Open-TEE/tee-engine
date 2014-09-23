/*****************************************************************************
** Copyright (C) 2014 Intel Corperation.                                    **
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

#include "socket_help.h"

#include <string.h>

int send_fd(int sockfd, int fd_to_send)
{
	struct msghdr msg_head;
	struct iovec iov;
	struct control_fd anc_load;
	char dummy = 'T';

	memset(&msg_head, 0, sizeof(struct msghdr));

	iov.iov_base = &dummy;
	iov.iov_len = sizeof(char);

	/* add 1 iov buffer to the header */
	msg_head.msg_iov = &iov;
	msg_head.msg_iovlen = 1;

	anc_load.header.cmsg_type = SCM_RIGHTS;
	anc_load.header.cmsg_len = CMSG_LEN(sizeof(int));
	anc_load.header.cmsg_level = SOL_SOCKET;

	msg_head.msg_control = &anc_load;
	msg_head.msg_controllen = CMSG_SPACE(sizeof(int));
	*((int *)CMSG_DATA(CMSG_FIRSTHDR(&msg_head))) = fd_to_send;

	return sendmsg(sockfd, &msg_head, 0) == -1 ? -1 : 0;
}

int recv_fd(int sockfd, int *recvd_fd)
{
	struct msghdr msg_head;
	struct iovec iov;
	struct control_fd anc_load;
	char dummy;
	int ret = 0;
	struct cmsghdr *recv_cont;

	iov.iov_base = &dummy;
	iov.iov_len = sizeof(char);

	/* add 1 iov buffer to the header */
	msg_head.msg_iov = &iov;
	msg_head.msg_iovlen = 1;

	anc_load.header.cmsg_type = SCM_RIGHTS;
	anc_load.header.cmsg_len = CMSG_LEN(sizeof(int));
	anc_load.header.cmsg_level = SOL_SOCKET;

	msg_head.msg_name = NULL;
	msg_head.msg_namelen = 0;
	msg_head.msg_control = &anc_load;
	msg_head.msg_controllen = CMSG_SPACE(sizeof(int));

	ret = recvmsg(sockfd, &msg_head, 0);
	if (ret == -1)
		return -1;

	recv_cont = CMSG_FIRSTHDR(&msg_head);
	if (recv_cont == NULL || recv_cont->cmsg_len != CMSG_LEN(sizeof(int)))
		return -1;

	*recvd_fd = *((int *)CMSG_DATA(recv_cont));
	return 0;
}
