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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "epoll_wrapper.h"
#include "tee_logging.h"

static int epollfd;

static int wrap_epoll_ctl(int fd, struct epoll_event *event, int op)
{
	if (epoll_ctl(epollfd, op, fd, event)) {
		OT_LOG(LOG_ERR, "Failed on epoll_ctl operation: 0x%x: %s", op, strerror(errno));
		return -1;
	}

	return 0;
}

int init_epoll()
{
	epollfd = epoll_create(10);
	if (epollfd < 0) {
		OT_LOG(LOG_ERR, "Failed to create epoll fd: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int epoll_reg_fd(int fd, uint32_t events)
{
	struct epoll_event event = {0};

	event.events = events;
	event.data.fd = fd;

	return wrap_epoll_ctl(fd, &event, EPOLL_CTL_ADD);
}

int epoll_reg_data(int fd, uint32_t events, void *data)
{
	struct epoll_event event = {0};

	event.events = events;
	event.data.ptr = data;

	return wrap_epoll_ctl(fd, &event, EPOLL_CTL_ADD);
}

int epoll_unreg(int fd)
{
	struct epoll_event event = {0};
	event.events = EPOLLIN;

	return wrap_epoll_ctl(fd, &event, EPOLL_CTL_DEL);
}

int wrap_epoll_wait(struct epoll_event *events, int max_events)
{
	return epoll_wait(epollfd, events, max_events, -1);
}

void cleanup_epoll()
{
	close(epollfd);
}
