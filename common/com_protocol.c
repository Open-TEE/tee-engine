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
#define _GNU_SOURCE

#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <zlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/select.h>

#include "com_protocol.h"
#include "socket_help.h"


static const uint32_t COM_MSG_START = 0xABCDEF12;
static const int TRY_READ_FD_COUNT = 5;

/* Struct information is added to message */
struct com_trasnport_info {
	uint32_t start;
	int data_len; /* data_len: user message */
	uLong checksum;
};

static int read_all(int fd, void *buf, int buf_len, void (*eintr_handler)())
{
	/* TODO (or if someone knows): Is there any problems using select with epoll? If there
	 * is no problems, remove ioctl-call-timeout and replace it with select-timeout. I am
	 * using ioctl technique, because i do not know if there is a problem.. */

	int total_read_bytes = 0, read_bytes = 0, i = 0;
	fd_set set;
	struct timeval timeout;
	int select_ret;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	for (i = 0; (i < TRY_READ_FD_COUNT && total_read_bytes < buf_len); ++i) {

		timeout.tv_sec = 3;
		timeout.tv_usec = 0;

		select_ret = select(fd + 1, &set, NULL, NULL, &timeout);
		if (select_ret == -1) {
			if (errno == EINTR) {
				eintr_handler();
				i--;
				continue;
			}

			return -1;

		} else if (select_ret == 0) {
			continue;

		} else {
			read_bytes = read(fd, ((unsigned char *)buf) + total_read_bytes,
					  buf_len - total_read_bytes);

			if (read_bytes == -1 || read_bytes != (buf_len - total_read_bytes)) {

				if (errno == EINTR) {
					if (eintr_handler)
						eintr_handler();
					i--;
					if (read_bytes > 0) {
						buf_len -= read_bytes;
						total_read_bytes += read_bytes;
					}

					continue;
				}

				syslog(LOG_ERR, "read_all: read error\n");
				return -1;
			}

			total_read_bytes += read_bytes;
		}
	}

	return total_read_bytes;
}

/* No partial send possibility here */
static int write_all(int fd, void *buf, int buf_len)
{
	int total_written_bytes = 0;
	int written_bytes = 0;

	while (total_written_bytes < buf_len) {

		written_bytes = write(fd, ((unsigned char *)buf) + total_written_bytes,
				      buf_len - total_written_bytes);

		if (written_bytes == -1) {
			syslog(LOG_ERR, "write_all: write error: %s\n", strerror(errno));
			return COM_RET_IO_ERROR;
		}

		total_written_bytes += written_bytes;
	}

	return total_written_bytes;
}

static int reset_socket(int sockfd, void (*eintr_handler)())
{
	int bytes_availible, ret;
	void *discard_buf = NULL;

	if (ioctl(sockfd, FIONREAD, &bytes_availible) == -1) {
		syslog(LOG_ERR, "read_transport_info: IOCTL error\n");
		return 1;
	}

	/* Temporary solution. Malloc function will make this function
	 * simpler than round-buffer-solutions. */
	discard_buf = malloc(bytes_availible);
	if (!discard_buf) {
		syslog(LOG_ERR, "read_transport_info: out of memory\n");
		return 1;
	}

	ret = read_all(sockfd, discard_buf, bytes_availible, eintr_handler);
	free(discard_buf);

	/* If we had partial read, ignore and hope that it clear by it self */
	return ret == -1 ? -1 : 0;
}

int com_recv_msg(int sockfd, void **msg, int *msg_len, void (*eintr_handler)())
{
	int ret;
	struct com_trasnport_info com_recv_trans_info;

	/* TODO: Wind socket to correct starting point. Previous read might gone bad and therefore
	 * there might be data and it is not starting correct sequence. Current solution might
	 * discard/ignore/not notice messages from socket! */

	/* Read transport capsule */
	ret = read_all(sockfd, &com_recv_trans_info, sizeof(struct com_trasnport_info), eintr_handler);
	if (ret != sizeof(struct com_trasnport_info)) {
		/* We did have a IO error or there was not enough data at fd */
		syslog(LOG_ERR, "com_read_msg: read -1 or corrupted messge\n");
		goto err;
	}

	/* Transport information read. Verify bit sequence, again */
	if (com_recv_trans_info.start != COM_MSG_START) {
		syslog(LOG_ERR, "com_read_msg: Read data is not beginning correctly\n");
		ret = reset_socket(sockfd, eintr_handler);
		if (ret == 0)
			ret = 1;
		goto err;
	}

	/* Malloc space for incomming message and read message */
	*msg_len = com_recv_trans_info.data_len;
	*msg = malloc(*msg_len);
	if (!*msg) {
		syslog(LOG_ERR, "com_read_msg: Out of memory\n");
		ret = 1;
		goto err;
	}

	ret = read_all(sockfd, *msg, *msg_len, eintr_handler);
	if (ret != *msg_len) {
		syslog(LOG_ERR, "com_read_msg: read -1 or corrupted messge\n");
		/* Error code filled */
		goto err;
	}

	/* Calculate and verify checksum */
	if (com_recv_trans_info.checksum != crc32(0, *msg, *msg_len)) {
		syslog(LOG_ERR, "com_read_msg: Message checksum is not matching, discard msg\n");
		ret = 1;
		goto err;
	}

	return 0;

err:
	free(*msg); /* Discardin msg */
	*msg_len = 0;
	*msg = NULL;
	return ret;
}

int com_wait_and_recv_msg(int sockfd, void **msg, int *msg_len, void (*eintr_handler)())
{
	fd_set set;
	struct timeval timeout;
	int select_ret;

	FD_ZERO(&set);
	FD_SET(sockfd, &set);

	while (1) {

		timeout.tv_sec = 1000;
		timeout.tv_usec = 0;

		select_ret = select(sockfd + 1, &set, NULL, NULL, &timeout);
		if (select_ret == -1) {
			if (errno == EINTR) {
				eintr_handler();
				continue;
			}

			return -1;

		} else if (select_ret == 0) {
			continue;

		} else {
			break;

		}
	}

	return com_recv_msg(sockfd, msg, msg_len, eintr_handler);

}

int com_send_msg(int sockfd, void *msg, int msg_len)
{
	int bytes_write_trans_send;
	int bytes_write_msg_send;
	struct com_trasnport_info com_trans_info;
	/* struct iovec bufs[2]; */

	/* Build message */

	/* Fill and calculate transport information */
	com_trans_info.start = COM_MSG_START;
	com_trans_info.data_len = msg_len;
	com_trans_info.checksum = crc32(0, msg, msg_len);

	/* TODO: Use gathert write

	bufs[0].iov_base = &com_trans_info;
	bufs[0].iov_len = sizeof(struct com_trasnport_info);

	bufs[1].iov_base = msg;
	bufs[1].iov_len = msg_len; */

	/* Send transport info */
	bytes_write_trans_send = write_all(sockfd, &com_trans_info, sizeof(struct com_trasnport_info));
	if (bytes_write_trans_send == -1) {
		syslog(LOG_ERR, "com_send_msg: send error\n");
		return -1;
	}

	/* Send message */
	bytes_write_msg_send = write_all(sockfd, msg, msg_len);
	if (bytes_write_msg_send == -1) {
		syslog(LOG_ERR, "com_send_msg: send error\n");
		return -1;
	}

	return bytes_write_msg_send;
}

com_msg_hdr_t com_get_msg_name(void *msg)
{
	/* Not the most optimizated operation, but I do not know a better way than
	 * a "hardcoded" solution. */

	struct com_msg_hdr msg_hdr;

	if (!msg) {
		syslog(LOG_ERR, "com_get_msg_name: message null\n");
		return 0;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.msg_name;
}

com_msg_hdr_t com_get_msg_type(void *msg)
{
	struct com_msg_hdr msg_hdr;

	if (!msg) {
		syslog(LOG_ERR, "com_get_msg_type: message null\n");
		return 0;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.msg_type;
}

sess_t com_get_msg_sess_id(void *msg)
{
	struct com_msg_hdr msg_hdr;

	if (!msg) {
		syslog(LOG_ERR, "com_get_msg_sess_id: message null\n");
		return 0;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.sess_id;
}
