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
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <linux/inotify.h>
#include <dirent.h>
#include <sys/ioctl.h>

#include "subprocess.h"
#include "epoll_wrapper.h"
#include "process_manager.h"
#include "elf_reader.h"
#include "conf_parser.h"

#define MAX_CURR_EVENTS 5
#define MAX_ERR_STRING 100

/*!
 * \brief init_sock
 * Initialize the daemons main public socket and listen for inbound connections
 * \param pub_sockfd The main socket to which clients connect
 * \return 0 on success -1 otherwise
 */
static int init_sock(int *pub_sockfd)
{
	const char *sock_path = "/tmp/open_tee_sock";
	struct sockaddr_un sock_addr;

	if (remove(sock_path) == -1 && errno != ENOENT) {
		syslog(LOG_ERR, "Failed to remove %s : %s", sock_path, strerror(errno));
		return -1;
	}

	*pub_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*pub_sockfd == -1) {
		syslog(LOG_ERR, "Create socket %s", strerror(errno));
		return -1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (bind(*pub_sockfd, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr_un)) == -1) {
		syslog(LOG_ERR, "Error %s", strerror(errno));
		return -1;
	}

	if (listen(*pub_sockfd, SOMAXCONN) == -1) {
		syslog(LOG_ERR, "Listen socket %s", strerror(errno));
		return -1;
	}
	return 0;
}

/*!
 * \brief From the file extension, function determines if it is a .so file.
 * \param file_name The name of the file
 * \returns '1' when file is an .so file, -1 otherwise.
 */
static bool is_so_file(char *file_name)
{
	char *file_extension;

	/* get pointer to the last occurance of '.', which  becomes an extension. */
	file_extension = strrchr(file_name, '.');
	if (strcmp(".so", file_extension) == 0)
		return true;
	else
		return false;
}

/*!
 * Concats directory path and file name to form absolute path
 * of an ELF file.
 * \param dir_path The ta directory path.
 * \param file_name The file name.
 * \returns Concatenated directory path and file name.
 */
static char *get_elf_file_path(const char *dir_path, char *file_name)
{
	char *elf_file_name;
	size_t dir_path_len, file_name_len;

	dir_path_len = strlen(dir_path);
	file_name_len = strlen(file_name);

	elf_file_name = malloc(dir_path_len + file_name_len + 1);
	if (elf_file_name == NULL) {
		syslog(LOG_ERR, "Out of memory.");
		return NULL;
	}
	memcpy(elf_file_name, dir_path, dir_path_len);
	memcpy(elf_file_name + dir_path_len, file_name, file_name_len + 1);
	return elf_file_name;
}

/*!
 * \brief Finds .so file in the directory, reads them and add their TA metadata in a list.
 * \param The directory in which .so files will be searched.
 */
static int read_existing_so_files(const char *dir_path)
{
	DIR *d;
	struct dirent *dir;
	char *elf_file_path = NULL;

	d = opendir(dir_path);
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			elf_file_path = get_elf_file_path(dir_path, dir->d_name);
			if (elf_file_path == NULL)
				return -1;

			if (is_so_file(elf_file_path))
				read_metadata(elf_file_path);
		}
		closedir(d);
		return 0;
	} else
		return -1;
}

/*!
 * \brief Reads the event details, determines kind of event. Based on event reads .so file add
 * its metadata to a list or delete metadata from the list.
 * \param The inotify file descriptor.
 * \param The directory which is being monitored.
 */
static int extract_inotify_event(int inotify_fd, const char *dir_path)
{
	int num_read;
	char *inotify_buffer = NULL;
	struct inotify_event *intfy_event;
	char *elf_file_path;
	char *tmp_str;
	int intfy_buff_sz;
	int result;

	result = ioctl(inotify_fd, FIONREAD, &intfy_buff_sz);
	if (result == -1) {
		syslog(LOG_ERR, "ioctl() failed %s.", strerror(errno));
		goto err_cleanup;
	}

	inotify_buffer = malloc(intfy_buff_sz);
	if (inotify_buffer == NULL) {
		syslog(LOG_ERR, "Out of memory.");
		goto err_cleanup;
	}

	num_read = read(inotify_fd, inotify_buffer, intfy_buff_sz);
	if (num_read == -1) {
		syslog(LOG_ERR, "Error while reading event %s.", strerror(errno));
		goto err_cleanup;
	}

	for (tmp_str = inotify_buffer; tmp_str < (inotify_buffer + num_read);
	     tmp_str += sizeof(struct inotify_event) + intfy_event->len) {

		intfy_event = (struct inotify_event *) tmp_str;
		/* Irrespective of an event if the event is related to
		 * .so file.
		 */
		if ((intfy_event->len > 0) && (is_so_file(intfy_event->name))) {
			elf_file_path = get_elf_file_path(dir_path, intfy_event->name);

			if (elf_file_path == NULL)
				continue;

			if (intfy_event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO |
						 IN_ATTRIB | IN_MODIFY))
				read_metadata(elf_file_path);
			else if (intfy_event->mask & (IN_DELETE | IN_MOVED_FROM)) {
				if (remove_metadata(elf_file_path) == -1)
					syslog(LOG_ERR,
					       "Error while removing metadata for ELF file %s",
					       elf_file_path);
				free(elf_file_path);
			}
		} else if (intfy_event->mask & (IN_DELETE_SELF | IN_MOVE_SELF))
			delete_metadata_list();
	}
	free(inotify_buffer);
	return 0;

err_cleanup:
	if (inotify_buffer != NULL)
		free(inotify_buffer);
	return -1;
}

int lib_main_loop(sig_status_cb check_signal_status, int sockpair_fd)
{
	int clientfd, public_sockfd, i;
	int event_count;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	char errbuf[MAX_ERR_STRING];
	proc_t new_client;
	int inotify_fd = 0;
	int inotify_wd = 0;
	char *dir_path = NULL;

	/* Read ta_dir_path from configuration */
	dir_path = config_parser_get_value("ta_dir_path");
	if (dir_path == NULL) {
		syslog(LOG_ERR, "Invalid TA directory path.");
		goto err_cleanup;
	}

	/* Read existing files in the monitored directory. */
	if (read_existing_so_files(dir_path) == -1)
		syslog(LOG_ERR, "Error while reading existing ELF files.");


	/* Initializing inotify */
	inotify_fd = inotify_init();
	if (inotify_fd < 0) {
		syslog(LOG_ERR, "inotify initialization failed.", strerror(errno));
		goto err_cleanup;
	}

	/* Add a directory watch for addition of new file
	 * In Linux when 'rm' command is used to delete the file, this event is registered as
	 * 'IN_DELETE', however when file is deleted using UI it is registered as 'IN_MOVED_FROM'.
	 * When file is replaced 'IN_MOVED_TO' and 'IN_MOVED_FROM' events are triggerred.
	 */
	inotify_wd = inotify_add_watch(inotify_fd, dir_path,
				       IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO |
				       IN_MOVED_FROM | IN_DELETE_SELF | IN_MOVE_SELF |
				       IN_ATTRIB | IN_MODIFY);
	if (inotify_wd == -1) {
		syslog(LOG_ERR, "inotify add watch for directory failed.", strerror(errno));
		goto err_cleanup;
	}

	if (init_epoll())
		goto err_cleanup;

	if (init_sock(&public_sockfd))
		goto err_cleanup;

	/* listen to inbound connections from userspace clients */
	if (epoll_reg_fd(public_sockfd, EPOLLIN))
		goto err_cleanup;

	/* listen for communications from the launcher process */
	if (epoll_reg_fd(sockpair_fd, EPOLLIN))
		goto err_cleanup;

	/* listen for addition of files in a directory */
	if (epoll_reg_fd(inotify_fd, EPOLLIN))
		goto err_cleanup;

	/* NB everything after this point must be thread safe */
	for (;;) {
		/* Block and wait for a one of the monitored I/Os to become available */
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				/* We have been interrupted so check which of our signals it was
				 * and act on it, though it may have been a SIGCHLD
				 */
				check_signal_status();
			} else {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed return from epoll_wait : %s", errbuf);
			}
			/* In both cases continue, and hope the error clears itself */
			continue;
		}

		for (i = 0; i < event_count; i++) {
			syslog(LOG_ERR, "Spinning in the inner foor loop");

			if (cur_events[i].data.fd == public_sockfd) {
				/* the listen socket has received a connection attempt */
				clientfd = accept(public_sockfd, NULL, NULL);
				if (clientfd == -1) {
					strerror_r(errno, errbuf, MAX_ERR_STRING);
					syslog(LOG_ERR, "Failed to accept child : %s", errbuf);
					/* hope the problem will clear for next connection */
					continue;
				}

				/* Create a dummy process entry to monitor the new client and
				 * just listen for future communications from this socket
				 * If there is already data on the socket, we will be notified
				 * immediatly once we return to epoll_wait() and we can handle
				 * it correctly
				 */
				if (create_uninitialized_client_proc(&new_client, clientfd))
					goto err_cleanup;

				if (epoll_reg_data(clientfd, EPOLLIN, (void *)new_client))
					goto err_cleanup;
			} else if (cur_events[i].data.fd == inotify_fd) {
				if (extract_inotify_event(inotify_fd, dir_path) == -1)
					syslog(LOG_ERR, "Error while extracing epoll events.");
			} else {
				pm_handle_connection(cur_events[i].events, cur_events[i].data.ptr);
			}
		}
	}
	free(dir_path);
	close(inotify_fd);
	return 0;

err_cleanup:
	if (dir_path != NULL)
		free(dir_path);
	if (inotify_fd != 0)
		close(inotify_fd);
	return -1;
}
