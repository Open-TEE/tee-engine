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
#include "subprocess.h"
#include "epoll_wrapper.h"
#include "process_manager.h"
#include "elf_reader.h"

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

#define MAX_CURR_EVENTS 5
#define MAX_ERR_STRING 100

/* Buffer space is allocated for 5 events. */
#define EVENT_BUF_LEN  (MAX_CURR_EVENTS * ((sizeof(struct inotify_event)) + 16))

// TODO: Path needs to be changed.
const char *dir_path = "/home/swapnil/tmp/so/";

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
bool is_so_file(char *file_name)
{
	char *file_extension;
	/* get pointer to the last occurance of '.', which  becomes an extension. */
	file_extension = strrchr(file_name, '.');

	syslog(LOG_INFO, "File extension is %s.\n", file_extension);
	if (strcmp(".so", file_extension) == 0) {
		syslog(LOG_INFO, "File extension matches.\n");
		return true;
	} else {
		syslog(LOG_INFO, "File extension does not matches.\n");
		return false;
	}
}

/*!
 * \brief Concats two strings and create a new string.
 * \param s1, s2 strings to be appended.
 * \returns Concatenated string.
 */
static char *concat(const char *s1, char *s2)
{
	size_t len1 = strlen(s1);
	size_t len2 = strlen(s2);
	char *result = malloc(len1+len2+1);

	memcpy(result, s1, len1);
	memcpy(result+len1, s2, len2+1);
	return result;
}

/*!
 * \brief Finds .so file in the directory, reads them and add their TA metadata in a list.
 * \param The directory in which .so files will be searched.
 */
void read_existing_so_files(const char *dir_path)
{
	DIR *d;
	struct dirent *dir;
	char *elf_file_path;

	d = opendir(dir_path);
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			elf_file_path = concat(dir_path, dir->d_name);
			if (is_so_file(elf_file_path))
				read_metadata(elf_file_path);
			else
				syslog(LOG_INFO, "%s is not a .so file\n", elf_file_path);

		}
		closedir(d);
	} else {
		syslog(LOG_ERR, "Error while opening directory %s\n", dir_path);
	}
}

/*!
 * \brief Reads the event details, determines kind of event. Based on event reads .so file add
 * its metadata to a list or delete metadata from the list.
 * \param The inotify file descriptor.
 * \param The directory which is being monitored.
 */
void extract_inotify_event(int inotify_fd, const char* dir_path)
{
	int num_read;
	char inotify_buffer[EVENT_BUF_LEN];
	struct inotify_event *intfy_event;
	char *elf_file_path;
	char *tmp_str;

	num_read = read(inotify_fd, inotify_buffer, EVENT_BUF_LEN);
	if (num_read == 0) {
		syslog(LOG_ERR, "Error while reading event.\n");
		return;
	} else if (num_read == -1) {
		syslog(LOG_ERR, "Error while reading event.\n");
		return;
	}
	for (tmp_str = inotify_buffer; tmp_str < inotify_buffer + num_read; ) {
		intfy_event = (struct inotify_event *) tmp_str;
		/* Irrespective of an event if the event is related to
		 * .so file.
		 */
		if ((intfy_event->len > 0) && (is_so_file(intfy_event->name))) {
			elf_file_path = concat(dir_path, intfy_event->name);
			if (intfy_event->mask & IN_CREATE) {
				syslog(LOG_INFO, "EVENT : IN_CREATE\n");
				syslog(LOG_INFO, "File created : %s\n", elf_file_path);
				/* When newly added file read immediately, it throws an error.
				 * during parsing.
				 */
				sleep(1);
				read_metadata(elf_file_path);
			} else if (intfy_event->mask & IN_DELETE) {
				syslog(LOG_INFO, "EVENT : IN_DELETE (can occur when .so file is deleted.)\n");
				syslog(LOG_INFO, "ELF file %s has been deleted.\n", elf_file_path);
				remove_metadata(elf_file_path);
			} else if (intfy_event->mask & IN_MOVED_FROM) {
				printf("EVENT : IN_MOVED_FROM  (when .so file is renamed or deleted.)\n");
				printf("ELF file %s has been renamed or deleted.\n", elf_file_path);
				remove_metadata(elf_file_path);
			} else if (intfy_event->mask & IN_MOVED_TO) {
				syslog(LOG_INFO, "EVENT : IN_MOVED_TO (can occur when .so file is renamed or replaced.)\n");
				if(remove_metadata(elf_file_path) == 0) {
					syslog(LOG_INFO, "ELF file %s has been replaced.\n", elf_file_path);
				} else {
					syslog(LOG_INFO, "ELF file %s has been renamed.\n", elf_file_path);
				}
				read_metadata(elf_file_path);
			}
		}
		tmp_str += sizeof(struct inotify_event) + intfy_event->len;
	}
}

int lib_main_loop(sig_status_cb check_signal_status, int sockpair_fd)
{
	int clientfd, public_sockfd, i;
	int event_count;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	char errbuf[MAX_ERR_STRING];
	proc_t new_client;
	int inotify_fd;
	int inotify_wd;	

	/* Read existing files in the monitored directory. */
	read_existing_so_files(dir_path);

	/* Initializing inotify */
	inotify_fd = inotify_init();
	if (inotify_fd < 0 ) {
		syslog(LOG_ERR, "inotify initialization failed.\n");
		return -1;
	} else {
		syslog(LOG_INFO, "inotify initialized successful.\n");
	}

	/* Add a directory watch for addition of new file
	 * In Linux when 'rm' command is used to delete the file, this event is registered as
	 * 'IN_DELETE', however when file is deleted using UI it is registered as 'IN_MOVED_FROM'.
	 * When file is replaced 'IN_MOVED_TO' and 'IN_MOVED_FROM' events are triggerred.
	 */
	inotify_wd = inotify_add_watch(inotify_fd, dir_path, IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
	if (inotify_wd == -1) {
		syslog(LOG_ERR, "inotify add watch for directory failed.\n");
		return -1;
	} else {
		syslog(LOG_INFO, "inotify add watch for directory is successful.\n");
	}

	if (init_epoll())
		return -1;

	if (init_sock(&public_sockfd))
		return -1;

	/* listen to inbound connections from userspace clients */
	if (epoll_reg_fd(public_sockfd, EPOLLIN))
		return -1;

	/* listen for communications from the launcher process */
	if (epoll_reg_fd(sockpair_fd, EPOLLIN))
		return -1;

	/* listen for addition of files in a directory */
	if (epoll_reg_fd(inotify_fd, EPOLLIN))
		return -1;

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
					return -1;

				if (epoll_reg_data(clientfd, EPOLLIN, (void *)new_client))
					return -1;
			} else if (cur_events[i].data.fd == inotify_fd) {
				extract_inotify_event(inotify_fd, dir_path);
			} else {
				pm_handle_connection(cur_events[i].events, cur_events[i].data.ptr);
			}
		}
	}
}
