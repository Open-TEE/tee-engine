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

#define _GNU_SOURCE

#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sched.h>
#include <syscall.h>

#include "subprocess.h"
#include "socket_help.h"
#include "ta_process.h"
#include "trusted_app_properties.h"
#include "com_protocol.h"
#include "../core/main_shared_var.h"
#include "epoll_wrapper.h"

#define MAX_CURR_EVENTS 5

int lib_main_loop(int manager_sock)
{
	int sockfd[2];
	pid_t new_proc_pid;
	struct com_msg_open_session *recv_open_msg = NULL;
	struct com_msg_ta_created created_ta;
	int recv_bytes, ret, event_count, i;
	sigset_t sig_empty_set, sig_block_set;
	struct epoll_event cur_events[MAX_CURR_EVENTS];

	if (sigemptyset(&sig_empty_set)) {
		syslog(LOG_ERR, "lib_main_loop: Sigempty set failed\n");
		exit(EXIT_FAILURE);
	}

	if (sigfillset(&sig_block_set)) {
		syslog(LOG_ERR, "lib_main_loop: Sigempty set failed\n");
		exit(EXIT_FAILURE);
	}

	if (init_epoll())
		exit(EXIT_FAILURE);

	/* listen to inbound connections from the manager */
	if (epoll_reg_fd(manager_sock, EPOLLIN))
		exit(EXIT_FAILURE);

	if (epoll_reg_fd(self_pipe_fd, EPOLLIN))
		exit(EXIT_FAILURE);

	/* The launchers, sole purpose is to listen for commands from the manager.
	 * When it receives a command from the manager it creates a new socket pair
	 * and forks off a child process.  this child process will become a TA.
	 * Once the child process is forked off, the launcher sends one end
	 * of the newly created socket pair back to the manager so it can
	 * communicate directly with the TA. The launcher then returns to wait until
	 * it is required to start the next TA.
	 *
	 * In the child process the launcher loads the TA as a library and waits for
	 * an open_session request to arrive from the manager so it cna complete its
	 * initialization
	 */

	for (;;) {
		printf("Ramble on!\n");

		if (pthread_sigmask(SIG_SETMASK, &sig_empty_set, NULL)) {
			syslog(LOG_ERR, "lib_main_loop: Problem with signal mask setting\n");
			continue;
		}

		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				check_and_reset_signal_status();
				continue;
			}

			/* Log error and hope the error clears itself */
			syslog(LOG_ERR, "lib_main_loop: Failed return from epoll_wait\n");
			continue;
		}

		if (pthread_sigmask(SIG_SETMASK, &sig_block_set, NULL)) {
			syslog(LOG_ERR, "lib_main_loop: Problem with signal mask setting\n");
			continue;
		}

		/* Note: All signals are blocked */

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == self_pipe_fd) {

				if (cur_events[i].events & EPOLLERR) {
					syslog(LOG_ERR, "lib_main_loop: Something wrong with self pipe\n");
					exit(EXIT_FAILURE);
				}

				check_and_reset_signal_status();
				continue;
			}

			if (cur_events[i].events & EPOLLERR || cur_events[i].events & EPOLLHUP) {
				syslog(LOG_ERR, "lib_main_loop: Manager socket error\n");
				exit(EXIT_FAILURE);
			}

			ret = com_wait_and_recv_msg(manager_sock, &recv_open_msg, &recv_bytes, NULL);

			if (ret == -1) {
				free(recv_open_msg);
				continue; /* TODO: Figur out why -1 */

			} else if (ret > 0) {
				free(recv_open_msg);
				continue;
			}

			/* Extrac info from message */
			if (recv_open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
			    recv_open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
				syslog(LOG_ERR, "lib_main_loop: Invalid message\n");
				free(recv_open_msg);
				continue; /* ignore */
			}

			/* create a socket pair so the manager and TA can communicate */
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
				syslog(LOG_ERR, "failed to create a socket pair : %s", strerror(errno));
				/* TODO: send err msg */
				free(recv_open_msg);
				continue;
			}

			/*
			 * Clone now to create the TA subprocess
			 */

			created_ta.pid = syscall(SYS_clone, SIGCHLD | CLONE_PARENT, 0 , 0);
			if (created_ta.pid == -1) {
				if (com_send_msg(manager_sock, &created_ta,
						 sizeof(struct com_msg_ta_created)) !=
				    sizeof(struct com_msg_ta_created)) {
					syslog(LOG_ERR, "lib_main_loop: Failed report fail");

				}

				continue;

			} else if (created_ta.pid == 0) {
				/* child process will become the TA*/
				epoll_unreg(manager_sock);
				close(manager_sock);
				close(sockfd[0]);
				prctl(PR_SET_PDEATHSIG, SIGTERM);
				if (ta_process_loop(sockfd[1], recv_open_msg)) {
					syslog(LOG_ERR, "ta_process has failed");
					exit(1);
				}

			} else {
				/* TODO: Proper error handling */
				created_ta.msg_hdr.msg_name = COM_MSG_NAME_CREATED_TA;
				created_ta.msg_hdr.msg_type = COM_TYPE_RESPONSE;
				created_ta.msg_hdr.sender_type = Launcher;
				created_ta.msg_hdr.sess_id = 0;
				created_ta.pid = new_proc_pid;

				/* We have to send kill signal to TA, because
				 * SIGTERM might not be executed if TA is "stuck" in
				 * create entry or open session function */

				if (com_send_msg(manager_sock, &created_ta,
						 sizeof(struct com_msg_ta_created)) ==
				    sizeof(struct com_msg_ta_created)) {

					if (send_fd(manager_sock, sockfd[0]) == -1) {
						syslog(LOG_ERR, "Failed to send TA sock");
						kill(new_proc_pid, SIGKILL);
						/* TODO: Check what is causing error */
					}

				} else {
					syslog(LOG_ERR, "Failed to send response msg");
					kill(new_proc_pid, SIGKILL);
					/* TODO: Check what is causing error */
				}

				/* parent process will stay as the launcher */
				/* The launcher process has no need for these socket descriptors now */
				close(sockfd[0]);
				close(sockfd[1]);
				free(recv_open_msg);
			}
		}
	}
}
