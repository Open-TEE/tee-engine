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

#define _GNU_SOURCE

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
#include "core_control_resources.h"
#include "com_protocol.h"
#include "epoll_wrapper.h"
#include "tee_logging.h"

#define MAX_CURR_EVENTS 5

static void check_signal_status(struct core_control *control_params)
{
	sig_atomic_t cpy_sig_vec = control_params->sig_vector;
	control_params->reset_signal_self_pipe();

	/* Note: SIGPIPE and SIGGHLD is not handeled. SIGPIPE is handeled locally and
	 * launcher is not parenting any process. Launcher spwan new process, but it will
	 * transfer ownership to manager process and all child-status-change signals are
	 * delivered to manger process */

	if (cpy_sig_vec & TEE_SIG_TERM) {
		closelog();
		exit(EXIT_SUCCESS);
	}

	if (cpy_sig_vec & TEE_SIG_HUP) {
		/* At the moment, do nothing */
	}
}

static void send_err_msg_to_manager(int man_fd, struct com_msg_ta_created *msg)
{
	/* No special error message. PID -1 is signaling error */
	msg->pid = -1; /* TA not created */

	if (com_send_msg(man_fd, msg, sizeof(struct com_msg_ta_created)) !=
	    sizeof(struct com_msg_ta_created)) {
		OT_LOG(LOG_ERR, "Failed report fail");
	}
}

int lib_main_loop(struct core_control *ctl_params)
{
	int sockfd[2];
	pid_t new_proc_pid;
	struct com_msg_open_session *recv_open_msg = NULL;
	struct com_msg_ta_created created_ta;
	int recv_bytes, ret, event_count, i;
	sigset_t sig_empty_set, sig_block_set;
	struct epoll_event cur_events[MAX_CURR_EVENTS];

	if (sigemptyset(&sig_empty_set)) {
		OT_LOG(LOG_ERR, "Sigempty set failed");
		exit(EXIT_FAILURE);
	}

	if (sigfillset(&sig_block_set)) {
		OT_LOG(LOG_ERR, "Sigempty set failed");
		exit(EXIT_FAILURE);
	}

	if (init_epoll()) {
		OT_LOG(LOG_ERR, "Epoll init failure");
		exit(EXIT_FAILURE);
	}

	/* listen to inbound connections from the manager */
	if (epoll_reg_fd(ctl_params->comm_sock_fd, EPOLLIN)) {
		OT_LOG(LOG_ERR, "Failed reg manager socket");
		exit(EXIT_FAILURE);
	}

	if (epoll_reg_fd(ctl_params->self_pipe_fd, EPOLLIN)) {
		OT_LOG(LOG_ERR, "Failed reg self pipe socket");
		exit(EXIT_FAILURE);
	}

	OT_LOG(LOG_ERR, "Entering the launcher mainloop");

	for (;;) {
		if (pthread_sigmask(SIG_SETMASK, &sig_empty_set, NULL)) {
			OT_LOG(LOG_ERR, "Problem with signal mask setting");
			continue;
		}

		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				check_signal_status(ctl_params);
				continue;
			}

			/* Log error and hope the error clears itself */
			OT_LOG(LOG_ERR, "Failed return from epoll_wait");
			continue;
		}

		if (pthread_sigmask(SIG_SETMASK, &sig_block_set, NULL)) {
			OT_LOG(LOG_ERR, "Problem with signal mask setting");
			continue;
		}

		/* Note: All signals are blocked */

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == ctl_params->self_pipe_fd) {

				if (cur_events[i].events & EPOLLERR) {
					OT_LOG(LOG_ERR, "Something wrong with self pipe");
					exit(EXIT_FAILURE);
				}

				check_signal_status(ctl_params);
				continue;
			}

			/* Launcher is monitoring only two socket and second one is manager fd */
			if (cur_events[i].events & EPOLLERR || cur_events[i].events & EPOLLHUP) {
				OT_LOG(LOG_ERR, "Manager socket error");
				exit(EXIT_FAILURE);
			}

			ret = com_recv_msg(ctl_params->comm_sock_fd, (void **)&recv_open_msg,
					   &recv_bytes);
			if (ret == -1) {
				free(recv_open_msg);
				/* TODO: Figur out why -1, but for now lets
				 *  hope the error clears itself*/
				continue;

			} else if (ret > 0) {
				/* ignore message */
				free(recv_open_msg);
				continue;
			}

			/* Extrac info from message */
			if (recv_open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION ||
			    recv_open_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
				OT_LOG(LOG_ERR, "Invalid message");
				free(recv_open_msg);
				continue; /* ignore */
			}

			/* Received correct mesage from manager. Prepare response message.
			 * PID is filled later */
			created_ta.msg_hdr.msg_name = COM_MSG_NAME_CREATED_TA;
			created_ta.msg_hdr.msg_type = COM_TYPE_RESPONSE;
			created_ta.msg_hdr.sender_type = com_sender_launcher;
			created_ta.msg_hdr.sess_id = recv_open_msg->msg_hdr.sess_id;

			/* create a socket pair so the manager and TA can communicate */
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
				OT_LOG(LOG_ERR, "failed to create a socket pair");
				send_err_msg_to_manager(ctl_params->comm_sock_fd, &created_ta);
				free(recv_open_msg);
				continue;
			}

			/*
			 * Clone now to create the TA subprocess
			 */
			new_proc_pid = syscall(SYS_clone, SIGCHLD | CLONE_PARENT, 0, 0);
			if (new_proc_pid == -1) {
				send_err_msg_to_manager(ctl_params->comm_sock_fd, &created_ta);
				free(recv_open_msg);
				continue;

			} else if (new_proc_pid == 0) {
				/* child process will become the TA*/
				epoll_unreg(ctl_params->comm_sock_fd);
				close(ctl_params->comm_sock_fd);
				close(sockfd[0]);
				prctl(PR_SET_PDEATHSIG, SIGTERM);
				closelog();
				if (ta_process_loop(ctl_params, sockfd[1], recv_open_msg)) {
					OT_LOG(LOG_ERR, "ta_process has failed");
					exit(1);
				}

			} else {
				created_ta.pid = new_proc_pid;

				/* We have to send kill signal to TA, because
				 * SIGTERM might not be executed if TA is "stuck" in
				 * create entry or open session function */

				if (com_send_msg(ctl_params->comm_sock_fd, &created_ta,
						 sizeof(struct com_msg_ta_created)) ==
				    sizeof(struct com_msg_ta_created)) {

					if (send_fd(ctl_params->comm_sock_fd, sockfd[0]) == -1) {
						OT_LOG(LOG_ERR, "Failed to send TA sock");
						kill(new_proc_pid, SIGKILL);
						/* TODO: Check what is causing error, but for now
						 * lets hope the error clears itself*/
					}

				} else {
					OT_LOG(LOG_ERR, "Failed to send response msg");
					kill(new_proc_pid, SIGKILL);
					/* TODO: Check what is causing error, but for now lets
					 *  hope the error clears itself*/
				}

				/* parent process will stay as the launcher */
				close(sockfd[0]);
				close(sockfd[1]);
				free(recv_open_msg);
			}
		}
	}
}
