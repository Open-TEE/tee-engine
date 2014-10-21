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

#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "subprocess.h"
#include "socket_help.h"
#include "ta_process.h"
#include "core_extern_resources.h"

static void check_signal_status()
{
	sig_atomic_t cpy_sig_vec = sig_vector;
	reset_signal_self_pipe();

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

int lib_main_loop(int manager_sock)
{
	void *lib_path; /* Temporary. Launcher patch is comming */
	ssize_t to_read = 1; /* Temporary. Launcher patch is comming */
	ssize_t num_r;
	int sockfd[2];

	/* The launchers, sole purpose is to listen for commands from the manager.
	 * When it receives a command from the manager it creates a new socket pair
	 * and forks off a child process.  this child process will become a TA.
	 * Once the child process is forked off, the launcher sends one end
	 * of the newly created socket pair to the back to the manager so it can
	 * communicate directly with the TA. The launcher then returns to wait until
	 * it is required to start the next TA.
	 *
	 * In the child process the launcher loads the TA library and waits for an
	 * open_session request to arrive from the manager so it cna complete its
	 * initialization
	 */
	for (;;) {

		num_r = recv(manager_sock, &lib_path, to_read, 0);
		if (num_r == -1) {
			if (errno == EINTR) {
				/* We have been interrupted so check which of our signals it was
				 * and act on it, though it may have been a SIGCHLD
				 */
				check_signal_status();
			} else {
				syslog(LOG_ERR, "recv fail : %s", strerror(errno));
			}

			continue;

		} else if (num_r < to_read) {
			/* TODO: we might want to loop here to read all of the struct data
			 * if it does not arrive in 1 go.
			 */
			syslog(LOG_ERR, "failed to read the correct data : %s", strerror(errno));
			continue;
		}

		/* create a socket pair so the manager and launcher can communicate */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
			syslog(LOG_ERR, "failed to create a socket pair : %s", strerror(errno));
			continue;
		}

		/* fork now to create the TA subprocess */
		switch (fork()) {
		case -1:
			/* failed to fork */
			return -1;
		case 0:
			/* child process will become the TA*/
			close(sockfd[0]);
			/* We should never return from the TA in this function call */
			if (ta_process_loop(NULL, sockfd[1])) {
				syslog(LOG_ERR, "ta_process has failed");
				exit(1);
			}
			break;
		default:
			/* parent process will stay as the launcher */
			if (send_fd(manager_sock, sockfd[0]))
				syslog(LOG_ERR, "failed to send the fd to manager");

			/* The launcher process has no need for these socket descriptors now */
			close(sockfd[0]);
			close(sockfd[1]);
			break;
		}
	}
}
