/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>

#include "io_thread.h"

/*!
 * \brief restart
 * set this to true when we receive a SIGHUP and we can re init the daemon
 */
static volatile sig_atomic_t restart;

/*!
 * \brief terminate
 * Terminate the application
 */
static volatile sig_atomic_t terminate;

/*!
 * \brief sig_handler
 * Callback handler for the registered signals
 * \param sig The id of the signal that ha been revceived
 */
static void sig_handler(int sig)
{
	switch (sig) {
	case SIGCHLD:
		/* wait for children, to reap the zombies */
		while (waitpid(-1, NULL, WNOHANG) > 0)
			continue;
		break;
	case SIGHUP:
		/* restart the daemon */
		restart = 1;
		break;
	case SIGTERM:
		/* terminate the app, so clean up */
		terminate = 1;
		break;
	}
}

/*!
 * \brief daemonize
 * Turn the process into a daemon
 * \return 0 on success
 */
static int daemonize(void)
{
	int fd, j;

	switch (fork()) {
	case -1:
		/* failed to fork */
		return -1;
	case 0:
		/* child process */
		break;
	default:
		/* parent process exits to create a background process */
		_exit(0);
	}

	if (setsid() == -1)
		return -1;

	switch (fork()) {
	case -1:
		/* failed to fork */
		return -1;
	case 0:
		/* child process */
		break;
	default:
		/* parent process exits to create a background process with no session */
		_exit(0);
	}

	if (chdir("/") == -1)
		return -1; /* unlikely as the root dir must be acessible */

	umask(0);

	/* Close open file descriptors, only 3 *should* be open as the process just started */
	for (fd = 0; fd < 100; fd++)
		close(fd);

	for (j = 0, fd = 0; fd < 2; j++) {
		fd = open("/dev/null", O_RDWR);
		if (fd != j)
			return -1; /* the new fds should be 0, 1, 2 : stdin, stdout stderr */
	}

	return 0;
}

/*!
 * \brief check_signal_status
 * After the signals have change the state of the global bits we should check what we have been
 * requested to do
 */
static void check_signal_status()
{
	if (restart) {
		syslog(LOG_DEBUG, "restart requested");
		restart = 0;
	}
	if (terminate) {
		syslog(LOG_DEBUG, "Terminate requested");
		closelog();
		exit(3);
	}
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	struct sigaction sig_act;

	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;
	sig_act.sa_handler = sig_handler;

	if (sigaction(SIGCHLD, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGHUP, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGTERM, &sig_act, NULL) == -1)
		exit(1);

	/*
	 * TODO: we should probably implement some file locks to ensure only one instance of the
	 * daemon is running at any one time.
	 */
	if (daemonize())
		exit(1);

	/* open syslog for writing */
	openlog(NULL, 0, LOG_USER);

	/* in a proper situation this function should never return */
	if (daemon_main_loop(&check_signal_status))
		exit(2);

	exit(0);
}
