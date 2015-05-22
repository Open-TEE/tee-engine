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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <linux/limits.h>
#include <syslog.h>
#include <unistd.h>

#include "subprocess.h"
#include "conf_parser.h"
#include "core_control_resources.h"
#include "tee_logging.h"
#include "args.h"

#ifdef ANDROID
#include "android_defines.h"
#include <libgen.h>
#endif

static struct core_control control_params;

#ifdef GRACEFUL_TERMINATION
/* Freeing only resources that are allocated here */
static void cleanup_core()
{
	config_parser_free_config(control_params.opentee_conf);
	close(control_params.self_pipe_fd);
	close(control_params.comm_sock_fd);
}
#endif

static void sig_handler(int sig)
{
	uint64_t event = 1;

	switch (sig) {
	case SIGCHLD:
		control_params.sig_vector |= TEE_SIG_CHILD;
		break;

	case SIGHUP:
		/* restart the daemon */
		control_params.sig_vector |= TEE_SIG_HUP;
		break;

	case SIGTERM:
		/* terminate the app, so clean up */
		control_params.sig_vector |= TEE_SIG_TERM;
		break;

	case SIGINT:
		/* terminate the app, so clean up */
		control_params.sig_vector |= TEE_SIG_INT;
		break;

	case SIGPIPE:
		/* Catch. Handled locally */
		break;
	}

	if (write(control_params.self_pipe_fd, &event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "write error");
		/* Lets hope that the error clear it self :S */
	}
}

static void reset_signal_self_pipe()
{
	uint64_t event;

	if (read(control_params.self_pipe_fd, &event, sizeof(uint64_t)) == -1) {
		/* EAGAIN == fd is zero and because it is set as non blocking, it returns EAGAIN */
		if (errno != EAGAIN) {
			OT_LOG(LOG_ERR, "Failed to reset control_params.self_pipe_fd\n");
			/* TODO: See what is causing it! */
		}
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

int load_lib(char *path, main_loop_cb *callback)
{
	void *lib;
	char *err = NULL;
	int ret = 0;

	dlerror();

	lib = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (lib == NULL) {
		OT_LOG(LOG_DEBUG, "Failed to load library, %s : %s", path, dlerror());
		return -1;
	}

	*(void **)(callback) = dlsym(lib, "lib_main_loop");
	err = dlerror();
	if (err != NULL || !*callback) {
		OT_LOG(LOG_DEBUG, "Failed to find lib_main_loop");
		ret = -1;
	}

	if (ret)
		dlclose(lib);

	return ret;
}

/*!
 * \brief check_create_pid_file
 * Check the existance of a PID file and try to aquire a lock on it, if we fail to lock the file
 * then it probably means that another instance of this program is already running and it must be
 * killed first
 * \param proc_name The name of this process e.e. argv[0]
 * \param write_pid Should we write the pid of this process? if false we will just check if we can
 * aquire a lock and will close the fd of the pid file before returning, if true we will write
 * to the pid file and keep the file handle to the pid file open, hence holding the lock.
 * \return 0 on success
 */
int check_create_pid_file(char *proc_name_a0, bool write_pid)
{
	struct stat st = {0};
	char *pid_file = NULL;
	char *pid_str = NULL;
	int fd, ret = 0;
	struct flock lock;
	char pid_dir[100] = {0};
	char *proc_name = basename(proc_name_a0);

	/* determine if the directory /var/run/opentee exists, this is the preferred place
	 * for daemon run files, i.e. when running in production this is where we will
	 * store the information, but when developing Open-TEE engine itself we will just use the
	 * /tmp dir for fast and easy starts and stops of the processes
	 */
	if (stat(PID_FILE_ROOT, &st) == -1) {
		/* we will use the tmp dir for the pid_file */
		memcpy(pid_dir, PID_FILE_USER, strnlen(PID_FILE_USER, sizeof(pid_dir) - 1));
		if (mkdir(pid_dir, 0755) == -1 && errno != EEXIST) {
			printf("Error mkdir %s\n", strerror(errno));
			ret = -1;
			goto out;
		}
	} else {
		/* either a wrapper program or init script has created the PID_FILE_ROOT for us */
		memcpy(pid_dir, PID_FILE_ROOT, strnlen(PID_FILE_ROOT, sizeof(pid_dir) - 1));
	}

	if (asprintf(&pid_file, "%s/%s.pid", pid_dir, proc_name) == -1) {
		printf("problems with asprintf\n");
		goto out;
	}

	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		printf("Could not open the PID file (%s)\n", strerror(errno));
		ret = 2;
		goto out;
	}

	/* create a lock on the pid file */
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(fd, F_SETLK, &lock) == -1) {
		if (errno == EACCES || errno == EAGAIN) {
			printf("\"%s\" is already running, pid file (%s) is locked!!\n",
			       proc_name, pid_file);
		} else {
			printf("Failed to lock pid_file (%s): %s\n", pid_file, strerror(errno));
		}

		ret = 3;
		goto out;
	}

	/* We just wanted to test if we already have a running daemon */
	if (!write_pid) {
		close(fd);
		goto out;
	}

	if (ftruncate(fd, 0) == -1) {
		printf("Problems with truncate\n");
		ret = 4;
		goto out;
	}

	/* we are the only process running this program */
	if (asprintf(&pid_str, "%ld", (long)getpid()) == -1) {
		printf("problems with asprintf for pid\n");
		ret = 5;
		goto out;
	}

	if (write(fd, pid_str, strlen(pid_str)) != (ssize_t)strlen(pid_str)) {
		printf("Failed to write the pid to the pid file\n");
		ret = 6;
	}

	if (ret == 0)
		control_params.pid_file_fd = fd;

	free(pid_str);
out:
	free(pid_file);
	return ret;
}

int main(int argc, char **argv)
{
	struct sigaction sig_act;
	int sockfd[2];
	char *lib_to_load = NULL;
	main_loop_cb main_loop;
	char proc_name[MAX_PR_NAME];
	int cmd_name_len = strnlen(argv[0], PATH_MAX);
	sigset_t sig_block_set;
	struct arguments arguments = DEFAULT_ARGUMENTS;

	/* Parse arguments */
	args_parse(argc, argv, &arguments);

	/* Block all signals */
	if (sigfillset(&sig_block_set))
		exit(1);

	if (pthread_sigmask(SIG_SETMASK, &sig_block_set, NULL))
		exit(1);

	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;
	sig_act.sa_handler = sig_handler;

	if (sigaction(SIGCHLD, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGHUP, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGTERM, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGPIPE, &sig_act, NULL) == -1)
		exit(1);
	if (sigaction(SIGINT, &sig_act, NULL) == -1)
		exit(1);

	/* ensure that only one instance of this program is running */
	if (check_create_pid_file(argv[0], false))
		exit(1);

	/* Daemonize if foreground was not requested */
	if (!arguments.foreground && daemonize())
		exit(1);

	/* write the PID of the manager process to the pid file and keep the file
	 * open, hence locked */
	if (check_create_pid_file(argv[0], true))
		exit(1);

	/* create a socket pair so the manager and launcher can communicate */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1)
		exit(1);

	if (config_parser_get_config(&control_params.opentee_conf, arguments.config_file) == -1)
		exit(1);

	control_params.argv0 = argv[0];
	control_params.argv0_len = cmd_name_len;
	control_params.reset_signal_self_pipe = reset_signal_self_pipe;
#ifdef GRACEFUL_TERMINATION
	control_params.fn_cleanup_core = cleanup_core;
#endif

	/* fork now to create the manager and launcher subprocesses */
	control_params.launcher_pid = fork();
	if (control_params.launcher_pid == -1) {
		/* failed to fork */
		return -1;
	} else if (control_params.launcher_pid == 0) {
		/* child process will become the launcher*/
		close(sockfd[0]);
		control_params.comm_sock_fd = sockfd[1];
		lib_to_load = control_params.opentee_conf->subprocess_launcher;
		strncpy(proc_name, "tee_launcher", MAX_PR_NAME);
		prctl(PR_SET_PDEATHSIG, SIGTERM);
	} else {
		/* parent process will become the manager */
		close(sockfd[1]);
		control_params.comm_sock_fd = sockfd[0];
		lib_to_load = control_params.opentee_conf->subprocess_manager;
		strncpy(proc_name, "tee_manager", MAX_PR_NAME);
	}

	/* set the name of our process it appears that we have to set
	 * both process and cmdline names
	 */
	prctl(PR_SET_NAME, (unsigned long)proc_name);
	memset(argv[0], 0, cmd_name_len);
	strncpy(argv[0], proc_name, cmd_name_len);

	/* open syslog for writing */
	openlog(proc_name, 0, LOG_USER);

	control_params.self_pipe_fd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
	if (control_params.self_pipe_fd == -1)
		exit(1);

	if (load_lib(lib_to_load, &main_loop) == -1)
		exit(1);

	/* Enter into the main part of the resepctive programs, manager or launcher
	 * in a proper situation this function should never return */
	if (main_loop(&control_params))
		exit(2);

	exit(0);
}
