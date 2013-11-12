#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>

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
 * \brief child_main_loop
 * This is where the child processing will start from
 */
static void child_main_loop(int childfd)
{
	ssize_t n;
	char buff[1024];

	while((n = (read(childfd, buff, sizeof(buff) -1))) > 0) {
		buff[n] = '\0';
		syslog(LOG_DEBUG, "%s", buff);
	}

	return;
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

/*!
 * \brief daemon_main_loop
 * This is the main processing loop of the parent, daemon process. It never returns.
 */
static void daemon_main_loop()
{
	const char *sock_path = "/tmp/open_tee_sock";
	int sockfd, childfd;
	struct sockaddr_un sock_addr;

	if (remove(sock_path) == -1 && errno != ENOENT) {
		syslog(LOG_ERR, "Failed to remove %s : %s", sock_path, strerror(errno));
		exit(1);
	}

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		syslog(LOG_ERR, "Create socket %s", strerror(errno));
		exit(1);
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (bind(sockfd, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr_un)) == -1) {
		syslog(LOG_ERR, "Error %s", strerror(errno));
		exit(1);
	}

	if (listen(sockfd, SOMAXCONN) == -1) {
		syslog(LOG_ERR, "Listen socket %s", strerror(errno));
		exit(1);
	}

	for (;;) {
		/* Block and wait for a client to connect */
		childfd = accept(sockfd, NULL, NULL);
		if (childfd == -1) {
			if (errno == EINTR) {
				/* We have been interrupted so check which of our signals it was
				 * and act on it, though it may have been a SIGCHLD
				 */
				check_signal_status();
				continue;
			} else {
				syslog(LOG_ERR, "Accept error %s", strerror(errno));
				exit(1);
			}
		}

		/* create a child process to handle the connection */
		switch (fork()) {
		case -1:
			/* Failed to fork */
			close(childfd);
			break;
		case 0:
			/* in the child */
			close(sockfd); /* This is the parents socket descriptor */
			child_main_loop(childfd);
			_exit(0);
		default:
			/* In the parent, just close the new child fd and continue
			 * to accept the next connection
			 */
			close(childfd);
			break;
		}
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

	daemon_main_loop();

	exit(0);
}
