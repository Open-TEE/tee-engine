/*****************************************************************************
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

#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

#include "manager_shared_variables.h"
#include "manager_io_thread.h"
#include "com_protocol.h"
#include "h_table.h"
#include "trusted_app_properties.h"
#include "socket_help.h"
#include "epoll_wrapper.h"

static const int TA_SES_APPROX_COUNT = 30;
static const int EXIT_OUT_OF_SES_ID = 23;

static void handle_communication_err(proc_t err_proc, int proc_errno)
{
	/* Note: SIGPIPE error is catched and handler is empty */

	if (proc_errno == EPIPE) {
		syslog(LOG_ERR, "handle_communication_err: Socket other end is dead\n");

	} else if (proc_errno == EDQUOT) {

	} else if (proc_errno == EFBIG) {

	} else if (proc_errno == ENOSPC) {

	} else {
		/* Discard message and hope the problem will clear out :/ */
	}
}

static void add_msg_done_queue_and_notify(struct manager_msg *man_msg)
{
	const uint64_t event = 1;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&done_queue_mutex)) {
		syslog(LOG_ERR, "add_msg_done_queue: Failed to lock the mutex\n");
		return;
	}

	/* enqueue the task manager queue */
	list_add_before(&man_msg->list, &done_queue.list);

	if (pthread_mutex_unlock(&done_queue_mutex)) {
		/* For now, just log error */
		syslog(LOG_ERR, "add_msg_done_queue: Failed to lock the mutex\n");
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_fd, &event, sizeof(uint64_t)) == -1) {
		syslog(LOG_ERR, "add_msg_done_queue: Failed to notify the io thread\n");
		/* TODO: See what is causing it! */
	}
}

static void gen_err_msg_and_add_to_done(struct manager_msg *man_msg,
					com_err_t err_origin, com_err_t err_name)
{
	free(man_msg->msg); /* replace old message with error */
	gen_err_msg(man_msg, err_origin, err_name, 0);
	add_msg_done_queue_and_notify(man_msg);
}

static void gen_man_and_err_msg_and_add_to_done(proc_t to, com_err_t err_origin, com_err_t err_name)
{
	struct manager_msg *new_man_msg = NULL;

	new_man_msg = calloc(1, sizeof(struct manager_msg));
	if (!new_man_msg) {
		syslog(LOG_ERR, "gen_man_and_err_msg_and_add_to_done: Out of memory\n");
		return;
	}

	new_man_msg->proc = to;

	gen_err_msg_and_add_to_done(new_man_msg, err_origin, err_name);
}

static void ca_init_context(struct manager_msg *man_msg)
{
	struct com_msg_ca_init_tee_conn *init_msg = man_msg->msg;

	/* Valid init message */
	if (init_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
	    init_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "init_new_ca_conn: Parsing wrong message, ignore msg\n");
		goto err;
	}

	/* Message can be received only from client */
	if (man_msg->proc->p_type != ClientApp) {
		syslog(LOG_ERR, "init_new_ca_conn: Message can be received only from clientApp\n");
		goto err;
	}

	/* Valid message. Updated CA proc status to initialized */
	man_msg->proc->content.process.status = Initialized;

	/* Response to CA */
	init_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;

	add_msg_done_queue_and_notify(man_msg);

	return;

err:
	gen_err_msg_and_add_to_done(man_msg, TEEC_ORIGIN_TEE, TEEC_ERROR_COMMUNICATION);

	/* TODO: Remove client connection: CA table, close socket and unreg epoll!!## */
}

static int create_uninitialized_ta_proc(proc_t *new_ta)
{
	*new_ta = (proc_t)malloc(sizeof(struct __proc));
	if (!*new_ta) {
		syslog(LOG_ERR, "create_uninitialized_ta_proc: Out of memory");
		return 1;
	}

	(*new_ta)->p_type = TrustedApp;
	(*new_ta)->content.process.status = Uninitialized;

	h_table_create(&(*new_ta)->content.process.links, TA_SES_APPROX_COUNT);
	if (!(*new_ta)->content.process.links) {
		syslog(LOG_ERR, "create_uninitialized_ta_proc: Out of memory");
		free(*new_ta);
		return 1;
	}

	return 0;
}

static int get_session_id(sess_t *new_id)
{
	/* TODO: Rare, but after ~92 quadrillion session this will overflow */
	*new_id = next_proc_id;
	next_proc_id++;
	return 0;
}

static int alloc_and_init_sessLink(struct __proc **sesLink, proc_t owner, proc_t to, uint64_t ses_id)
{
	*sesLink = (proc_t)malloc(sizeof(struct __proc));
	if (!*sesLink) {
		syslog(LOG_ERR, "alloc_and_init_sessLink: Out of memory");
		return 1;
	}

	(*sesLink)->p_type = sessionLink;
	(*sesLink)->content.sesLink.status = session_initialized;
	(*sesLink)->content.sesLink.owner = owner;
	(*sesLink)->content.sesLink.to = to;
	(*sesLink)->content.sesLink.session_id = ses_id;

	return 0;
}

static int add_new_session_to_ta(proc_t owner,  proc_t to, void *open_ses_data,
				 int open_ses_data_len, uint64_t session_id, proc_t *new_sesLink)
{
	if (alloc_and_init_sessLink(new_sesLink, owner, to, session_id))
		return 1;

	/* Malloc and copy open session msg, because then we can proceed "normaly" */
	(*new_sesLink)->content.sesLink.open_session_data = calloc(1, open_ses_data_len);
	if (!(*new_sesLink)->content.sesLink.open_session_data) {
		syslog(LOG_ERR, "add_new_session_to_ta: Out of memory");
		return 1;
	}

	memcpy((*new_sesLink)->content.sesLink.open_session_data, open_ses_data, open_ses_data_len);
	(*new_sesLink)->content.sesLink.open_session_data_len = open_ses_data_len;

	if (h_table_insert(owner->content.process.links, &session_id, sizeof(sess_t), *new_sesLink)) {
		syslog(LOG_ERR, "add_new_session_to_ta: Out of memory");
		return 1;
	}

	return 0;
}

static int add_new_session_to_ca(proc_t owner, proc_t to, uint64_t session_id, proc_t *new_sesLink)
{
	if (alloc_and_init_sessLink(new_sesLink, owner, to, session_id))
		return 1;

	if (pthread_mutex_lock(&CA_table_mutex)) {
		syslog(LOG_ERR, "add_new_session_to_ca: Failed to lock the mutex\n");
		return 1;
	}

	if (h_table_insert(owner->content.process.links, &session_id, sizeof(uint64_t), *new_sesLink)) {
		syslog(LOG_ERR, "add_new_session_to_ta: Out of memory");
		return 1;
	}

	if (pthread_mutex_unlock(&CA_table_mutex)) {
		syslog(LOG_ERR, "add_new_session_to_ca: Failed to unlock the mutex\n");
		return 1;
	}

	return 0;
}

static int create_sesLink(proc_t owner, proc_t to, void *open_ses_data, int open_ses_data_len, sess_t sess_id)
{
	proc_t new_owner_ses = NULL;
	proc_t new_to_ses = NULL;

	if (owner->p_type == ClientApp && add_new_session_to_ca(owner, NULL, sess_id, &new_owner_ses))
		return 1;

	if (owner->p_type == TrustedApp && add_new_session_to_ta(owner, NULL, sess_id, NULL, 0, &new_owner_ses))
		return 1;

	if (add_new_session_to_ta(to, new_owner_ses, open_ses_data, open_ses_data_len, sess_id, &new_to_ses))
		return 1;

	new_owner_ses->content.sesLink.to = new_to_ses;

	return 0;
}

static void free_sess(proc_t del_sess)
{
	sess_t rem_sess_id;

	if (!del_sess || del_sess->p_type != sessionLink)
		return;

	rem_sess_id = del_sess->content.sesLink.session_id;
	free(del_sess->content.sesLink.open_session_data);

	if (del_sess->content.sesLink.owner->p_type == ClientApp) {

		if (del_sess->content.sesLink.status == session_active &&
		    epoll_unreg(del_sess->content.sesLink.sockfd) == -1)
			syslog(LOG_ERR, "free_sess: Failed to unreg socket, %i\n", errno);

		close(del_sess->content.sesLink.sockfd);
	}

	h_table_remove(del_sess->content.sesLink.owner->content.process.links, &rem_sess_id, sizeof(sess_t));
	free(del_sess);
}

static void remove_session_between(proc_t owner, proc_t to, uint64_t sess_id)
{
	proc_t del_sess;

	del_sess = h_table_get(owner->content.process.links, &sess_id, sizeof(sess_t));
	free_sess(del_sess);

	del_sess = h_table_get(to->content.process.links, &sess_id, sizeof(sess_t));
	free_sess(del_sess);
}

static void free_proc(proc_t del_proc)
{
	proc_t proc_sess = NULL;

	if (!del_proc || del_proc->p_type == sessionLink)
		return;

	/* Free process sessions
	 * Note: It is a programmer error he close session and there is session open */
	h_table_init_stepper(del_proc->content.process.links);
	while(1) {
		proc_sess = h_table_step(del_proc->content.process.links);
		if (proc_sess)
			free_sess(proc_sess);
		else
			break;
	}

	/* Free session hashtable */
	h_table_free(del_proc->content.process.links);

	/* Client process spesific operations */
	if (del_proc->p_type == ClientApp) {
		if (pthread_mutex_lock(&CA_table_mutex)) {
			syslog(LOG_ERR, "free_proc: Failed to lock the mutex\n");
			return; /* TODO: what to do? */
		}

		h_table_remove(clientApps, &del_proc->content.process.sockfd, sizeof(del_proc->content.process.sockfd));

		if (pthread_mutex_unlock(&CA_table_mutex)) {
			syslog(LOG_ERR, "free_proc: Failed to unlock the mutex\n");
			return; /* TODO: what to do? */
		}
	}

	/* Trusted process spesific operations */
	if (del_proc->p_type == TrustedApp) {

		/* TODO: Release file locks!! */

		h_table_remove(trustedApps, &del_proc->content.process.pid, sizeof(pid_t));
	}

	/* Unreg socket from epoll and close */
	if (epoll_unreg(del_proc->content.process.sockfd) == -1) {
		syslog(LOG_ERR, "free_proc: Failed to unreg socket\n");
	}

	close(del_proc->content.process.sockfd);
	free(del_proc);
}

static int finalize_session_intilization(struct manager_msg *man_msg, proc_t ta_session)
{
	struct com_msg_open_session *open_resp_msg = man_msg->msg;
	int sockfd[2];

	/* Session lin To status should be uninitialized */
	if (ta_session->content.sesLink.to->content.sesLink.status != session_initialized) {
		syslog(LOG_ERR, "finalize_session_intilization: Invalid TO session status\n");
		return 1;
	}

	/* create a socket pair for CA session and manager communication */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
		syslog(LOG_ERR, "finalize_session_intilization: Failed to create socket pair\n");
		return 1;
	}

	/* Reg CA session socket */
	if (epoll_reg_data(sockfd[0], EPOLLIN, ta_session->content.sesLink.to)) {
		syslog(LOG_ERR, "finalize_session_intilization: Epoll reg error\n");
		return 1;
	}

	ta_session->content.sesLink.to->content.sesLink.sockfd = sockfd[0];
	ta_session->content.sesLink.status = session_active;
	ta_session->content.sesLink.to->content.sesLink.status = session_active;
	open_resp_msg->sess_fd_to_caller = sockfd[1];

	return 0;
}

static void open_session_response(struct manager_msg *man_msg)
{
	struct com_msg_open_session *open_resp_msg = man_msg->msg;
	proc_t session;

	/* Message can be received only from trusted App! */
	if (man_msg->proc->p_type != TrustedApp ||
	    man_msg->proc->content.process.status != Initialized ||
	    open_resp_msg->msg_hdr.sender_type != TA) {
		syslog(LOG_ERR, "open_session_response: Invalid sender\n");
		goto ignore_msg;
	}

	session = h_table_get(man_msg->proc->content.process.links, &open_resp_msg->msg_hdr.sess_id, sizeof(sess_t));
	if (!session) {
		syslog(LOG_ERR, "open_session_response: Invalid session ID\n");
		goto ignore_msg;
	}

	if (session->content.sesLink.status != session_initialized) {
		syslog(LOG_ERR, "open_session_response: Invalid session status\n");
		goto ignore_msg;
	}

	/* Check received message answer and proceed according to that */
	if (open_resp_msg->return_code_open_session != TEE_SUCCESS)
		remove_session_between(session->content.sesLink.owner, session->content.sesLink.to, open_resp_msg->msg_hdr.sess_id);

	if (open_resp_msg->return_code_create_entry != TEE_SUCCESS)
		free_proc(session->content.sesLink.owner);

	if (open_resp_msg->return_code_create_entry == TEE_SUCCESS && open_resp_msg->return_code_open_session != TEE_SUCCESS) {
		/* TODO: should TA killed */
	}

	if (open_resp_msg->return_code_open_session == TEE_SUCCESS && finalize_session_intilization(man_msg, session))
		goto err;

	/* Update receiver info to message "address" */
	man_msg->proc = session->content.sesLink.to->content.sesLink.owner;
	add_msg_done_queue_and_notify(man_msg);
	return;

err:
	man_msg->proc = session->content.sesLink.to->content.sesLink.owner;
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
	remove_session_between(session->content.sesLink.owner, session->content.sesLink.to, open_resp_msg->msg_hdr.sess_id);
	/* TODO: should TA killed == KEEP ALIVE */
	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static int comm_launcher_to_launch_ta(void *msg, int msg_len, int *new_ta_fd, pid_t *new_ta_pid)
{
	struct com_msg_ta_created *recv_created_msg = NULL;
	int send_bytes;
	int recv_bytes;

	/* Communicationg directly to launcher */
	send_bytes = com_send_msg(launcher_fd, msg, msg_len);
	if (send_bytes == COM_RET_IO_ERROR) {
		/* socket is dead or something? Make here function call that figur out */
		return 1;
	}

	/* Receive launcer msg. In case of error, abort TA initialization */
	recv_bytes = com_wait_and_recv_msg(launcher_fd, &recv_created_msg, &recv_bytes, NULL);
	if (recv_bytes == COM_RET_IO_ERROR) {
		syslog(LOG_ERR, "comm_launcher_to_launch_ta: Invalid message (IO error)\n");
		return 1; /* TODO: check why IO error occur. Maybe launcher dead or crap at sock? */

	} else if (recv_bytes == COM_RET_OUT_OF_MEM) {
		syslog(LOG_ERR, "comm_launcher_to_launch_ta: Invalid message (out-of-mem)\n");
		return 1;

	} else if (recv_bytes == COM_RET_GENERIC_ERR) {
		syslog(LOG_ERR, "comm_launcher_to_launch_ta: Invalid message (generic error)\n");
		return 1;
	}

	if (recv_created_msg->msg_hdr.msg_name != COM_MSG_NAME_CREATED_TA ||
	    recv_created_msg->msg_hdr.msg_type != COM_TYPE_RESPONSE ||
	    recv_created_msg->msg_hdr.sender_type != Launcher) {
		syslog(LOG_ERR, "comm_launcher_to_launch_ta: Invalid message\n");
		free(recv_created_msg);
		return 1;
	}

	*new_ta_pid = recv_created_msg->pid;

	/* launcher is forking to new proc and creates sockpair. Other end will be send here. */
	if (recv_fd(launcher_fd, new_ta_fd) == -1) {
		syslog(LOG_ERR, "comm_launcher_to_launch_ta: Error at recv TA fd : %i\n", errno);
		fprintf(stderr, "%s\n", strerror(errno));
		kill(*new_ta_pid , SIGHUP);
		free(recv_created_msg);
		return 1;
	}

	free(recv_created_msg);
	return 0;
}

static int launch_and_init_ta(struct manager_msg *man_msg, TEE_UUID *ta_uuid,
			      proc_t *new_ta_proc, proc_t conn_ta)
{
	struct trusted_app_properties ta_properties;
	struct com_msg_open_session *open_sess_msg = man_msg->msg;
	int new_ta_fd;
	pid_t new_ta_pid;

	/* Init return values */
	*new_ta_proc = NULL;
	conn_ta = NULL;

	/* If trusted application exists at TA folder and get it properties. */
	if (get_ta_properties(ta_uuid, &ta_properties)) {
		syslog(LOG_ERR, "launch_and_init_ta: TA with requested UUID is not found\n");
		goto err_1;
	}

	/* Do we connect existing application or launch new */
	h_table_init_stepper(trustedApps);
	while (1) {
		conn_ta = h_table_step(trustedApps);
		if (!conn_ta)
			break;

		if (bcmp(&conn_ta->content.process.ta_uuid, ta_uuid, sizeof(TEE_UUID)))
			continue;
	}

	if (ta_properties.singleton_instance && conn_ta) {
		/* Singleton and TA running */
		return 0;
	}

	if (ta_properties.singleton_instance && !ta_properties.multi_session && conn_ta) {
		/* Singleton and running and not supporting multi session! */
		goto not_multi_session;
	}

	/* Launch new TA */
	memcpy(open_sess_msg->ta_lib_path_witn_name, ta_properties.ta_so_name_with_path, MAX_TA_PATH_NAME);
	if (comm_launcher_to_launch_ta(man_msg->msg, man_msg->msg_len, &new_ta_fd, &new_ta_pid)) {
		syslog(LOG_ERR, "launch_and_init_ta: Problem launching TA\n");
		goto err_1;
	}

	/* Note: TA is launched and its init process is on going now on its own proc */

	/* Init TA data to manager */
	if (create_uninitialized_ta_proc(new_ta_proc)) {
		goto err_2;
	}

	(*new_ta_proc)->content.process.sockfd = new_ta_fd;
	(*new_ta_proc)->content.process.pid = new_ta_pid;
	memcpy(&(*new_ta_proc)->content.process.ta_uuid, ta_uuid, sizeof(TEE_UUID));

	if (epoll_reg_data((*new_ta_proc)->content.process.sockfd, EPOLLIN, *new_ta_proc)) {
		syslog(LOG_ERR, "launch_and_init_ta: Epoll reg error\n");
		goto err_2;
	}

	if (h_table_insert(trustedApps, &new_ta_pid, sizeof(pid_t), *new_ta_proc)) {
		syslog(LOG_ERR, "launch_and_init_ta: out of memory\n");
		goto err_3;
	}

	/* TA ready for communication */
	(*new_ta_proc)->content.process.status = Initialized;

	return 0;

err_3:
	epoll_unreg((*new_ta_proc)->content.process.sockfd);
err_2:
	kill(new_ta_pid, SIGKILL);
	free_proc(*new_ta_proc);
	*new_ta_proc = NULL;
err_1:
	conn_ta = NULL;
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
	return 1;

not_multi_session:
	conn_ta = NULL;
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_ACCESS_CONFLICT);
	return 1;
}

static void open_session_query(struct manager_msg *man_msg)
{
	proc_t new_ta = NULL;
	proc_t conn_ta = NULL;
	sess_t new_session_id;
	struct com_msg_open_session *open_msg = man_msg->msg;

	/* Generate new session ID and assign it to message */
	if (get_session_id(&new_session_id)) {
		syslog(LOG_ERR, "open_session_query: Out of memory");
		goto err;
	}

	open_msg->msg_hdr.sess_id = new_session_id;

	/* Launch new TA, if needed */
	if (launch_and_init_ta(man_msg, &open_msg->uuid, &new_ta, conn_ta)) {
		/* Error message has been send */
		return;
	}

	/* Send invoke task to TA */
	if (conn_ta) {

		if (create_sesLink(man_msg->proc, conn_ta, man_msg->msg, man_msg->msg_len, new_session_id)) {
			/* Error message has been LOGGED (not send) */
			goto err;
		}

		/* Pass on open session cmd */
		man_msg->proc = conn_ta;
		add_msg_done_queue_and_notify(man_msg);

	} else if (new_ta) {

		if (create_sesLink(man_msg->proc, new_ta, man_msg->msg, man_msg->msg_len, new_session_id)) {
			/* Error message has been LOGGED (not send) */
			goto err;
		}

		/* Open session command is already send */

	} else {
		/* Should never end up here ! */
		syslog(LOG_ERR, "open_session_query: Error\n");
		exit(EXIT_FAILURE);
	}

	free_manager_msg(man_msg);
	return;

err:
	free_proc(new_ta);
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
}


static void open_session_msg(struct manager_msg *man_msg)
{
	struct com_msg_open_session *open_msg = man_msg->msg;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION) {
		/* Should never end up here */
		syslog(LOG_ERR, "open_session_msg: Handling wrong message\n");
		goto err;
	}

	if (man_msg->proc->p_type == ClientApp && man_msg->proc->content.process.status == Initialized) {
		open_msg->msg_hdr.sender_type = CA;

	} else if (man_msg->proc->p_type == TrustedApp) {
		open_msg->msg_hdr.sender_type = TA;

	} else {
		syslog(LOG_ERR, "open_session_msg: Invalid sender\n");
		goto err;
	}

	if (open_msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		open_session_query(man_msg);

	} else if (open_msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		open_session_response(man_msg);

	} else {
		syslog(LOG_ERR, "open_session_msg: Unkwon message type\n");
		goto err;
	}

	return;
err:
	free_manager_msg(man_msg);
}

static void invoke_cmd_query(struct manager_msg *man_msg)
{
	struct com_msg_invoke_cmd *invoke_msg = man_msg->msg;

	if (man_msg->proc->p_type != sessionLink) {
		syslog(LOG_ERR, "invoke_cmd_query: Invalid sender process\n");
		goto ignore_msg;
	}

	/* TODO: If session alive */

	if (man_msg->proc->content.sesLink.owner->p_type == ClientApp) {
		invoke_msg->msg_hdr.sender_type = CA;

	} else if (man_msg->proc->content.sesLink.owner->p_type == TrustedApp) {
		invoke_msg->msg_hdr.sender_type = TA;

	} else {
		syslog(LOG_ERR, "invoke_cmd_query: Invalid sender process\n");
		goto ignore_msg;
	}

	invoke_msg->session_id = man_msg->proc->content.sesLink.session_id;

	man_msg->proc = man_msg->proc->content.sesLink.to->content.sesLink.owner;
	add_msg_done_queue_and_notify(man_msg);

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static void invoke_cmd_response(struct manager_msg *man_msg)
{
	struct com_msg_invoke_cmd *invoke_resp_msg = man_msg->msg;
	proc_t session = NULL;

	/* TODO: If session alive */

	if (man_msg->proc->p_type == sessionLink) {
		syslog(LOG_ERR, "invoke_cmd_response: Invalid sender\n");
		goto ignore_msg;
	}

	session = h_table_get(man_msg->proc->content.process.links, &invoke_resp_msg->session_id, sizeof(sess_t));
	if (!session) {
		syslog(LOG_ERR, "invoke_cmd_response: Session is not found\n");
		goto ignore_msg;
	}

	man_msg->proc = session->content.sesLink.to;
	add_msg_done_queue_and_notify(man_msg);

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static void invoke_cmd(struct manager_msg *man_msg)
{
	struct com_msg_invoke_cmd *invoke_msg = man_msg->msg;

	/* Sender is not process, but session link, but sessionling owner process must be
	 * initialized */
	if (man_msg->proc->p_type == sessionLink &&
	    man_msg->proc->content.sesLink.status == session_active &&
	    man_msg->proc->content.sesLink.owner->content.process.status != Initialized) {
		syslog(LOG_ERR, "invoke_cmd: Invalid process status\n");
		goto ignore_msg;
	}

	/* Valid open session message */
	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD) {
		syslog(LOG_ERR, "invoke_cmd: Parsing wrong message, ignore msg\n");
		goto ignore_msg;
	}

	if (invoke_msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		invoke_cmd_query(man_msg);

	} else if (invoke_msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		invoke_cmd_response(man_msg);

	} else {
		syslog(LOG_ERR, "invoke_cmd: Unkwon message type or invalid sender\n");
		goto ignore_msg;
	}

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static int should_ta_destroy(proc_t ta_proc)
{
	struct trusted_app_properties ta_properties;

	if (get_ta_properties(&ta_proc->content.process.ta_uuid, &ta_properties)) {
		syslog(LOG_ERR, "should_ta_destroy: TA with requested UUID is not found\n");
		return -1;
	}

	if (ta_properties.instance_keep_alive)
		return 0;

	if (ta_properties.singleton_instance && !h_table_empty(ta_proc->content.process.links))
		return 0;

	return 1; /* Default action is destroy */
}

static void close_session(struct manager_msg *man_msg)
{
	struct com_msg_close_session *close_msg = man_msg->msg;
	proc_t ta_proc;

	/* Valid open session message */
	if (close_msg->msg_hdr.msg_name != COM_MSG_NAME_CLOSE_SESSION ||
	    close_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "close_session: Parsing wrong message, ignore msg\n");
		goto ignore_msg;
	}

	if (man_msg->proc->p_type != sessionLink) {
		syslog(LOG_ERR, "close_session: Invalid sender\n");
		goto ignore_msg;
	}

	ta_proc = man_msg->proc->content.sesLink.to->content.sesLink.owner;

	/* Update close message */
	close_msg->msg_hdr.sess_id = man_msg->proc->content.sesLink.session_id;
	close_msg->should_ta_destroy = should_ta_destroy(man_msg->proc->content.sesLink.owner);
	if (close_msg->should_ta_destroy == -1)
		goto ignore_msg;

	/* Remove sessions */
	remove_session_between(man_msg->proc->content.sesLink.owner,
			       man_msg->proc->content.sesLink.to->content.sesLink.owner,
			       man_msg->proc->content.sesLink.session_id);

	man_msg->proc = ta_proc; /* Update message address */
	add_msg_done_queue_and_notify(man_msg);

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static void ca_finalize_context(struct manager_msg *man_msg)
{

	struct com_msg_ca_finalize_constex *fin_con_msg = man_msg->msg;

	/* Valid init message */
	if (fin_con_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
	    fin_con_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		syslog(LOG_ERR, "init_new_ca_conn: Parsing wrong message, ignore msg\n");
		goto ignore_msg;
	}

	/* Message can be received only from client */
	if (man_msg->proc->p_type != ClientApp) {
		syslog(LOG_ERR, "init_new_ca_conn: Message can be received only from clientApp\n");
		goto ignore_msg;
	}

	free_proc(man_msg->proc);

	/* Response to CA */
	fin_con_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;

	add_msg_done_queue_and_notify(man_msg);

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

void *manager_logic_main_thread(void *arg)
{
	arg = arg; /* ignored */
	struct manager_msg *handled_msg;
	com_msg_hdr_t com_msg_name;

	while (1) {

		if (pthread_mutex_lock(&todo_queue_mutex)) {
			syslog(LOG_ERR, "manager_logic_main_thread: Failed to lock the mutex\n");
			continue;
		}

		// Wait for message
		while (list_is_empty(&todo_queue.list)) {
			if (pthread_cond_wait(&todo_queue_cond, &todo_queue_mutex)) {
				syslog(LOG_ERR, "manager_logic_main_thread: Failed to wait for condition\n");
				continue;
			}
		}

		/* Queue is FIFO and therefore get just fist message */
		handled_msg = LIST_ENTRY(todo_queue.list.next, struct manager_msg, list);
		list_unlink(&handled_msg->list);

		if (pthread_mutex_unlock(&todo_queue_mutex)) {
			syslog(LOG_ERR, "manager_logic_main_thread: Failed to lock the mutex\n");
			continue;
		}

		/* Manager message queue is released */

		/* Exctract messagese part */
		com_msg_name = com_get_msg_name(handled_msg->msg);

		//syslog(LOG_ERR, "manager_logic_main_thread: CMD start : %i\n", com_msg_name);

		switch (com_msg_name) {
		case COM_MSG_NAME_CA_INIT_CONTEXT:
			ca_init_context(handled_msg);
			break;

		case COM_MSG_NAME_ERROR:
			//error_msg(handled_msg);
			break;

		case COM_MSG_NAME_OPEN_SESSION:
			open_session_msg(handled_msg);
			break;

		case COM_MSG_NAME_INVOKE_CMD:
			invoke_cmd(handled_msg);
			break;

		case COM_MSG_NAME_CLOSE_SESSION:
			close_session(handled_msg);
			break;

		case COM_MSG_NAME_CA_FINALIZ_CONTEXT:
			ca_finalize_context(handled_msg);
			break;

		default:
			/* Just logging an error and message will be ignored */
			syslog(LOG_ERR, "manager_logic_main_thread: Unknow message, ignore\n");
			free_manager_msg(handled_msg);
		}

		//syslog(LOG_ERR, "manager_logic_main_thread: CMD ended : %i\n", com_msg_name);

	}
}
