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
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "com_protocol.h"
#include "extern_resources.h"
#include "h_table.h"
#include "io_thread.h"
#include "socket_help.h"
#include "ta_dir_watch.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "logic_thread.h"

/* Used for hashtable init */
#define TA_SESS_COUNT_EST 50

static void release_ta_file_locks(proc_t ta)
{
	ta = ta;
	/* TODO: Implement */
}

static void add_and_notify_io_sock_to_close(int fd)
{
	struct sock_to_close *fd_to_close = NULL;
	const uint64_t event = 1;

	/* Notify logic thread */
	fd_to_close = calloc(1, sizeof(struct sock_to_close));
	if (!fd_to_close) {
		OT_LOG(LOG_ERR, "out-of-memory");
		return;
	}

	fd_to_close->sockfd = fd;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&socks_to_close_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		free(fd_to_close);
		return;
	}

	list_add_after(&fd_to_close->list, &socks_to_close.list);

	if (pthread_mutex_unlock(&socks_to_close_mutex)) {
		/* For now, just log error */
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_close_sock, &event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to notify the io thread");
		/* TODO: See what is causing it! */
	}
}

static void free_sess(proc_t del_sess)
{
	if (!del_sess || del_sess->p_type != proc_t_link)
		return;

	/* Session in TA is not using socket. All messages from TA will arive to TA process socket.
	 * And if session is active, function is called from close session function */
	if (del_sess->content.sesLink.owner->p_type == proc_t_CA &&
	    del_sess->content.sesLink.status == sess_active) {

		if (epoll_unreg(del_sess->sockfd) == -1)
			OT_LOG(LOG_ERR, "Failed to unreg socket");

		/* If functions fails. we will leaking FDs */
		add_and_notify_io_sock_to_close(del_sess->sockfd);
	}

	h_table_remove(del_sess->content.sesLink.owner->content.process.links,
		       (unsigned char *)&del_sess->content.sesLink.session_id, sizeof(uint64_t));

	free(del_sess);
	del_sess = NULL;
}

static void free_proc(proc_t del_proc)
{
	proc_t proc_sess = NULL;

	if (!del_proc || del_proc->p_type == proc_t_link)
		return;

	/* Free process sessions
	 * Note: It is a programmer error, if he close session and there is session open */
	h_table_init_stepper(del_proc->content.process.links);
	while (1) {
		proc_sess = h_table_step(del_proc->content.process.links);
		if (proc_sess)
			free_sess(proc_sess);
		else
			break;
	}

	/* Free session hashtable */
	h_table_free(del_proc->content.process.links);

	/* Client process spesific operations */
	if (del_proc->p_type == proc_t_CA && pthread_mutex_lock(&CA_table_mutex) == -1) {

		h_table_remove(clientApps,
			       (unsigned char *)&del_proc->sockfd, sizeof(del_proc->sockfd));

		if (pthread_mutex_unlock(&CA_table_mutex))
			OT_LOG(LOG_ERR, "Failed to unlock the mutex");
	}

	/* Trusted process spesific operations */
	if (del_proc->p_type == proc_t_TA) {
		release_ta_file_locks(del_proc);
		h_table_remove(trustedApps,
			       (unsigned char *)&del_proc->content.process.pid, sizeof(pid_t));
	}

	/* Unreg socket from epoll and close */
	if ((del_proc->content.process.status == proc_uninitialized ||
	     del_proc->content.process.status == proc_initialized) &&
	    epoll_unreg(del_proc->sockfd) == -1)
		OT_LOG(LOG_ERR, "Failed to unreg socket");

	add_and_notify_io_sock_to_close(del_proc->sockfd);

	free(del_proc);
	del_proc = NULL;
}

static void add_msg_done_queue_and_notify(struct manager_msg *man_msg)
{
	const uint64_t event = 1;

	/* Lock task queue from logic thread */
	if (pthread_mutex_lock(&done_queue_mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		return;
	}

	/* enqueue the task manager queue */
	list_add_before(&man_msg->list, &done_queue.list);

	if (pthread_mutex_unlock(&done_queue_mutex)) {
		/* For now, just log error */
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
	}

	/* notify the I/O thread that there is something at output queue */
	if (write(event_done_queue_fd, &event, sizeof(uint64_t)) == -1) {
		OT_LOG(LOG_ERR, "Failed to notify the io thread");
		/* TODO/PLACEHOLDER: notify IO thread */
	}
}

static void gen_err_msg_and_add_to_done(struct manager_msg *man_msg, uint32_t err_origin,
					uint32_t err_name)
{
	free(man_msg->msg); /* replace old message with error */

	man_msg->msg = calloc(1, sizeof(struct com_msg_error));
	if (!man_msg->msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		return;
	}

	man_msg->msg_len = sizeof(struct com_msg_error);

	/* Fill error message */
	((struct com_msg_error *)man_msg->msg)->msg_hdr.msg_name = COM_MSG_NAME_ERROR;
	((struct com_msg_error *)man_msg->msg)->ret_origin = err_origin;
	((struct com_msg_error *)man_msg->msg)->ret = err_name;

	add_msg_done_queue_and_notify(man_msg);
}

static void ca_init_context(struct manager_msg *man_msg)
{
	struct com_msg_ca_init_tee_conn *init_msg;

	if (!man_msg)
		return;

	init_msg = man_msg->msg;

	/* Valid init message */
	if (init_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
	    init_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Parsing wrong message, ignore msg");
		goto discard_msg;
	}

	/* Message can be received only from client */
	if (man_msg->proc->p_type != proc_t_CA) {
		OT_LOG(LOG_ERR, "Message can be received only from clientApp");
		goto discard_msg;
	}

	/* Valid message. Updated CA proc status to initialized */
	man_msg->proc->content.process.status = proc_initialized;

	/* Response to CA */
	init_msg->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	init_msg->ret = TEE_SUCCESS;

	add_msg_done_queue_and_notify(man_msg);

	return;

discard_msg:
	free(man_msg);
}

static void remove_session_between(proc_t owner, proc_t to, uint64_t sess_id)
{
	free_sess(h_table_get(owner->content.process.links, (unsigned char *)(&sess_id),
			      sizeof(uint64_t)));

	free_sess(h_table_get(to->content.process.links, (unsigned char *)(&sess_id),
			      sizeof(uint64_t)));
}

static void open_session_response(struct manager_msg *man_msg)
{
	struct com_msg_open_session *open_resp_msg = man_msg->msg;
	int sockfd[2];
	proc_t ta_session;

	/* Message can be received only from trusted App! */
	if (man_msg->proc->p_type != proc_t_TA ||
	    man_msg->proc->content.process.status != proc_initialized) {
		OT_LOG(LOG_ERR, "Invalid sender");
		goto ignore_msg;
	}

	/* Sender is TA. Lets get TA session from TA proc session links */
	ta_session =
	    h_table_get(man_msg->proc->content.process.links,
			(unsigned char *)(&open_resp_msg->msg_hdr.sess_id), sizeof(uint64_t));
	if (!ta_session) {
		OT_LOG(LOG_ERR, "Invalid session ID");
		goto ignore_msg;
	}

	if (ta_session->content.sesLink.status != sess_initialized ||
	    ta_session->content.sesLink.to->content.sesLink.status != sess_initialized) {
		OT_LOG(LOG_ERR, "Invalid TA or TA session TO status");
		goto ignore_msg;
	}

	/* Check received message answer and proceed according to that */

	if (open_resp_msg->return_code_open_session != TEE_SUCCESS) {

		remove_session_between(ta_session->content.sesLink.owner,
				       ta_session->content.sesLink.to,
				       open_resp_msg->msg_hdr.sess_id);

	} else {

		/* create a socket pair for CA session and manager communication */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1) {
			OT_LOG(LOG_ERR, "Failed to create socket pair");
			goto err_1;
		}

		/* Reg CA session socket */
		if (epoll_reg_data(sockfd[0], EPOLLIN, ta_session->content.sesLink.to))
			goto err_2; /* Err msg logged */

		ta_session->content.sesLink.to->sockfd = sockfd[0];
		ta_session->content.sesLink.status = sess_active;
		ta_session->content.sesLink.to->content.sesLink.status = sess_active;
		open_resp_msg->sess_fd_to_caller = sockfd[1];
	}

	/* Send message to its initial sender
	 * man_msg->proc will be used as message "address" */
	man_msg->proc = ta_session->content.sesLink.to->content.sesLink.owner;
	add_msg_done_queue_and_notify(man_msg);
	return;

err_2:
	close(sockfd[0]);
	close(sockfd[1]);
err_1:
	man_msg->proc = ta_session->content.sesLink.to->content.sesLink.owner;
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
	remove_session_between(ta_session->content.sesLink.owner, ta_session->content.sesLink.to,
			       open_resp_msg->msg_hdr.sess_id);
	/* TODO: should TA killed == KEEP ALIVE */
	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static void get_next_sess_id(uint64_t *new_id)
{
	/* TODO: Rare, but after ~92 quadrillion session this will overflow */
	static uint64_t next_sess_id;

	*new_id = next_sess_id++;
}

static int create_uninitialized_ta_proc(proc_t *new_ta, TEE_UUID *ta_uuid)
{
	*new_ta = (proc_t)calloc(1, sizeof(struct __proc));
	if (!*new_ta) {
		OT_LOG(LOG_ERR, "Out of memory");
		return 1;
	}

	h_table_create(&(*new_ta)->content.process.links, TA_SESS_COUNT_EST);
	if (!(*new_ta)->content.process.links) {
		OT_LOG(LOG_ERR, "Out of memory");
		free(*new_ta);
		return 1;
	}

	(*new_ta)->p_type = proc_t_TA;
	(*new_ta)->content.process.status = proc_uninitialized;
	memcpy(&(*new_ta)->content.process.ta_uuid, ta_uuid, sizeof(TEE_UUID));

	return 0;
}

static proc_t get_ta_by_uuid(TEE_UUID *uuid)
{
	proc_t ta = NULL;

	h_table_init_stepper(trustedApps);

	while (1) {
		ta = (proc_t)h_table_step(trustedApps);
		if (!ta)
			break; /* TA is not running, return NULL */

		if (!bcmp(&ta->content.process.ta_uuid, uuid, sizeof(TEE_UUID)))
			break; /* TA running, return proc ptr */
	}

	return ta;
}

static int comm_launcher_to_launch_ta(struct manager_msg *man_msg, int *new_ta_fd,
				      pid_t *new_ta_pid)
{
	struct com_msg_ta_created *recv_created_msg = NULL;

	/* Initialize new ta pid -1 in purpose of error handling in this function */
	*new_ta_pid = -1;

	/* Communicating directly to launcher */
	if (com_send_msg(launcher_fd, man_msg->msg, man_msg->msg_len) != man_msg->msg_len) {
		/* TODO: Why socket failing */
		OT_LOG(LOG_ERR, "Communication proble to launcher");
		goto err;
	}

	/* Note: After this point we might receive signal SIGCHLD */

	/* Receive launcer msg. In case of error, abort TA initialization */
	if (com_recv_msg(launcher_fd, (void **)(&recv_created_msg), NULL)) {
		/* TODO: Why socket failing */
		OT_LOG(LOG_ERR, "failed to receive ta create message");
		goto err;
	}

	if (recv_created_msg->msg_hdr.msg_name != COM_MSG_NAME_CREATED_TA ||
	    recv_created_msg->msg_hdr.msg_type != COM_TYPE_RESPONSE) {
		OT_LOG(LOG_ERR, "Invalid message\n");
		goto err;
	}

	if (recv_created_msg->pid == -1) {
		/* If PID is -1, fork/clone failed! */
		OT_LOG(LOG_ERR, "Problem in TA launching");
		goto err;
	}

	*new_ta_pid = recv_created_msg->pid;

	/* launcher is forking to new proc and creates sockpair. Other end will be send here. */
	if (recv_fd(launcher_fd, new_ta_fd) == -1) {
		OT_LOG(LOG_ERR, "Error at recv TA fd");
		goto err;
	}

	free(recv_created_msg);
	return 0;

err:
	if (*new_ta_pid != -1)
		kill(*new_ta_pid, SIGKILL);

	free(recv_created_msg);
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
	return 1;
}

static int connect_to_ta(struct manager_msg *man_msg, proc_t *conn_ta, TEE_UUID *ta_uuid,
			 struct trusted_app_propertie *ta_propertie)
{
	int ret = 0;

	*conn_ta = get_ta_by_uuid(ta_uuid);
	if (*conn_ta)
		return 0; /* Connect to existing, because ta is running/loaded */

	if (ta_dir_watch_lock_mutex())
		return 1; /* Err msg logged */

	/* If trusted application exists at TA folder and get it properties. */
	ta_propertie = ta_dir_watch_props(ta_uuid);
	if (!ta_propertie) {
		OT_LOG(LOG_ERR, "TA with requested UUID is not found");
		gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_BAD_PARAMETERS);
		ret = 1;
		goto ret;
	}

	memcpy(&((struct com_msg_open_session *)man_msg->msg)->ta_so_name,
	       ta_propertie->ta_so_name, TA_MAX_FILE_NAME);

	if (ta_propertie->user_config.singletonInstance) {
		ret = 0;
		goto ret; /* Singleton and TA running */
	}

	if (ta_propertie->user_config.singletonInstance &&
	    !ta_propertie->user_config.multiSession) {
		/* Singleton and running and not supporting multi session! */
		gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_ACCESS_CONFLICT);
		ret = 1;
	}

ret:
	ta_dir_watch_unlock_mutex();
	return ret;
}

static int launch_and_init_ta(struct manager_msg *man_msg, TEE_UUID *ta_uuid, proc_t *new_ta_proc,
			      proc_t *conn_ta)
{
	struct trusted_app_propertie *ta_propertie = NULL;
	pid_t new_ta_pid = 0; /* Zero for compiler warning */

	/* Init return values */
	*new_ta_proc = (proc_t)malloc(sizeof(struct __proc));
	*conn_ta = NULL; /* NULL for compiler warning */

	if (connect_to_ta(man_msg, conn_ta, ta_uuid, ta_propertie))
		return 1; /* Err logged and send */

	if (*conn_ta)
		return 0; /* Connect to existing TA */

	/* Connection to new TA -> TA will be created */
	if (create_uninitialized_ta_proc(new_ta_proc, ta_uuid)) {
		/* Err logged and just send err to sender*/
		gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
		return 1;
	}

	/* Launch new TA */
	if (comm_launcher_to_launch_ta(man_msg, &(((*new_ta_proc)->sockfd)),
				       &((*new_ta_proc)->content.process.pid))) {
		free(*new_ta_proc);
		return 1; /* Err logged and send */
	}

	/* Note: TA is launched and its init process is on going now on its own proc */

	if (epoll_reg_data((*new_ta_proc)->sockfd, EPOLLIN, *new_ta_proc)) {
		OT_LOG(LOG_ERR, "Epoll reg error");
		goto err_1;
	}

	if (h_table_insert(trustedApps, (unsigned char *)&((*new_ta_proc)->content.process.pid),
			   sizeof(pid_t), *new_ta_proc)) {
		OT_LOG(LOG_ERR, "out of memory");
		goto err_2;
	}

	/* TA ready for communication */
	(*new_ta_proc)->content.process.status = proc_initialized;

	return 0;

err_2:
	epoll_unreg((*new_ta_proc)->sockfd);
err_1:
	kill(new_ta_pid, SIGKILL);
	free_proc(*new_ta_proc);
	*conn_ta = NULL;
	*new_ta_proc = NULL;
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);

	return 1;
}

static int alloc_and_init_sessLink(struct __proc **sesLink, proc_t owner, proc_t to,
				   uint64_t sess_id)
{
	*sesLink = (proc_t)malloc(sizeof(struct __proc));
	if (!*sesLink) {
		OT_LOG(LOG_ERR, "Out of memory");
		return 1;
	}

	(*sesLink)->p_type = proc_t_link;
	(*sesLink)->content.sesLink.status = sess_initialized;
	(*sesLink)->content.sesLink.owner = owner;
	(*sesLink)->content.sesLink.to = to;
	(*sesLink)->content.sesLink.session_id = sess_id;

	return 0;
}

static int add_new_session_to_proc(proc_t owner, proc_t to, uint64_t session_id,
				   proc_t *new_sesLink)
{
	if (alloc_and_init_sessLink(new_sesLink, owner, to, session_id))
		return 1;

	if (h_table_insert(owner->content.process.links, (unsigned char *)&session_id,
			   sizeof(uint64_t), *new_sesLink)) {
		OT_LOG(LOG_ERR, "Out of memory");
		return 1;
	}

	return 0;
}

static int create_sesLink(proc_t owner, proc_t to, uint64_t sess_id)
{
	proc_t new_owner_ses = NULL;
	proc_t new_to_ses = NULL;

	/* Following code will be generating two session link and cross linking sessions to gether
	 */

	if (add_new_session_to_proc(owner, NULL, sess_id, &new_owner_ses))
		return 1;

	if (add_new_session_to_proc(to, new_owner_ses, sess_id, &new_to_ses))
		return 1;

	new_owner_ses->content.sesLink.to = new_to_ses;

	return 0;
}

static void open_session_query(struct manager_msg *man_msg)
{
	proc_t new_ta = NULL;
	proc_t conn_ta = NULL;
	uint64_t new_session_id;
	struct com_msg_open_session *open_msg = man_msg->msg;

	/* Generate new session ID */
	get_next_sess_id(&new_session_id);

	/* SessID is needed when message is sent back from TA */
	open_msg->msg_hdr.sess_id = new_session_id;

	/* Launch new TA, if needed */
	if (launch_and_init_ta(man_msg, &open_msg->uuid, &new_ta, &conn_ta))
		return; /* Err msg logged and send to sender */

	/* If new_ta is NULL, should connect existing TA (conn_ta is not NULL)
	 * If conn_ta is NULL, new ta created and connect to that  (new_ta is not null)
	 * If conn_ta is NULL and new_ta NULL, should never happen */

	/* Send invoke task to TA */
	if (conn_ta) {

		if (create_sesLink(man_msg->proc, conn_ta, new_session_id))
			goto err; /* Err msg logged */

		/* Pass on open session cmd
		 * Know error: If this message send fails, CA will be waiting forever, because
		 * no error message is not send */
		man_msg->proc = conn_ta;
		add_msg_done_queue_and_notify(man_msg);

	} else if (new_ta) {

		if (create_sesLink(man_msg->proc, new_ta, new_session_id))
			goto err; /* Err msg logged */

		/* Open session command is already send */

		free_manager_msg(man_msg); /* TA will send response message */

	} else {
		/* Should never end up here ! */
		OT_LOG(LOG_ERR, "Error");
		goto err;
	}

	return;

err:
	free_proc(new_ta);
	gen_err_msg_and_add_to_done(man_msg, TEE_ORIGIN_TEE, TEE_ERROR_GENERIC);
}

static void open_session_msg(struct manager_msg *man_msg)
{
	struct com_msg_open_session *open_msg = man_msg->msg;

	if (open_msg->msg_hdr.msg_name != COM_MSG_NAME_OPEN_SESSION) {
		OT_LOG(LOG_ERR, "Handling wrong message");
		goto discard_msg;
	}

	/* Function is only valid for proc FDs */
	if (man_msg->proc->p_type == proc_t_link ||
	    man_msg->proc->content.process.status != proc_initialized) {
		OT_LOG(LOG_ERR, "Invalid sender or senders status");
		goto discard_msg;
	}

	/* Query and response will handle in their own functions */
	if (open_msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		open_session_query(man_msg);

	} else if (open_msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		open_session_response(man_msg);

	} else {
		OT_LOG(LOG_ERR, "Unkwon message type");
		goto discard_msg;
	}

	return;

discard_msg:
	free_manager_msg(man_msg);
}

static void invoke_cmd_query(struct manager_msg *man_msg)
{
	((struct com_msg_invoke_cmd *)man_msg->msg)->session_id =
	    man_msg->proc->content.sesLink.session_id;

	man_msg->proc = man_msg->proc->content.sesLink.to->content.sesLink.owner;
	add_msg_done_queue_and_notify(man_msg);
}

static void invoke_cmd_response(struct manager_msg *man_msg)
{
	struct com_msg_invoke_cmd *invoke_resp_msg = man_msg->msg;
	proc_t session = NULL;

	/* REsponse to invoke to command can be received only from TA */
	if (man_msg->proc->p_type != proc_t_TA) {
		OT_LOG(LOG_ERR, "Invalid sender");
		goto ignore_msg;
	}

	session = h_table_get(man_msg->proc->content.process.links,
			      (unsigned char *)(&invoke_resp_msg->session_id), sizeof(uint64_t));
	if (!session) {
		OT_LOG(LOG_ERR, "Session is not found");
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

	/* Session link can only be sender */
	if (man_msg->proc->p_type >= proc_t_last) {
		OT_LOG(LOG_ERR, "Invalid sender");
		goto ignore_msg;
	}

	/* Valid open session message */
	if (invoke_msg->msg_hdr.msg_name != COM_MSG_NAME_INVOKE_CMD) {
		OT_LOG(LOG_ERR, "Invalid message");
		goto ignore_msg;
	}

	/* TODO: Panic handling. Here should be logic, which checks session status! */

	if (invoke_msg->msg_hdr.msg_type == COM_TYPE_QUERY) {
		invoke_cmd_query(man_msg);

	} else if (invoke_msg->msg_hdr.msg_type == COM_TYPE_RESPONSE) {
		invoke_cmd_response(man_msg);

	} else {
		OT_LOG(LOG_ERR, "Unkwon msg type");
		goto ignore_msg;
	}

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

static void ca_finalize_context(struct manager_msg *man_msg)
{
	struct com_msg_ca_finalize_constex *fin_con_msg = man_msg->msg;

	/* Valid init message */
	if (fin_con_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_FINALIZ_CONTEXT ||
	    fin_con_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Parsing wrong message, ignore msg");
		goto ignore_msg;
	}

	/* Message can be received only from client */
	if (man_msg->proc->p_type != proc_t_CA) {
		OT_LOG(LOG_ERR, "Message can be received only from clientApp");
		goto ignore_msg;
	}

	free_proc(man_msg->proc); /* Del client proc */

ignore_msg:
	free_manager_msg(man_msg);
}

static bool active_sess_in_ta(proc_t ta_proc)
{
	proc_t sess;

	h_table_init_stepper(ta_proc->content.process.links);

	while (1) {
		sess = h_table_step(ta_proc->content.process.links);
		if (!sess)
			return false;

		/* Initialized means that there might be an open session message out */
		if (sess->content.sesLink.status == sess_active ||
		    sess->content.sesLink.status == sess_initialized)
			return true;
	}
}

/*!
 * \brief should_ta_destroy
 * \param ta_proc
 * \return If TA should destroy, return 1.
 * If TA should not destroy, return 0.
 * In case of error (e.g. TA not found in TA directory), return -1
 */
static int should_ta_destroy(proc_t ta_proc)
{
	struct trusted_app_propertie *ta_properties;
	int ret = 0; /* Default action is not to destroy */

	if (ta_dir_watch_lock_mutex())
		return -1; /* Err logged */

	ta_properties = ta_dir_watch_props(&ta_proc->content.process.ta_uuid);
	if (!ta_properties) {
		OT_LOG(LOG_ERR, "TA with requested UUID is not found");
		ret = -1;
		goto unlock;
	}

	/* Keep alive instance is never terminated */
	if (ta_properties->user_config.instanceKeepAlive) {
		ret = 0;
		goto unlock;
	}

	/* TA might be signleton or multi-instance TA, but if there is no session opens, terminate
	 */
	if (active_sess_in_ta(ta_proc))
		ret = 1;

unlock:
	ta_dir_watch_unlock_mutex();

	return ret;
}

static void close_session(struct manager_msg *man_msg)
{
	struct com_msg_close_session *close_msg = man_msg->msg;
	proc_t ta_proc;

	/* Valid open session message */
	if (close_msg->msg_hdr.msg_name != COM_MSG_NAME_CLOSE_SESSION ||
	    close_msg->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Invalid message");
		goto ignore_msg;
	}

	if (man_msg->proc->p_type != proc_t_link) {
		OT_LOG(LOG_ERR, "Invalid sender");
		goto ignore_msg;
	}

	/* Save session TO proc addr, because session might be removed */
	ta_proc = man_msg->proc->content.sesLink.to->content.sesLink.owner;

	/* Update close message */
	close_msg->should_ta_destroy =
	    should_ta_destroy(man_msg->proc->content.sesLink.to->content.sesLink.owner);
	if (close_msg->should_ta_destroy == -1) {
		goto ignore_msg;

	} else if (close_msg->should_ta_destroy == 1) {
		/* Session is not removed. It will be removed when TA exit */
		man_msg->proc->content.sesLink.status = sess_closed;
		man_msg->proc->content.sesLink.to->content.sesLink.status = sess_closed;
		/* No new open session message to TA */
		man_msg->proc->content.sesLink.owner->content.process.status = proc_disconnected;

	} else {
		/* Remove sessions, because TA will be not terminated */
		remove_session_between(man_msg->proc->content.sesLink.owner,
				       man_msg->proc->content.sesLink.to->content.sesLink.owner,
				       man_msg->proc->content.sesLink.session_id);
	}

	man_msg->proc = ta_proc;
	add_msg_done_queue_and_notify(man_msg);

	return;

ignore_msg:
	free_manager_msg(man_msg);
}

void *logic_thread_mainloop(void *arg)
{
	arg = arg; /* ignored */
	struct manager_msg *handled_msg;
	uint8_t com_msg_name;

	while (1) {

		if (pthread_mutex_lock(&todo_queue_mutex)) {
			OT_LOG(LOG_ERR, "Failed to lock the mutex");
			continue;
		}

		/* Wait for message */
		while (list_is_empty(&todo_queue.list)) {
			if (pthread_cond_wait(&todo_queue_cond, &todo_queue_mutex)) {
				OT_LOG(LOG_ERR, "Failed to wait for condition");
				continue;
			}
		}

		/* Queue is FIFO and therefore get just fist message */
		handled_msg = LIST_ENTRY(todo_queue.list.next, struct manager_msg, list);
		list_unlink(&handled_msg->list);

		if (pthread_mutex_unlock(&todo_queue_mutex)) {
			OT_LOG(LOG_ERR, "Failed to lock the mutex");
			continue;
		}

		/* Manager message queue is released */

		/* Exctract messagese part */
		if (com_get_msg_name(handled_msg->msg, &com_msg_name)) {
			OT_LOG(LOG_ERR, "Error with message, discarding");
			free_manager_msg(handled_msg);
			continue;
		}

		if (!handled_msg->proc) {
			OT_LOG(LOG_ERR, "Error with sender details");
			free_manager_msg(handled_msg);
			continue;
		}

		switch (com_msg_name) {
		case COM_MSG_NAME_PROC_STATUS_CHANGE:

			break;

		case COM_MSG_NAME_FD_ERR:

			break;

		case COM_MSG_NAME_CA_INIT_CONTEXT:
			ca_init_context(handled_msg);
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
			OT_LOG(LOG_ERR, "Unknow message, ignore");
			free_manager_msg(handled_msg);
		}
	}

	/* should never reach here */
	OT_LOG(LOG_ERR, "Logic thread is about to exit");
	exit(EXIT_FAILURE); /* TODO: Replace this function with kill tee gracefully */
	return NULL;
}
