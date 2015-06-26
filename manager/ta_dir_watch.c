/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

#include <dirent.h>
#include <errno.h>
#include <gelf.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "conf_parser.h"
#include "com_protocol.h"
#include "core_control_resources.h"
#include "elf_read.h"
#include "epoll_wrapper.h"
#include "extern_resources.h"
#include "io_thread.h"
#include "ta_dir_watch.h"
#include "tee_list.h"
#include "tee_ta_properties.h"
#include "tee_logging.h"

struct loaded_ta {
	struct list_head list;
	struct trusted_app_propertie ta;
};

static const char *seek_section_name = PROPERTY_SEC_NAME;
struct core_control *control_params;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct loaded_ta ta_dir_table;
static int inotify_fd;
static int inotify_wd;
static uint32_t inotify_flags =
		IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

static void free_ta(struct trusted_app_propertie *ta)
{
	struct manager_msg *new_man_msg = NULL;

	new_man_msg = calloc(1, sizeof(struct manager_msg));
	if (!new_man_msg) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		return;
	}

	new_man_msg->msg = calloc(1, sizeof(struct com_msg_ta_rem_from_dir));
	if (!new_man_msg->msg) {
		OT_LOG(LOG_ERR, "Out of memory\n");
		free(new_man_msg);
		return;
	}

	((struct com_msg_ta_rem_from_dir *)new_man_msg->msg)->msg_hdr.msg_name =
			COM_MSG_NAME_TA_REM_FROM_DIR;

	memcpy(&((struct com_msg_ta_rem_from_dir *)new_man_msg->msg)->uuid,
	       &ta->user_config.appID, sizeof(TEE_UUID));

	add_man_msg_inbound_queue_and_notify(new_man_msg);
}

static void remove_all_tas()
{
	struct loaded_ta *ta = NULL;
	struct list_head *pos, *la;

	if (ta_dir_watch_lock_mutex()) {
		/* Lets hope that errot clear it shelf..
		 * Know error: Might end up dublicate entries */
		return;
	}

	if (!list_is_empty(&ta_dir_table.list)) {

		LIST_FOR_EACH_SAFE(pos, la, &ta_dir_table.list) {
			ta = LIST_ENTRY(pos, struct loaded_ta, list);
			list_unlink(&ta->list);
			free_ta(&ta->ta);
		}
	}

	ta_dir_watch_unlock_mutex();
}

static bool does_name_and_uuid_in_table(struct trusted_app_propertie *new_ta)
{
	struct loaded_ta *ta_in_table;
	struct list_head *pos;
	bool ret = false;

	if (ta_dir_watch_lock_mutex())
		return true;

	if (list_is_empty(&ta_dir_table.list))
		goto end;

	LIST_FOR_EACH(pos, &ta_dir_table.list) {

		ta_in_table = LIST_ENTRY(pos, struct loaded_ta, list);

		if (!strncasecmp(ta_in_table->ta.ta_so_name, new_ta->ta_so_name,
				 strlen(ta_in_table->ta.ta_so_name))) {
			OT_LOG(LOG_ERR, "TA .so name: %s : is already in use",
			       ta_in_table->ta.ta_so_name);
			ret = true;
			goto end;
		}

		if (!memcmp(&ta_in_table->ta.user_config.appID, &new_ta->user_config.appID,
			  sizeof(TEE_UUID))) {
			OT_LOG(LOG_ERR, "TAs has same UUID: %s : %s",
			       ta_in_table->ta.ta_so_name, new_ta->ta_so_name);
			ret = true;
			goto end;
		}
	}

end:
	ta_dir_watch_unlock_mutex();
	return ret;
}

static void delete_ta(char *name)
{
	struct loaded_ta *ta = NULL;
	struct list_head *pos, *la;

	if (ta_dir_watch_lock_mutex()) {
		/* Lets hope that errot clear it shelf..
		 * Know error: Might end up dublicate entries */
		return;
	}

	if (list_is_empty(&ta_dir_table.list))
		goto end;

	LIST_FOR_EACH_SAFE(pos, la, &ta_dir_table.list) {

		ta = LIST_ENTRY(pos, struct loaded_ta, list);

		if (strncasecmp(name, ta->ta.ta_so_name, TA_MAX_FILE_NAME) != 0)
			continue;

		/* Found */
		list_unlink(&ta->list);
		free_ta(&ta->ta);
		free(ta);
		break;
	}

end:
	ta_dir_watch_unlock_mutex();
}

static void add_new_ta(char *name)
{
	char ta_with_path[MAX_PATH_NAME] = {0};
	struct loaded_ta *new_ta_propertie = NULL;
	size_t ta_user_config_size = sizeof(struct gpd_ta_config);

	if (!name || strlen(name) > TA_MAX_FILE_NAME) {
		OT_LOG(LOG_ERR, "name is null or too long");
		return;
	}

	if (snprintf(ta_with_path, MAX_PATH_NAME, "%s/%s",
		     control_params->opentee_conf->ta_dir_path, name) == MAX_PATH_NAME) {
		OT_LOG(LOG_ERR, "ta path name overflow");
		goto err;
	}

	new_ta_propertie = calloc(1, sizeof(struct loaded_ta));
	if (!new_ta_propertie) {
		OT_LOG(LOG_ERR, "Out of memory");
		goto err;
	}

	if (!get_data_from_elf(ta_with_path, seek_section_name,
			       &new_ta_propertie->ta.user_config,
			       &ta_user_config_size)) {
		OT_LOG(LOG_ERR, "%s : properties section is not found", name);
		goto err;
	}

	memcpy(&new_ta_propertie->ta.ta_so_name, name, strlen(name));

	if (does_name_and_uuid_in_table(&new_ta_propertie->ta))
		goto err;

	/* Not optimatez
	 * TODO: Check if TA propertie is loaded and then copy the information */
	delete_ta(new_ta_propertie->ta.ta_so_name);

	if (ta_dir_watch_lock_mutex()) {
		/* Lets hope that errot clear it shelf..
		 * Know error: Might end up dublicate entries */
		goto err;
	}

	list_add_before(&new_ta_propertie->list, &ta_dir_table.list);

	ta_dir_watch_unlock_mutex();

	return;

err:
	OT_LOG(LOG_ERR, "TA \"%s\" rejected", name);
	free(new_ta_propertie);
}

static void read_ta_dir()
{
	struct dirent *ta_dir_entry = NULL;
	DIR *ta_dir = NULL;

	ta_dir = opendir(control_params->opentee_conf->ta_dir_path);
	if (!ta_dir) {
		OT_LOG(LOG_ERR, "Can not open ta folder");
		return;
	}

	while ((ta_dir_entry = readdir(ta_dir)) != NULL) {

		if (ta_dir_entry->d_name[0] == '.')
			continue;

		add_new_ta(&ta_dir_entry->d_name[0]);
	}

	closedir(ta_dir);
}

static int init_notifys()
{
	inotify_fd = inotify_init();
	if (inotify_fd == -1) {
		OT_LOG(LOG_ERR, "inotify init failed");
		return -1;
	}

	inotify_wd =
	    inotify_add_watch(inotify_fd, control_params->opentee_conf->ta_dir_path, inotify_flags);
	if (inotify_wd == -1) {
		if (errno == ENOENT) {
			OT_LOG(LOG_ERR, "Invalid TA folder path");
		} else {
			OT_LOG(LOG_ERR, "failed to add watch");
		}

		goto err_1;
	}

	if (epoll_reg_fd(inotify_fd, EPOLLIN)) {
		OT_LOG(LOG_ERR, "failed epoll reg");
		goto err_2;
	}

	return inotify_fd;

err_2:
	inotify_rm_watch(inotify_fd, inotify_wd);
err_1:
	close(inotify_fd);
	return -1;
}

static int re_init_ta_properties()
{
	epoll_unreg(inotify_fd);

	/* Close overflowed */
	if (!inotify_rm_watch(inotify_fd, inotify_wd) && errno != EBADF)
		close(inotify_fd);
	else
		OT_LOG(LOG_ERR, "fd or wd not valid");

	remove_all_tas();

	/* Init new */
	if (init_notifys() == -1)
		return -1;

	read_ta_dir();

	return inotify_fd;
}

void ta_dir_watch_event(struct epoll_event *e_event, int *man_ta_dir_watch_fd)
{
	uint8_t buf[BUF_LEN], *i;
	int num_read;
	struct inotify_event *i_event = NULL;

	if (!(e_event->events & EPOLLIN)) {
		OT_LOG(LOG_ERR, "Inotify fd EPOLLERR");
		goto reinit_ta_properties;
	}

	while (1) {
		num_read = read(inotify_fd, &buf, BUF_LEN);
		if (num_read == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				OT_LOG(LOG_ERR, "read error");
				/* TODO: Why it is an error? */
				goto reinit_ta_properties;
			}
		}

		break;
	}

	i = buf;
	while (i < buf + num_read) {

		i_event = (struct inotify_event *)i;

		if (i_event->mask & IN_Q_OVERFLOW)
			goto reinit_ta_properties;

		if (i_event->mask & (IN_DELETE | IN_MOVED_FROM))
			delete_ta(i_event->name);

		if (i_event->mask & (IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE))
			add_new_ta(i_event->name);

		i += sizeof(struct inotify_event) + i_event->len;
	}

	return;

reinit_ta_properties:
	if (*man_ta_dir_watch_fd) {
		*man_ta_dir_watch_fd = re_init_ta_properties();
		if (*man_ta_dir_watch_fd == -1) {
			OT_LOG(LOG_ERR, "Can not re init ta dir watch");
			/* TODO: Close of all TAs? */
		}
	}
}

int ta_dir_watch_init(struct core_control *c_params, int *man_ta_dir_watch_fd)
{
	control_params = c_params;

	INIT_LIST(&ta_dir_table.list);

	if (init_notifys() == -1)
		return 1;

	read_ta_dir();

	if (man_ta_dir_watch_fd)
		*man_ta_dir_watch_fd = inotify_fd;

	return 0;	
}

void ta_dir_watch_cleanup()
{
	inotify_rm_watch(inotify_fd, inotify_wd);
	close(inotify_fd);
	remove_all_tas();

	while (pthread_mutex_destroy(&mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex");
			break;
		}
		/* Busy loop */
	}
}

struct trusted_app_propertie *ta_dir_watch_props(TEE_UUID *get_ta_uuid)
{
	struct loaded_ta *ta = NULL;
	struct list_head *pos;

	if (!get_ta_uuid)
		goto end;

	if (list_is_empty(&ta_dir_table.list))
		goto end;

	LIST_FOR_EACH(pos, &ta_dir_table.list) {

		ta = LIST_ENTRY(pos, struct loaded_ta, list);

		if (!memcmp(&ta->ta.user_config.appID, get_ta_uuid, sizeof(TEE_UUID)))
			return &ta->ta;
	}

end:
	return NULL;
}

int ta_dir_watch_lock_mutex()
{
	if (pthread_mutex_lock(&mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock the mutex");
		/* Lets hope that errot clear it shelf.. */
		return 1;
	}

	return 0;
}

int ta_dir_watch_unlock_mutex()
{
	if (pthread_mutex_unlock(&mutex)) {
		OT_LOG(LOG_ERR, "Failed to unlock the mutex");
		/* Lets hope that errot clear it shelf.. */
		return 1;
	}

	return 0;
}
