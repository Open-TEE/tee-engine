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

#define _GNU_SOURCE

#include <gelf.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <string.h>
#include <dirent.h>
#include <syslog.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>

#include "elf_read.h"
#include "h_table.h"
#include "conf_parser.h"
#include "trusted_app_properties.h"
#include "../manager/epoll_wrapper.h"

static const char *seek_section_name = ".ta_properties";
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static char *ta_folder_path;
static HASHTABLE ta_dir_table;
static int inotify_fd;
static uint32_t inotify_flags = IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
								IN_MOVED_FROM | IN_MOVED_TO;
#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define CONF_TA_DIR_PATH_VALUE "ta_dir_path"
#define ESTIMATE_COUNT_OF_TAS 40

static void remove_all_tas()
{
	struct trusted_app_properties *ta = NULL;

	h_table_init_stepper(ta_dir_table);

	if (pthread_mutex_lock(&mutex)) {
		syslog(LOG_ERR, "remove_all_tas: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf..
		 * Know error: Might end up dublicate entries */
		return;
	}

	while (1) {
		ta = h_table_step(ta_dir_table);
		if (!ta)
			break;

		free(ta);
	}

	if (pthread_mutex_unlock(&mutex)) {
		syslog(LOG_ERR, "remove_all_tas: Failed to unlock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
	}
}

void *get_ta_props(TEE_UUID *get_ta_uuid)
{
	struct trusted_app_properties *ta = NULL;

	if (!ta_dir_table)
		return NULL;

	if (pthread_mutex_lock(&mutex)) {
		syslog(LOG_ERR, "get_ta_props: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
		return NULL;
	}

	ta = h_table_get(ta_dir_table, (unsigned char *)get_ta_uuid, sizeof(TEE_UUID));

	if (pthread_mutex_unlock(&mutex)) {
		syslog(LOG_ERR, "get_ta_props: Failed to unlock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
	}

	return ta;
}

static void add_new_ta(char *name)
{
	char *ta_with_path = NULL;
	struct trusted_app_properties *ta_elf_propertie = NULL;

	if (asprintf(&ta_with_path, "%s%s", ta_folder_path, name)) {
		syslog(LOG_ERR, "add_new_ta: Out of memory\n");
		goto err;
	}

	ta_elf_propertie  = calloc(1, sizeof(struct trusted_app_properties));
	if (!ta_elf_propertie) {
		syslog(LOG_ERR, "add_new_ta: Out of memory\n");
		goto err;
	}

	if (get_data_from_elf(ta_with_path, seek_section_name,
						  ta_elf_propertie, sizeof(struct trusted_app_properties))) {
		syslog(LOG_ERR, "add_new_ta: TA properties section is not found\n");
		goto err;
	}

	if (pthread_mutex_lock(&mutex)) {
		syslog(LOG_ERR, "add_new_ta: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
		goto err;
	}

	/* Not optimatez */
	h_table_remove(ta_dir_table, (unsigned char *)&ta_elf_propertie->uuid, sizeof(TEE_UUID));

	if (h_table_insert(ta_dir_table, (unsigned char *)&ta_elf_propertie->uuid,
					   sizeof(TEE_UUID), ta_elf_propertie)) {
		syslog(LOG_ERR, "add_new_ta: table insert failed\n");
		/* No move to error, lets free mutex */
	}

	if (pthread_mutex_unlock(&mutex)) {
		syslog(LOG_ERR, "add_new_ta: Failed to unlock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
	}

err:
	free(ta_with_path);
	free(ta_elf_propertie);
}

static void delete_ta(char *name)
{
	struct trusted_app_properties *ta = NULL;

	h_table_init_stepper(ta_dir_table);

	if (pthread_mutex_lock(&mutex)) {
		syslog(LOG_ERR, "delete_ta: Failed to lock the mutex\n");
		/* Lets hope that errot clear it shelf..
		 * Know error: Might end up dublicate entries */
		return;
	}

	while (1) {
		ta = h_table_step(ta_dir_table);
		if (!ta)
			break;

		if (strncasecmp(name, ta->ta_so_name, TA_MAX_FILE_NAME) != 0)
			continue;

		/* Found */
		h_table_remove(ta_dir_table, (unsigned char *)&ta->uuid, sizeof(TEE_UUID));
		break;
	}

	if (pthread_mutex_unlock(&mutex)) {
		syslog(LOG_ERR, "delete_ta: Failed to unlock the mutex\n");
		/* Lets hope that errot clear it shelf.. */
	}
}

static void read_ta_dir()
{
	DIR *ta_dir = NULL;
	struct dirent *ta_dir_entry = NULL;

	ta_dir = opendir(ta_folder_path);
	if (!ta_dir)	{
		syslog(LOG_ERR, "read_ta_dir: Can not open ta folder\n");
		return;
	}

	while ((ta_dir_entry = readdir(ta_dir)) != NULL) {

		if (ta_dir_entry->d_name[0] == '.')
			continue;

		add_new_ta(&ta_dir_entry->d_name[0]);
	}

	closedir(ta_dir);
}

static void inotify_events_owerflow()
{
	int num_read, trash_buf_size = 512;
	char trash_buf[trash_buf_size];

	/* Consume all bits */
	while (1) {
		num_read = read(inotify_fd, &trash_buf, trash_buf_size);
		if (num_read == -1) {

			if (errno == EINTR)
				continue;

			syslog(LOG_ERR, "inotify_events_owerflow: read error\n");
			break; /* Lets hope it will clear it self */
		}

		if (num_read != trash_buf_size)
			continue;
	}

	/* Not optimazed */
	remove_all_tas();
	read_ta_dir();
}

void handle_inotify_fd(struct epoll_event *e_event)
{
	char buf[BUF_LEN];
	int num_read;
	char *i;
	struct inotify_event *i_event;

	if (e_event->events & EPOLLERR) {
		syslog(LOG_ERR, "handle_inotify_fd: Inotify fd EPOLLERR\n");
		epoll_unreg(inotify_fd);
		close(inotify_fd);
		return;
	}

	num_read = read(inotify_fd, &buf, BUF_LEN);
	if (num_read == -1) {
		syslog(LOG_ERR, "handle_inotify_fd: read error\n");
		/* TODO: Why it is an error? */
		return;
	}

	i = buf;
	while (i < buf + num_read) {

		i_event = (struct inotify_event *)i;

		if (i_event->mask & IN_Q_OVERFLOW) {
			inotify_events_owerflow();
			break;
		}

		if (i_event->mask & IN_CREATE)
			add_new_ta(i_event->name);

		if (i_event->mask & IN_DELETE)
			delete_ta(i_event->name);

		if (i_event->mask & IN_MOVED_FROM)
			delete_ta(i_event->name);

		if (i_event->mask & IN_MOVED_TO)
			add_new_ta(i_event->name);

		if (i_event->mask & IN_CLOSE_WRITE)
			add_new_ta(i_event->name);

		i += sizeof(struct inotify_event) + i_event->len;
	}
}

int init_ta_properti_notify()
{
	ta_folder_path = NULL;
	ta_dir_table = NULL;

	ta_folder_path = config_parser_get_value(CONF_TA_DIR_PATH_VALUE);
	if (!ta_folder_path) {
		syslog(LOG_ERR, "init_ta_properti_notify: Did not get ta dir path form config file\n");
		goto err;
	}

	h_table_create(&ta_dir_table, ESTIMATE_COUNT_OF_TAS);
	if (!ta_dir_table) {
		syslog(LOG_ERR, "init_ta_properti_notify: Hashtable creation failed\n");
		goto err;
	}

	inotify_fd = inotify_init();
	if (inotify_fd) {
		syslog(LOG_ERR, "init_ta_properti_notify: inotify init failed\n");
		goto err;
	}

	if (inotify_add_watch(inotify_fd, ta_folder_path, inotify_flags)) {
		syslog(LOG_ERR, "init_ta_properti_notify: failed to add watch\n");
		goto err;
	}

	read_ta_dir();

	return inotify_fd;

err:
	free(ta_folder_path);
	h_table_free(ta_dir_table);
	ta_dir_table = NULL;
	return -1;
}

static void __attribute__ ((destructor)) elf_cleanup()
{
	free(ta_folder_path);
	remove_all_tas();
	h_table_free(ta_dir_table);
}
