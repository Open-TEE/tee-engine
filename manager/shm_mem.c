/*****************************************************************************
** Copyright (C) 2014 Tanel Dettenborn                                      **
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

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "com_protocol.h"
#include "extern_resources.h"
#include "io_thread.h"
#include "logic_thread.h"
#include "tee_list.h"
#include "tee_logging.h"

/*!
 * \brief generate_random_path Generate a path, that can be used for a shared memory path
 * Memory for the path will be allocated in this function but it is the callers responsibility
 * to free the memory when finished.
 * \param name [OUT] the path that is created by this function
 * \param name_len [in] name-buffer length
 * \return 0 on success, 1 in case of error
 */
static int generate_random_path(char *name, size_t name_len)
{
	time_t time_val;
	const char *str_time;
	uuid_t uuid;
	char salt[20];
	char *raw_rand, *tmp;

	time_val = time(NULL);
	str_time = ctime(&time_val);
	uuid_generate(uuid);

	memcpy(salt, "$5$", 3);
	memcpy(salt + 3, uuid, sizeof(uuid));
	salt[19] = '$';

	raw_rand = strrchr(crypt(str_time, salt), '$');

	/* shm_open does not like to have path seperators '/' in teh name so remove them */
	tmp = raw_rand;
	while (*tmp) {
		if (*tmp == '/')
			*tmp = '_';
		tmp++;
	}

	if ((strlen(raw_rand) + 1) <= name_len) {
		memcpy(name, raw_rand, strlen(raw_rand) + 1);
		name[0] = '/';
		return 0;

	}

	/* Buffer too small */
	OT_LOG(LOG_ERR, "Name buffer too small")
	return 1;
}


void open_shm_region(struct manager_msg *man_msg)
{
	struct com_msg_open_shm_region *open_shm = man_msg->msg;
	struct proc_shm_mem *new_shm = NULL;
	int fd;

	if (open_shm->msg_hdr.msg_type != COM_TYPE_QUERY) {
		OT_LOG(LOG_ERR, "Wrong message type, discard msg");
		free_manager_msg(man_msg);
		return;
	}

	open_shm->return_code = TEE_SUCCESS;

	if (open_shm->size == 0)
		goto out;

	new_shm = calloc(1, sizeof(struct proc_shm_mem));
	if (!new_shm) {
		OT_LOG(LOG_ERR, "Out of memory");
		open_shm->return_code = TEEC_ERROR_OUT_OF_MEMORY;
		goto err_1;
	}

	/* The name of the shm object files should be in the format "/somename\0"
	 * so we will generate a random name that matches this format based of of
	 * a UUID */
	if (generate_random_path(open_shm->name, SHM_MEM_NAME_LEN)) {
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_1;
	}

	/* Store shm uuid to manager. This will be needed if CA/TA process crashes unexpectedly */
	memcpy(new_shm->name, open_shm->name, SHM_MEM_NAME_LEN);
	new_shm->size = open_shm->size;

	fd = shm_open(open_shm->name, (O_RDWR | O_CREAT | O_EXCL),
		      (S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP));
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory");
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_1;
	}

	if (ftruncate(fd, open_shm->size) == -1) {
		OT_LOG(LOG_ERR, "Failed to truncate: %d", errno);
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_2;
	}

	/* We have finished with the file handle as it has been mapped so don't leak it */
	close(fd);
	list_add_after(&new_shm->list, &man_msg->proc->content.process.shm_mem.list);

out:
	open_shm->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	add_msg_out_queue_and_notify(man_msg);
	return;

err_2:
	shm_unlink(open_shm->name);
	close(fd);
err_1:
	free(new_shm);
	add_msg_out_queue_and_notify(man_msg);
}

void unlink_shm_region(struct manager_msg *man_msg)
{
	struct com_msg_unlink_shm_region *unlink_shm = man_msg->msg;
	struct proc_shm_mem *shm_entry;
	struct list_head *pos, *la;

	LIST_FOR_EACH_SAFE(pos, la, &man_msg->proc->content.process.shm_mem.list) {

		shm_entry = LIST_ENTRY(pos, struct proc_shm_mem, list);
		if (!strncmp(shm_entry->name, unlink_shm->name, SHM_MEM_NAME_LEN)) {
			list_unlink(&shm_entry->list);
			shm_unlink(unlink_shm->name);
			free(shm_entry);
			return;
		}
	}
}

void unlink_all_shm_region(proc_t proc)
{
	struct proc_shm_mem *shm_entry;
	struct list_head *pos, *la;

	LIST_FOR_EACH_SAFE(pos, la, &proc->content.process.shm_mem.list) {
		shm_entry = LIST_ENTRY(pos, struct proc_shm_mem, list);
		list_unlink(&shm_entry->list);
		shm_unlink(shm_entry->name);
		free(shm_entry);
	}
}
