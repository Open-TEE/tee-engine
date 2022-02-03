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


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#ifdef ANDROID
#include <cutils/ashmem.h>
#endif /* ANDROID */

#include "extern_resources.h"
#include "io_thread.h"
#include "logic_thread.h"
#include "tee_list.h"
#include "tee_logging.h"

/*!
 * \brief generate_random_path Generate a path, that can be used for a shared memory path
 * Memory for the path will be allocated in this function but it is the callers responsibility
 * to free the memory when finished.
 * \param name [OUT] the path that is created by this function, need to be atleast SHM_MEM_NAME_LEN
 * \return 0 on success, 1 in case of error
 */
static int generate_random_path(char *name)
{
	struct timespec realtime;
	struct timespec boottime;
	int n = SHM_MEM_NAME_LEN - 1;

	clock_gettime(CLOCK_BOOTTIME, &boottime);
	clock_gettime(CLOCK_REALTIME, &realtime);

	memset(name, 't', SHM_MEM_NAME_LEN-1);
	name[0] = '/';
	name[SHM_MEM_NAME_LEN-1] = 0;
	sprintf(name+1, "%llu", (unsigned long long)boottime.tv_sec);
	sprintf(name+15, "%llu", (unsigned long long)realtime.tv_nsec);
	sprintf(name+30, "%llu", (unsigned long long)realtime.tv_sec);

	/* strip null characters back to t , except terminating */
	while (n--) {
		if (name[n] == 0)
			name[n] = 't';
	}

	return 0;
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
	if (generate_random_path(open_shm->name)) {
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_1;
	}

	/* Store shm uuid to manager. This will be needed if CA/TA process crashes unexpectedly */
	memcpy(new_shm->name, open_shm->name, SHM_MEM_NAME_LEN);
	new_shm->size = open_shm->size;

#ifdef ANDROID
	fd = ashmem_create_region(open_shm->name, open_shm->size);

#else
	fd = shm_open(open_shm->name, (O_RDWR | O_CREAT | O_EXCL),
		      (S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP));

#endif /* ANDROID */

	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory");
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_1;
	}

#ifndef ANDROID

	if (ftruncate(fd, open_shm->size) == -1) {
		OT_LOG(LOG_ERR, "Failed to truncate: %d", errno);
		open_shm->return_code = TEEC_ERROR_GENERIC;
		goto err_2;
	}

#endif /* not ANDROID */

	/* We have finished with the file handle as it has been mapped so don't leak it */
	list_add_after(&new_shm->list, &man_msg->proc->shm_mem.list);
	open_shm->msg_hdr.shareable_fd[0] = fd;
	open_shm->msg_hdr.shareable_fd_count = 1;
	new_shm->fd = fd;
out:
	open_shm->msg_hdr.msg_type = COM_TYPE_RESPONSE;
	add_msg_out_queue_and_notify(man_msg);
	return;

err_2:
#ifndef ANDROID
	shm_unlink(open_shm->name);
#endif
	close(fd);
err_1:
	free(new_shm);
	open_shm->msg_hdr.msg_name = COM_MSG_NAME_ERROR;
	add_msg_out_queue_and_notify(man_msg);
}

void unlink_shm_region(struct manager_msg *man_msg)
{
	struct com_msg_unlink_shm_region *unlink_shm = man_msg->msg;
	struct proc_shm_mem *shm_entry;
	struct list_head *pos, *la;

	LIST_FOR_EACH_SAFE(pos, la, &man_msg->proc->shm_mem.list) {

		shm_entry = LIST_ENTRY(pos, struct proc_shm_mem, list);
		if (!strncmp(shm_entry->name, unlink_shm->name, SHM_MEM_NAME_LEN)) {
			list_unlink(&shm_entry->list);
			close(shm_entry->fd);
#ifndef ANDROID
			shm_unlink(unlink_shm->name);
#endif
			free(shm_entry);
			return;
		}
	}
}

void unlink_all_shm_region(proc_t proc)
{
	struct proc_shm_mem *shm_entry;
	struct list_head *pos, *la;

	LIST_FOR_EACH_SAFE(pos, la, &proc->shm_mem.list) {
		shm_entry = LIST_ENTRY(pos, struct proc_shm_mem, list);
		list_unlink(&shm_entry->list);
		close(shm_entry->fd);
#ifndef ANDROID
		shm_unlink(shm_entry->name);
#endif
		free(shm_entry);
	}
}
