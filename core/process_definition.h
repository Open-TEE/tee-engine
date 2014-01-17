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

#ifndef __TEE_PROCESS_MANAGER_H__
#define __TEE_PROCESS_MANAGER_H__

#include <sys/types.h>
#include "tee_internal_api.h"
#include "tee_list.h"

#define MAX_FILE_PATH 255

struct session {
	uint32_t sessionID;
	int client_sock;
	struct list_head list;
};

struct proc {
	pid_t pid;
	TEE_UUID appID;
	char ipc_fs_handle[MAX_FILE_PATH];
	bool singleton_instance;
	bool instance_keep_alive;
	struct session active_sessions;
	struct list_head list;
	void *mmap_address;
};

#endif
