/****************************************************************************
** Copyright (C) 2014 Brian McGillion.					   **
**									   **
** Licensed under the Apache License, Version 2.0 (the "License");	   **
** you may not use this file except in compliance with the License.	   **
** You may obtain a copy of the License at				   **
**									   **
** http://www.apache.org/licenses/LICENSE-2.0				   **
**									   **
** Unless required by applicable law or agreed to in writing, software	   **
** distributed under the License is distributed on an "AS IS" BASIS,	   **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.**
** See the License for the specific language governing permissions and	   **
** limitations under the License.					   **
*****************************************************************************/

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"

void free_params(TEE_Param params[4], int paramTypes)
{
	int i;
	int type;

	for (i = 0; i < 4; i++) {
		// If we have mapped memory we should free it
		type = TEE_PARAM_TYPE_GET(paramTypes, i);
		if (type == TEE_PARAM_TYPE_MEMREF_INPUT ||
		    type ==  TEE_PARAM_TYPE_MEMREF_OUTPUT ||
		    type == TEE_PARAM_TYPE_MEMREF_INOUT) {
			if (params[i].memref.buffer != NULL)
				munmap(params[i].memref.buffer, params[i].memref.size);
		}
	}
}

int32_t intermediate_to_internal_params(const struct inter_operation *i_op, TEE_Param params[4])
{
	int fd;
	int i;
	int type;
	char errbuf[MAX_ERR_STRING];

	if (i_op == NULL)
		return -1;

	memset(&params, 0, 4 * sizeof(TEE_Param));

	for (i = 0; i < 4; i++) {

		type = TEE_PARAM_TYPE_GET(i_op->paramTypes, i);
		if (type == TEE_PARAM_TYPE_MEMREF_INPUT ||
		    type == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
		    type == TEE_PARAM_TYPE_MEMREF_INOUT) {

			// We have a shared memory region so we must map it
			// reuse type to define the permissions the area should be mapped as
			if (type == TEE_PARAM_TYPE_MEMREF_INPUT)
				type = O_RDONLY;
			else
				type = O_RDWR;

			// open the shared memory section
			fd = shm_open(i_op->params[i].memref.path, type, 0);
			if (fd == -1) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed to open shared mem: %s\n", errbuf);
				goto err_out;
			}

			if (type == O_RDONLY)
				type = PROT_READ;
			else
				type = PROT_READ | PROT_WRITE;

			// map the shared memory region
			params[i].memref.buffer = mmap(NULL, i_op->params[i].memref.size, type,
						       MAP_SHARED, fd,
						       i_op->params[i].memref.offset);
			if (params[i].memref.buffer == MAP_FAILED) {
				strerror_r(errno, errbuf, MAX_ERR_STRING);
				syslog(LOG_ERR, "Failed to mmap: %s\n", errbuf);
				goto err_out;
			}

			params[i].memref.size = i_op->params[i].memref.size;

			// can close fd once we have mapped the shm region
			close(fd);
		} else {
			// just copy the value types
			memcpy(&params[i].value, &i_op->params[i].value, sizeof(struct inter_value));
		}

	}

	return 0;

err_out:
	free_params(params, i_op->paramTypes);
	return -1;
}

void copy_back_internal_params(const TEE_Param params[4], struct inter_operation *i_op)
{
	int i;

	for (i = 0; i < 4; i++) {

		switch (TEE_PARAM_TYPE_GET(i_op->paramTypes, i)) {
		// if we have an inout or pout put value it must be copied back to the caller
		case TEE_PARAM_TYPE_VALUE_INOUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			memcpy(&i_op->params[i].value, &params[i].value,
			       sizeof(struct inter_value));
			break;
		}
	}
}
