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

#include "tee_memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void *instance_data;

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buf, size_t size)
{
	const char *maps = "/proc/self/maps";
	FILE *fd;
	char *line = NULL;
	unsigned long region_start, region_end;
	char perms[4];
	uint32_t mem_perms = 0;
	size_t dummy;
	uint32_t shared = 0;
	size = size;

	if (!buf)
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = fopen(maps, "r");
	if (!fd)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	while (getline(&line, &dummy, fd) != -1) {
		/* Ensure that we can read the first 3 elements of the line and that the address
		 * that we are searching for falls with in the memory region define by the first
		 * 2 paramaters
		 */
		if (sscanf(line, "%lx-%lx %4s", &region_start, &region_end, perms) != 3 ||
		    !((uintptr_t)buf < region_end && region_start <= (uintptr_t)buf)) {
			free(line);
			line = NULL;
			continue;
		}

		if (perms[0] == 'r')
			mem_perms |= (TEE_MEMORY_ACCESS_READ & accessFlags);
		if (perms[1] == 'w')
			mem_perms |= (TEE_MEMORY_ACCESS_WRITE & accessFlags);
		if (perms[3] == 's')
			shared = TEE_MEMORY_ACCESS_ANY_OWNER;

		/* if we have a shared memory address then we must be allowed to access it based
		 * on the accessFlags. Section 4.11.1 defines the following as the logic for this:
		 *         Allowed                  Shared Lib                    Result
		 *           true                      true                         Allowed
		 *           false                     true                         Denied
		 *           true                      false (local mem address)    Allowed
		 *           false                     false (      "          )    Allowed
		 */
		mem_perms |= ((accessFlags & TEE_MEMORY_ACCESS_ANY_OWNER) | shared);
		break;
	}

	fclose(fd);
	free(line);

	return (mem_perms == accessFlags) ? TEEC_SUCCESS : TEEC_ERROR_ACCESS_DENIED;
}

void TEE_SetInstanceData(void *instanceData)
{
	instance_data = instanceData;
}

void *TEE_GetInstanceData()
{
	return instance_data;
}

void *TEE_Malloc(size_t size, uint32_t hint)
{
	hint = hint; // reserved for future use
	return calloc(size, sizeof(uint8_t));
}

void *TEE_Realloc(void *buffer, uint32_t newSize) // TODO HMM the newSize should be size_t
{
	return realloc(buffer, newSize);
}

void TEE_Free(void *buffer)
{
	free(buffer);
}

void TEE_MemMove(void *dest, void *src, uint32_t size)
{
	memmove(dest, src, size);
}

int32_t TEE_MemCompare(void *buffer1, void *buffer2, uint32_t size)
{
	return memcmp(buffer1, buffer2, size);
}

void TEE_MemFill(void *buffer, uint32_t x, uint32_t size)
{
	memset(buffer, x, size);
}
