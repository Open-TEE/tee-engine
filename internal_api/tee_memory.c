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


static void *instance_data;

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer, size_t size)
{
	//TODO using the /proc/self/maps determine where the address points to
	// if it is heap or stack then it is read write, if mmap, then we need to
	// determine the access constrainsts.
	accessFlags = accessFlags;
	buffer = buffer;
	size = size;
	return TEE_SUCCESS;
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

void *TEE_Realloc(void *buffer, uint32_t newSize) //TODO HMM the newSize should be size_t
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
