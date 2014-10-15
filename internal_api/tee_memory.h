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

#ifndef __TEE_INTERNAL_MEMORY_H__
#define __TEE_INTERNAL_MEMORY_H__

#include "tee_data_types.h"

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer, size_t size);

void TEE_SetInstanceData(void *instanceData);

void *TEE_GetInstanceData();

void *TEE_Malloc(size_t size, uint32_t hint);

void *TEE_Realloc(void *buffer, uint32_t newSize);

void TEE_Free(void *buffer);

void TEE_MemMove(void *dest, void *src, uint32_t size);

int32_t TEE_MemCompare(void *buffer1, void *buffer2, uint32_t size);

void TEE_MemFill(void *buffer, uint32_t x, uint32_t size);

#endif
