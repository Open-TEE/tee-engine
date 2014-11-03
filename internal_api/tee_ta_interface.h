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

#ifndef __TEE_TA_INTERFACE_H__
#define __TEE_TA_INTERFACE_H__

#include "tee_data_types.h"

#ifdef TA_PLUGIN
#define TA_EXPORT __attribute__((__visibility__("default")))

TEE_Result TA_EXPORT TA_CreateEntryPoint(void);

void TA_EXPORT TA_DestroyEntryPoint(void);

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
					      void **sessionContext);

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext);

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4]);
#else
#define TA_EXPORT

typedef TEE_Result (*TA_CreateEntryPoint_t)(void);

typedef void (*TA_DestroyEntryPoint_t)(void);

typedef TEE_Result (*TA_OpenSessionEntryPoint_t)(uint32_t paramTypes, TEE_Param params[4],
						 void **sessionContext);

typedef void (*TA_CloseSessionEntryPoint_t)(void *sessionContext);

typedef TEE_Result (*TA_InvokeCommandEntryPoint_t)(void *sessionContext, uint32_t commandID,
						   uint32_t paramTypes, TEE_Param params[4]);

#endif /* TA_PLUGIN */

#endif
