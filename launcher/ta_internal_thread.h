/*****************************************************************************
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

#ifndef __TA_INTERNAL_THREAD_H__
#define __TA_INTERNAL_THREAD_H__

/* TA internal client API functions. These function will need a callback */
#define FN_TEE_OPEN_TA_SESSION		0x01
#define FN_TEE_CLOSE_TA_SESSION		0x02
#define FN_TEE_INCOKE_TA_COMMAND	0x03

void *ta_internal_thread(void *arg);

void *internal_api_fn_resolver(uint8_t fn);

#endif /* __TA_INTERNAL_THREAD_H__ */
