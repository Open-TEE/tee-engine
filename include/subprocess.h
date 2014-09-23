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

#ifndef __TEE_SUBPROCESS_H__
#define __TEE_SUBPROCESS_H__

#include <stdint.h>

static const uint32_t TEE_SIG_CHILD	= 0x00000001;
static const uint32_t TEE_SIG_TERM	= 0x00000002;
static const uint32_t TEE_SIG_HUP	= 0x00000004;
static const uint32_t TEE_SIG_INT	= 0x00000008;

typedef void (*sig_status_cb)();

typedef int (*main_loop_cb)(sig_status_cb handler, int sockpair_fd);

/*!
 * \brief lib_main_loop
 * This is the main processing loop of the library that is being loaded.
 * \param handler a callback that will be called if EINTER is returned from blocking function
 * \param sockpair_fd The socket handle that is used to communicate between manager and launcher
 * \return This function should never return unless a major error occurs, and then -1.
 */
int lib_main_loop(sig_status_cb handler, int sockpair_fd);

#endif
