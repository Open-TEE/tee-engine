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

#ifndef __CORE_EXTERN_RESOURCES_H__
#define __CORE_EXTERN_RESOURCES_H__

#include <signal.h>
#include <unistd.h>

#include "conf_parser.h"

#define MAX_PR_NAME		16

#define TEE_SIG_CHILD		0x00000001
#define TEE_SIG_TERM		0x00000002
#define TEE_SIG_HUP		0x00000004

extern volatile sig_atomic_t sig_vector;
extern char *argv0;
extern int argv0_len;
extern pid_t launcher_pid;
extern int self_pipe_fd;
struct emulator_config *opentee_conf;
extern void reset_signal_self_pipe();

#endif /* __CORE_EXTERN_RESOURCES_H__ */
