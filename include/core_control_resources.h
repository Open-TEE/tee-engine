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

#ifndef __CORE_CONTROL_RESOURCES_H__
#define __CORE_CONTROL_RESOURCES_H__

#include <signal.h>
#include <unistd.h>

/* clang-format off */
#define MAX_PR_NAME		16
#define MAX_PATH_NAME		512

#define TEE_SIG_CHILD		0x00000001
#define TEE_SIG_TERM		0x00000002
#define TEE_SIG_HUP		0x00000004
#define TEE_SIG_INT		0x00000008

/* clang-format on */

/*!
 * \brief The core_control struct
 * A structure that defines many states that are shared between the core, launcher and manager
 */
struct core_control {
	volatile sig_atomic_t sig_vector;
	char *argv0;
	int argv0_len;
	pid_t launcher_pid;
	int self_pipe_fd;
	struct emulator_config *opentee_conf;
	void (*reset_signal_self_pipe)(void);
	void (*fn_cleanup_launher)(void); /* Can be used only when flag GRACEFUL_TERMINATION def*/
	void (*fn_cleanup_core)(void); /* Can be used only when flag GRACEFUL_TERMINATION def*/
	int comm_sock_fd;
	int pid_file_fd;
};

#endif /* __CORE_CONTROL_RESOURCES_H__ */
