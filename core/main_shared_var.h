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

#ifndef __MAIN_SHARED_VAR_H__
#define __MAIN_SHARED_VAR_H__

#include <signal.h>
#include <unistd.h>

#define MAX_PR_NAME			16
#define TA_EXIT_INTERNAL_ERROR		34
#define TA_EXIT_CREATE_ENTRY_FAILED	35
#define TA_EXIT_SUCCESS			36

extern volatile sig_atomic_t sig_vector;
extern char *argv0;
extern int argv0_len;
extern pid_t manager_pid;
extern pid_t launcher_pid;
extern int self_pipe_fd;
extern void check_and_reset_signal_status();

#endif /* __MAIN_SHARED_VAR_H__ */
