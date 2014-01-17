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

#ifndef __TEE_CONTEXT_CHILD_H__
#define __TEE_CONTEXT_CHILD_H__

/*!
 * \brief context_handler_loop
 * This is the entry point for the client context that is created by the InitializeContext call
 * in the client, the rest of the context duration will be handled from here, including the
 * creation of any subsequent sessions
 * \param client_sock_fd An initialized socket connection to the Client
 */
void context_handler_loop(int client_sock_fd);

#endif
