/*****************************************************************************
** Copyright (C) 2013 Brian McGillion                                       **
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

#ifndef __TEE_IO_THREAD__
#define __TEE_IO_THREAD__

typedef void (*sig_status_cb)(void);

/*!
 * \brief daemon_main_loop
 * This is the main processing loop of the parent, daemon process.
 * \param handler a callback that will be called if EINTER is returned from blocking function
 * \return 0 on success, -1 otherwise
 */
int daemon_main_loop(sig_status_cb handler);

#endif
