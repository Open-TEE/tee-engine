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

#ifndef __TEE_DYNAMIC_LOADER_H__
#define __TEE_DYNAMIC_LOADER_H__

#include "tee_internal_api.h"

/*!
 * \brief The ta_interface struct
 * These are the entry points for a trusted application section 4.3 of the specification
 */
struct ta_interface {
	TA_CreateEntryPoint_t create;		   /*!< Initialize the TA */
	TA_DestroyEntryPoint_t destroy;		   /*!< Clean up the TA */
	TA_OpenSessionEntryPoint_t open_session;   /*!< Open a communication session with TA */
	TA_InvokeCommandEntryPoint_t invoke_cmd;   /*!< Call a specific command in the TA */
	TA_CloseSessionEntryPoint_t close_session; /*!< Close down the session */
	TEE_UUID id;
	void *library; /*!< A pointer to the handle returned
			       by dlopen() */
};

/*!
 * \brief load_ta
 *  Attempt to load a trusted application from Disk.  On success the callbacks structure will
 * be populated with the entry points into the applet and the create callback will have been called
 * to initialize the TA.  This function will create the memory for the callback struct which must
 * be freed by a call to \sa unload_ta when it is no longer required.
 * \param ta_so_name The TA file to load
 * \param callbacks The structure that is to be created and populated with the entry points to the
 * TA
 * \return TEE_SUCCESS on success, or another value to indicate any errors.
 */
TEE_Result load_ta(const char *ta_so_name, struct ta_interface **callbacks);

/*!
 * \brief unload_ta
 * Unload the TA and free any resources that it may have consumed.  As part of this process the
 * destroy callback from the TA will be called to allow it to finalize any internal content
 * \param callbacks A pointer to the TA interface structure that is to be freed
 */
void unload_ta(struct ta_interface *callbacks);

#endif
