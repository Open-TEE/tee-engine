/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

#ifndef __TEE_ELF_READER__
#define __TEE_ELF_READER__

#include "data_types.h"
#include "tee_list.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

/*!
 *  \brief Reads metadata in section .ta_config in an ELF file and adds it into a list.
 *  \param Absolute path of an ELF file which is to be read.
 */
void read_metadata(char *);

/*!
 *  \brief Removes metadata of an ELF file from a list.
 *  \param Absolute path of an ELF file.
 *  \return 0 when removin metadata from a list is successful, -1 otherwise.
 */
int remove_metadata(char *);

/*!
 *  \brief Delete metadata list.
 */
void delete_metadata_list();

/*!
 *  \brief Search for metadata matching input TEE_UUID in a list.
 *  \param TEE_UUID which is to be matched with the TEE_UUID of metadata in a list.
 *  \return When found returns ta metadata, NULL otherwise.
 */
struct ta_metadata *search_ta_by_uuid(TEE_UUID tee_uuid);

#endif
