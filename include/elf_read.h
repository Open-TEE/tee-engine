/*****************************************************************************
** Copyright (C) 2014 Tanel Dettenborn                                      **
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

#ifndef __ELF_READ__
#define __ELF_READ__

/*!
 * \brief get_data_from_elf
 * Search from ELF file section and retrieve section data
 * \param elf_file Searched file. Must be NULL (\0) terminated
 * \param sec_name Seeked section name. Name must be NULL (\0) terminated
 * \param buf section data to read
 * \param buf_len Buf lenght. If section is found, data that is read to buffer is filled to buf_len
 * \return If section is found, return value is true. If section is not found,return value is false.
 */
bool get_data_from_elf(const char *elf_file, const char *sec_name, void *buf, size_t *buf_len);

#endif /* __ELF_READ__ */
