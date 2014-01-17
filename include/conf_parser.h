/*****************************************************************************
** Copyright (C) 2013 ICRI.                                    **
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

#ifndef __CONFIG_PARSER_H__
#define __CONFIG_PARSER_H__

/*!
 * \file conf_parser.h
 * \brief A simple modul for parsning a TEE emulator configure file. The
 * configure file syntax is described in config.conf file.
 *
 * How to Use:
 * 1. Function get_value() is retrieving a value from the configure file,
 * which corresponds with a key. \sa getvalue()
 * or
 * 2. Function get_config() will populate the given struct, but this should
 * only be used if neccesary implementation is implemented. \sa get_config()
 *
 * How these two differ from each other?
 * Function get_value() returns a value, which is allocated by malloc and
 * freeing the allocated memory is the responsibility of users. If you do not
 * wantfor example to do a  malloc-free-memory operation or want to get all
 * config at once, you can implement the neccesary implemetation and use
 * get_config() function.
 *
 * How can I  add a new config parameter and use get_config()-function?
 * At this point the preferred solution
 * 1.Add a new member to Emulator_config-struct
 * 2.Create a function which will read and add value to struct
 * 3.Call your function in get_config()-function
 * Really simple, See for example fill_ta_dir_path()-function
 */

/*!
 * \brief Emulator config struct
 * Emulator config parameters
 */
struct emulator_config {
	char *ta_dir_path; /*!< Folder that contais TAs */
	char *subprocess_manager; /*!< The library that implements the manager fucnctionality */
	char *subprocess_launcher; /*!< The library that implements the TA launcher functionality */
};

/*!
 * \brief config_parser_get_config
 * Populates Emulator_config-struct. Should only be used if neccessary
 * steps have been taken. See more details in file description.
 * \param conf is allocated memory via malloc caller must free with config_parser_free_config
 * \return 1 on success, 0 on failure
 */
int config_parser_get_config(struct emulator_config **conf);

/*!
 * \brief config_parser_free_config
 * Free an emulator config struct that has been assigned with config_parser_get_config
 * \param conf the config that is to be freed
 */
void config_parser_free_config(struct emulator_config *conf);

/*!
 * \brief config_parser_get_value
 * Retrieving a value from configure file that is responding to a key.
 * \param key which value is wanted
 * \return In case of success returning pointer to value. Memory for value
 * is allocated by malloc and it is the responsibility of a user to free
 * memory. Value is newline terminated. On failure function will return
 * NULL and no memory is malloced.
 */
char *config_parser_get_value(const char *key);

#endif /* __CONFIG_PARSER_H__ */
