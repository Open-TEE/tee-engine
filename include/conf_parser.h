/*****************************************************************************
** Copyright (C) 2013 Tanel Dettenborn                                      **
** Copyright (C) 2014 Brian McGillion                                       **
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

#ifndef CONF_PARSER_H
#define CONF_PARSER_H

/*!
 * \brief Emulator config struct
 * Emulator config parameters
 */
struct emulator_config {
	char *ta_dir_path;	 /*!< Folder that contais TAs */
	char *subprocess_manager;  /*!< The library that implements the manager fucnctionality */
	char *subprocess_launcher; /*!< The library that implements the TA launcher functionality */
	char *core_lib_path;       /*!< The path where the libraries are stored */
};

/*!
 * \brief config_parser_get_config
 * Populates Emulator_config-struct. Should only be used if neccessary
 * steps have been taken. See more details in file description.
 * \param conf is allocated memory via malloc caller must free with config_parser_free_config
 * \param config_file Filename where to parse configuration from
 * \return 1 on success, 0 on failure
 */
int config_parser_get_config(struct emulator_config **conf, char *config_file);

/*!
 * \brief config_parser_free_config
 * Free an emulator config struct that has been assigned with config_parser_get_config
 * \param conf the config that is to be freed
 */
void config_parser_free_config(struct emulator_config *conf);

#endif /* CONF_PARSER */
