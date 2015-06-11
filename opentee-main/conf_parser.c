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

#include "conf_parser.h"
#include "ini.h"
#include "tee_logging.h"
#include "core_control_resources.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*!
 * \brief ini_handler
 * The callback handler that is registered with the ini parser
 * \param user The user defined type that is used to store the parsed values
 * \param section The ini section that is being parsed
 * \param name The name of the configuration in that section
 * \param value The value of a named configuration
 * \return 0 on failure; > 0 on success
 */
static int ini_handler(void *user, const char *section, const char *name, const char *value)
{
	struct emulator_config *conf = (struct emulator_config *)user;

	if (strcmp(section, "PATHS") == 0) {
		if (strcmp(name, "core_lib_path") == 0)
			conf->core_lib_path = strdup(value);
		else if (strcmp(name, "ta_dir_path") == 0)
			conf->ta_dir_path = strdup(value);
		else if (strcmp(name, "subprocess_manager") == 0)
			conf->subprocess_manager = strdup(value);
		else if (strcmp(name, "subprocess_launcher") == 0)
			conf->subprocess_launcher = strdup(value);
	}

	return 1;
}

/*!
 * \brief fixup_lib_path
 * To be useful the lib name should be the whole path so we concatinate the strings here
 * \param path The base directory containing the libraries
 * \param lib_name [IN] The name of the library [OUT] the full path of the library
 * \return 0 on success -1 otherwise
 */
static int fixup_lib_path(const char *path, char **lib_name)
{
	char tmp[MAX_PATH_NAME] = {0};
	int ret = 0;

	if (snprintf(tmp, MAX_PATH_NAME, "%s/%s", path, *lib_name) == MAX_PATH_NAME) {
		OT_LOG(LOG_ERR, "Failed to make %s path", *lib_name);
		ret = -1;
		goto out;
	}

	/* copy the entire path + name back into the libname */
	free(*lib_name);
	*lib_name = strdup(tmp);

out:
	return ret;
}

int config_parser_get_config(struct emulator_config **conf, char *config_file)
{
	struct emulator_config *tmp_conf;

	tmp_conf = (struct emulator_config *)calloc(1, sizeof(struct emulator_config));
	if (tmp_conf == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		return -1;
	}

	if (ini_parse(config_file, ini_handler, tmp_conf) < 0)
		goto err_out;

	if (fixup_lib_path(tmp_conf->core_lib_path, &tmp_conf->subprocess_manager))
		goto err_out;

	if (fixup_lib_path(tmp_conf->core_lib_path, &tmp_conf->subprocess_launcher))
		goto err_out;

	*conf = tmp_conf;

	return 0;

err_out:
	OT_LOG(LOG_ERR, "Failed to read the config paramaters");
	free(tmp_conf);
	conf = NULL;
	return -1;
}

void config_parser_free_config(struct emulator_config *conf)
{
	if (!conf)
		return;

	free(conf->subprocess_launcher);
	free(conf->subprocess_manager);
	free(conf->ta_dir_path);
	free(conf);
}
