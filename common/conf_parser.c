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

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "conf_parser.h"

#ifndef CONF_FILE_WITH_PATH /* Allow this to be sepecified on the compile line -D */
#define CONF_FILE_WITH_PATH "/etc/opentee.conf"
#endif

static const size_t BLOCK_SIZE = 256;

/*!
 * \brief first_non_whitspace
 * Allocate first non whitespace character location from the beginning
 * \param line is handled line
 * \return a pointer to first non whitespace character in line
 */
static char *first_non_whitespace(char *line)
{
	size_t k = 0;
	for (k = 0; k < strlen(line); ++k) {
		if (!isspace(line[k]))
			break;
	}

	return &line[k];
}

/*!
 * \brief last_non_whitespace
 * Opposite to first_non_whitespace. \sa first_non_whitespace
 */
static char *last_non_whitespace(char *line)
{
	size_t k = 0;
	for (k = (strlen(line)-1); k > 0; --k) {
		if (!isspace(line[k]))
			break;
	}

	return &line[k];
}

/*!
 * \brief strip_whitespace
 * Removes whitespaces from the beginning and at the end. Does not actually
 * remove.
 * \param line is handled line
 */
static void strip_whitespace(char *line)
{
	char *end = last_non_whitespace(line) + 1;
	*end = '\0';

	char *begin = first_non_whitespace(line);

	size_t len = (end + 1) - begin;

	memmove(line, begin, len);
}

/*!
 * \brief parse_value
 * Function is retrieving a value from a line. At the beginning and at the
 * ind whitespace is removed.
 * \param line that is containing a key-value pair
 * \return In case of success returning a pointer to value. Memory for value
 * is allocated by malloc and it is the responsibility of a user to free
 * memory. Value is newline terminated. In case of failure function will
 * return NULL and no memory is malloced.
 */
static char *parse_value(const char *line)
{
	char *buf = (char *) calloc(0, sizeof(char) * BLOCK_SIZE);
	if (buf == NULL) {
		syslog(LOG_DEBUG, "Calloc failed");
		return NULL;
	}

	char *as_op = memchr(line, '=', strlen(line));
	if (as_op == NULL) {
		free(buf);
		syslog(LOG_DEBUG, "No assigning operator");
		return NULL;
	}

	size_t begin = as_op - line + 1;
	size_t end = strlen(line);

	char read_ch;
	size_t buf_index = 0;
	size_t count = 0;
	size_t buf_size = BLOCK_SIZE;

	size_t k = 0;
	for (k = begin; k < end; ++k) {

		if (count - 1 >= buf_size) {
			char *tmp;
			tmp = realloc(buf, buf_size + BLOCK_SIZE);
			if (tmp == NULL) {
				syslog(LOG_DEBUG, "Realloc failed");
				free(buf);
				return NULL;
			}

			buf = tmp;
			buf_size += BLOCK_SIZE;
			memset(&buf[k], 0, BLOCK_SIZE);
			count = 0;
		}

		read_ch = line[k];
		if (read_ch == '#')
			break;

		buf[buf_index] = read_ch;
		buf_index++;
		count++;
	}

	buf[buf_index] = '\0';

	strip_whitespace(buf);

	return buf;
}

/*!
 * \brief alloc_fill_value
 * Read a value from the config and allocate enough space for it in the dest
 * \param key The config setting we wish to find in the config file
 * \param dest Where to store the value
 * \return -1 on error, 0 otherwise
 */
static int alloc_fill_value(const char *key, char **dest)
{
	char *value = config_parser_get_value(key);
	if (value == NULL)
		return -1;

	*dest = (char *)calloc(strlen(value) + 1, sizeof(char));
	if (*dest == NULL) {
		free(value);
		return -1;
	}

	strncpy(*dest, value, strlen(value));
	free(value);
	return 0;
}

/*!
 * \brief concat_values
 * Many values in the config file may need to be concatinated together, e.g.
 * library path and library name, so that the library can be accessed properly
 * \param base The base value that is used for concatination
 * \param src_n_dest The value that is to be concatinated to the base and where the result will
 * be stored
 * \return 0 on success, -1 otherwise
 */
static int concat_values(const char *base, char **src_n_dest)
{
	char *tmp;

	if (base == NULL || *src_n_dest == NULL)
		return 0; /* nothing will change */

	tmp = (char *)calloc(strlen(base) + strlen(*src_n_dest) + 1, sizeof(char));
	if (tmp == NULL)
		return -1;

	/* concatinat the 2 strings */
	snprintf(tmp, strlen(base) + strlen(*src_n_dest) + 1, "%s%s", base, *src_n_dest);

	/* now store the result back into src_n_dest */
	free(*src_n_dest);
	*src_n_dest = tmp;

	return 0;
}

int config_parser_get_config(struct emulator_config **conf)
{
	struct emulator_config *conf_ptr;
	char *core_lib_path = NULL;
	int ret;

	/* TODO: Fix this function to only open the conf file once and read all values */

	conf_ptr = (struct emulator_config *)calloc(sizeof(struct emulator_config), sizeof(char));
	if (conf_ptr == NULL)
		return -1;

	if (alloc_fill_value("ta_dir_path", &conf_ptr->ta_dir_path) == -1) {
		ret = -1;
		goto out;
	}

	if (alloc_fill_value("core_lib_path", &core_lib_path) == -1) {
		ret = -1;
		goto out;
	}

	if (alloc_fill_value("subprocess_manager", &conf_ptr->subprocess_manager) == -1) {
		ret = -1;
		goto out;
	}

	if (alloc_fill_value("subprocess_launcher", &conf_ptr->subprocess_launcher) == -1) {
		ret = -1;
		goto out;
	}

	/* tidy up and make the library paths full paths, hence usable */
	if (concat_values(core_lib_path, &conf_ptr->subprocess_manager) == -1) {
		ret = -1;
		goto out;
	}

	if (concat_values(core_lib_path, &conf_ptr->subprocess_launcher) == -1) {
		ret = -1;
		goto out;
	}

out:
	/* There has been some error so clean up */
	if (ret == -1) {
		config_parser_free_config(conf_ptr);
		conf_ptr = NULL;
	}

	/* clean up the tmp lib path variable */
	free(core_lib_path);

	/* Assign the config back to the caller */
	*conf = conf_ptr;

	return ret;
}

void config_parser_free_config(struct emulator_config *conf)
{
	if (conf == NULL)
		return; /* nothing to free */

	if (conf->ta_dir_path)
		free(conf->ta_dir_path);

	if (conf->subprocess_launcher)
		free(conf->subprocess_launcher);

	if (conf->subprocess_manager)
		free(conf->subprocess_manager);

	free(conf);
}

char *config_parser_get_value(const char *key)
{
	FILE *init_file = fopen(CONF_FILE_WITH_PATH, "r");
	char *value = NULL;

	if (init_file == NULL) {
		syslog(LOG_DEBUG, "Failed open config file");
		goto err1;
	}

	if (feof(init_file)) {
		syslog(LOG_DEBUG, "File is empty");
		goto err2;
	}

	size_t n = 0;
	ssize_t read = 0;
	char *line = NULL;
	while ((read = getline(&line, &n, init_file)) != -1) {

		if ((*first_non_whitespace(line) == '#') ||
		    (*first_non_whitespace(line) == '[')) {
			free(line);
			n = 0;
			line = NULL;
			continue;
		}

		char *assigment_op = memchr(line, '=', strlen(line));
		if (assigment_op == NULL) {
			free(line);
			n = 0;
			line = NULL;
			continue;
		}

		char *key_line = (char *) calloc(0, sizeof(char) * (assigment_op-line));
		if (key_line == NULL) {
			syslog(LOG_DEBUG, "Calloc failed");
			goto err3;
		}

		strncpy(key_line, line, assigment_op-line);

		if (strstr(key_line, key)) {
			value = parse_value(line);
			free(key_line);
			goto err3;
		}

		free(key_line);
		free(line);
		n = 0;
		line = NULL;
	}

err3:
	free(line);
err2:
	fclose(init_file);
err1:
	return value;
}
