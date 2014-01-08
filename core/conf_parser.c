#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#include "conf_parser.h"

static const char *first_non_whitespace(const char *line)
{
	size_t k = 0;
	for (k = 0; k < strlen(line); ++k) {
		if (isspace(line[k]))
			continue;
		break;
	}

	return &line[k];
}

static char *last_non_whitespace(char *line)
{
	size_t k = 0;
	for (k = (strlen(line)-1); k > 0; --k) {
		if (isspace(line[k]))
			continue;
		break;
	}

	return &line[k];
}

static void strip_whitespace(char *line)
{
	size_t begin = first_non_whitespace(line) - line;

	if (begin != 0) {
		size_t i = 0;
		for (i = begin; i <= strlen(line); ++i)
			line[i-begin] = line[i];
	}

	char *end = last_non_whitespace(line) + 1;
	*end = '\0';
}

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

	char readed_ch;
	size_t buf_index = 0;
	size_t count = 0;

	size_t k = 0;
	for (k = begin; k < end; ++k) {

		if (BLOCK_SIZE == (count - 1)) {
			buf = realloc(buf, sizeof(char) * BLOCK_SIZE);
			if (buf == NULL) {
				syslog(LOG_DEBUG, "Realloc failed");
				return NULL;
			}

			memset(&buf[k], 0, BLOCK_SIZE);
			count = 0;
		}

		readed_ch = line[k];
		if (readed_ch == '#')
			break;

		buf[buf_index] = readed_ch;
		buf_index++;
		count++;
	}

	buf[buf_index] = '\0';

	strip_whitespace(buf);

	return buf;
}

char *get_value(const char *key)
{
	FILE *init_file = fopen(CONF_FILE_WITH_PATH, "r");

	if (init_file == NULL) {
		syslog(LOG_DEBUG, "Failed open config file");
		return NULL;
	}

	if (feof(init_file)) {
		syslog(LOG_DEBUG, "File is empty");
		return NULL;
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

		char *key_line =
			(char *) calloc(0, sizeof(char) * (assigment_op-line));

		if (key_line == NULL) {
			free(line);
			syslog(LOG_DEBUG, "Calloc failed");
			return NULL;
		}

		strncpy(key_line, line, assigment_op-line);

		if (strstr(key_line, key)) {
			char *value = parse_value(line);
			if (value == NULL) {
				free(key_line);
				free(line);
				return NULL;
			}

			free(key_line);
			n = 0;
			free(line);
			return value;
		}

		free(key_line);
		free(line);
		n = 0;
		line = NULL;
	}

	return NULL;
}

static int fill_ta_dir_path(struct Emulator_config *conf)
{
	char *value = get_value("ta_dir_path");
	if (value == NULL)
		return -1;

	if (strlen(value) >= MAX_TA_DIR_PATH)
		return -1;

	strncpy(conf->ta_dir_path, value, strlen(value));
	free(value);
	return 0;
}

int get_config(struct Emulator_config *conf)
{
	if (fill_ta_dir_path(conf) == -1)
		return -1;
	return 0;
}
