/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#include "args.h"
#include <argp.h>

const char *argp_program_version = "Open-TEE";
const char *argp_program_bug_address = "https://github.com/Open-TEE/tee-engine/issues";

static const char doc[] = "Open-TEE Core Process -- A program which runs Trusted Applications";

static struct argp_option options[] = {
	{"foreground", 'f', 0, 0, "Do not daemonize but start the process in foreground", 0},
	{"config", 'c', "CONFIG_FILE", 0, "Specify path to configuration file. "
		"Defaults to: " DEFAULT_CONFIG_FILE, 0},
	{0}
};

/***
 *  \brief Argument parsing callback function that is used with argp
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	/* Argp passes void pointer to arguments struct inside state */
	struct arguments *arguments = state->input;

	switch (key) {
	/* Handle foreground argument */
	case 'f':
		arguments->foreground = true;
		break;
	/* Handle config file argument */
	case 'c':
		arguments->config_file = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};

/***
 * \brief Function to parse arguments of TEE Core Process
 * @param argc[in] Argument count from main
 * @param argv[in] Array of argument strings from main
 * @param args[out] Structure where parsed arguments are places
 */
void args_parse(int argc, char **argv, struct arguments *args)
{
	/* Handle argument parsing with Argp */
	argp_parse(&argp, argc, argv, 0, 0, args);
}
