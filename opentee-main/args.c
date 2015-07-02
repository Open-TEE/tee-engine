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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

static const char usage[] =
"Usage: %s [OPTION...]\n"
"Open-TEE Core Process -- A program which runs Trusted Applications\n"
"\n"
"  -p, --pid-dir=PID_DIR      Specify path to keep pid file. Defaults to:\n"
"                             /var/run/opentee when run by root, or \n"
"                             /tmp/opentee when run by a non-root user.\n"
"  -c, --config=CONFIG_FILE   Specify path to configuration file. Defaults to:\n"
"                             /etc/opentee.conf\n"
"  -f, --foreground           Do not daemonize but start the process in\n"
"                             foreground\n"
"  -h, --help                 Give this help list\n"
"\n";

/***
 * \brief Function to parse arguments of TEE Core Process
 * @param argc[in] Argument count from main
 * @param argv[in] Array of argument strings from main
 * @param args[out] Structure where parsed arguments are places
 */
void args_parse(int argc, char **argv, struct arguments *args)
{
	int c;
	int option_index = 0;

	struct option long_options[] = {
		{"pid-dir", required_argument, 0, 'p'},
		{"config", required_argument, 0, 'c'},
		{"foreground", no_argument, 0, 'f'},
		{"help", no_argument, 0, '?'},
		{0, 0, 0, 0}
	};

	do {
		c = getopt_long(argc, argv, "fp:c:h", long_options, &option_index);

		switch (c) {
		case 'p':
			args->pid_dir = optarg;
			break;
		case 'c':
			args->config_file = optarg;
			break;
		case 'f':
			args->foreground = true;
			break;
		case 'h':
			printf(usage, argv[0]);
			exit(0);
		case -1:
			/* End of arguments */
			break;
		case '?':
			/* Invalid options */
			printf(usage, argv[0]);
			exit(1);
		default:
			exit(1);
			break;
		}
	} while (c != -1);
}
