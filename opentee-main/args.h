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

#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>

struct arguments {
	bool foreground;
	char *config_file;
};

/* Allow this to be sepecified on the compile line -D */
#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "/etc/opentee.conf"
#endif

#define DEFAULT_ARGUMENTS {.foreground = false, \
			   .config_file = DEFAULT_CONFIG_FILE}

void args_parse(int argc, char **argv, struct arguments *args);

#endif /* ARGS_H */
