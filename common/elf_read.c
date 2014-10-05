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

#include <gelf.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

#include "elf_read.h"

int get_data_from_elf(const char *elf_file, const char *sec_name, void *buf, size_t buf_len)
{
	int fd, is_sec_found = -1;
	Elf *e;
	char *name;
	Elf_Scn *scn = NULL;
	Elf_Data *data = NULL;
	GElf_Shdr shdr;
	size_t shstrndx;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		syslog(LOG_ERR, "get_ta_data: Elf version\n");
		return 1;
	}

	fd = open(elf_file, O_RDONLY, 0);
	if (!fd) {
		syslog(LOG_ERR, "get_ta_data: Open file\n");
		return 1;
	}

	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e) {
		syslog(LOG_ERR, "get_ta_data: Elf begin\n");
		goto end;
	}

	if (elf_kind(e) != ELF_K_ELF) {
		syslog(LOG_ERR, "get_ta_data: elf kind\n");
		goto end;
	}

	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		syslog(LOG_ERR, "get_ta_data: elf kind\n");
		goto end;
	}

	while (1) {

		scn = elf_nextscn(e, scn);
		if (!scn)
			break;

		if (gelf_getshdr(scn, &shdr) != &shdr) {
			syslog(LOG_ERR, "get_ta_data: gelf getshdr\n");
			goto end;
		}

		name = elf_strptr(e, shstrndx, shdr.sh_name);
		if (!name) {
			syslog(LOG_ERR, "get_ta_data: elf_strptr\n");
			goto end;
		}

		if (strlen(sec_name) != strlen(name))
			continue;

		if (!strcasecmp(sec_name, name)) {
			data = elf_getdata(scn, data);
			if (!data) {
				syslog(LOG_ERR, "get_ta_data: elf_getdata\n");
				goto end;
			}

			if (buf_len > data->d_size) {
				memcpy(buf, data->d_buf, data->d_size);
				is_sec_found = 0;

			} else {
				syslog(LOG_ERR, "get_ta_data: Buffer too small\n");
				goto end;
			}
		}
	}

end:
	if (is_sec_found)
		syslog(LOG_ERR, "get_ta_data: sec not found\n");

	elf_end(e);
	close(fd);
	return is_sec_found;
}
