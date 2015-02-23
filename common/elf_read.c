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

#include <libelf.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "elf_read.h"
#include "tee_logging.h"

#define MAX_SEC_NAME_LEN 20

bool get_data_from_elf(const char *elf_file, const char *sec_name, void *buf, size_t *buf_len)
{
	int fd;
	bool is_sec_found = false;
	Elf *file;
	char *name;
	Elf_Scn *scn = NULL;
	Elf_Data *data = NULL;
	size_t shstrndx;
#if __WORDSIZE == 32
	Elf32_Shdr *elf_hdr;
#else
	Elf64_Shdr *elf_hdr;
#endif
	if (elf_version(EV_CURRENT) == EV_NONE) {
		OT_LOG(LOG_ERR, "Elf version");
		return false;
	}

	fd = open(elf_file, O_RDONLY, 0);
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Open file");
		return false;
	}

	file = elf_begin(fd, ELF_C_READ, NULL);
	if (!file) {
		OT_LOG(LOG_ERR, "Elf begin failed : %s", elf_errmsg(elf_errno()));
		goto end;
	}

	if (elf_kind(file) != ELF_K_ELF)
		goto end; /* No error message, this might cause log fill */


	if (elf_getshdrstrndx(file, &shstrndx) != 0) {
		OT_LOG(LOG_ERR, "elf getshdrstrndx : %s", elf_errmsg(elf_errno()));
		goto end;
	}

	while (!is_sec_found) {

		scn = elf_nextscn(file, scn);
		if (!scn)
			break;

#if __WORDSIZE == 32
		elf_hdr = elf32_getshdr(scn);
		if (!elf_hdr) {
			OT_LOG(LOG_ERR, "elf getshdr : %s", elf_errmsg(elf_errno()));
			goto end;
		}
#else

		elf_hdr = elf64_getshdr(scn);
		if (!elf_hdr) {
			OT_LOG(LOG_ERR, "elf getshdr : %s", elf_errmsg(elf_errno()));
			goto end;
		}
#endif

		name = elf_strptr(file, shstrndx, elf_hdr->sh_name);
		if (!name) {
			OT_LOG(LOG_ERR, "elf_strptr : %s", elf_errmsg(elf_errno()));
			goto end;
		}

		if (!strncasecmp(sec_name, name, MAX_SEC_NAME_LEN)) {
			data = elf_getdata(scn, data);
			if (!data) {
				OT_LOG(LOG_ERR, "elf_getdata : %s", elf_errmsg(elf_errno()));
				goto end;
			}

			if (*buf_len >= data->d_size) {
				memcpy(buf, data->d_buf, data->d_size);
				*buf_len = data->d_size;
				is_sec_found = true;
				break;

			} else {
				OT_LOG(LOG_ERR, "Buffer too small");
				goto end;
			}
		}
	}

end:
	elf_end(file);
	close(fd);
	return is_sec_found;
}
