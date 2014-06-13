/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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
#include "elf_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <gelf.h>
#include <syslog.h>
#include <pthread.h>

const char *ta_section_name = ".ta_config";

struct list_head *head;

pthread_mutex_t list_mutex;

/*!
 *  \brief Initializes a list.
 *  \return 0 when initialization is successful, -1 otherwise.
 */
static int initialize_list()
{
	head = (struct list_head *) malloc(sizeof(struct list_head));
	if (head == NULL)
		return -1;
	INIT_LIST(head);
	return 0;
}

/*!
 *  \brief Adds TA metadata to a list.
 *  \param TA metadata.
 *  \return 0 when adding TA metadata is successful, -1 otherwise.
 */
static int add_to_metadata_list(struct ta_metadata *ta_mdata)
{
	if (!head) {
		/* List has not been initialized. */
		if (initialize_list() == -1) {
			syslog(LOG_ERR, "List initialization failed.");
			return -1;
		}
	}
	ta_mdata->list = (struct list_head) LIST_HEAD_INIT(ta_mdata->list);

	pthread_mutex_lock(&list_mutex);
	list_add_after(&ta_mdata->list, head);
	pthread_mutex_unlock(&list_mutex);
	return 0;
}

int read_metadata(char *elf_file)
{
	int elf_file_fd;
	Elf *elf;
	char *section_name;
	unsigned char *section_data;
	Elf_Scn *elf_scn;
	Elf_Data *elf_data;
	GElf_Shdr section_hdr;
	size_t shstrndx;
	struct ta_metadata *ta_mdata;
	size_t ta_metadata_size;

	/* Initialize ELF library. */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("ELF library initialization failed : %s.\n" , elf_errmsg(-1));
		goto err_cleanup;
	}

	/* Open ELF file for reading */
	elf_file_fd = open(elf_file, O_RDONLY, 0);
	if (elf_file_fd < 0) {
		syslog(LOG_ERR, "ope()n ELF file %s failed.\n", elf_file);
		goto err_cleanup;
	}

	elf = elf_begin(elf_file_fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		syslog(LOG_ERR, "elf_begin() failed : %s.\n", elf_errmsg(-1));
		goto err_cleanup;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		syslog(LOG_ERR, "%s is not an ELF object.\n", elf_file);
		goto err_cleanup;
	}

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		syslog(LOG_ERR, "elf_getshdrstrndx() failed : %s.\n", elf_errmsg(-1));
		goto err_cleanup;
	}

	elf_scn = NULL;
	/* Scan ELF sections. */
	while ((elf_scn = elf_nextscn(elf, elf_scn)) != NULL) {
		/* Get section header */
		if (gelf_getshdr(elf_scn, &section_hdr) != &section_hdr) {
			syslog(LOG_ERR, "getshdr()failed : %s\n", elf_errmsg(-1));
			continue;
		}
		/* Get section name */
		section_name = elf_strptr(elf, shstrndx, section_hdr.sh_name);
		if (section_name == NULL) {
			syslog(LOG_ERR, "elf_strptr() failed : %s\n", elf_errmsg(-1));
			continue;
		}
		/* Compare section name. */
		if (strcmp(ta_section_name, section_name) == 0) {
			elf_data = NULL;
			/* Retrieve data of an identified section.*/
			while ((elf_data = elf_getdata(elf_scn, elf_data)) != NULL) {
				section_data = (unsigned char *) elf_data->d_buf;
				ta_mdata = (struct ta_metadata *)
					   malloc(sizeof(struct ta_metadata));
				if (ta_mdata == NULL) {
					syslog(LOG_ERR, "Out of memory.");
					goto err_cleanup;
				}
				ta_mdata->elf_file_name = elf_file;

				/* data from section data needs to be copied just for parameters
				 * appID, dataSize, stackSize, singletonInstance, multiSession,
				 * instanceKeepAlive. Therefore while copying data from
				 * section_data size of char * (elf_file_name) and list_head
				 * is excluded from the total size of ta_metadata.
				 */
				ta_metadata_size = sizeof(struct ta_metadata) -
						   sizeof(char *) -
						   sizeof(struct list_head);
				memcpy(ta_mdata, section_data, ta_metadata_size);
				/* Add TA metadata to list. */
				add_to_metadata_list(ta_mdata);
			}
		}
	}
err_cleanup:
	if (!elf)
		elf_end(elf);
	if (elf_file_fd)
		close(elf_file_fd);
	return -1;

	elf_end(elf);
	close(elf_file_fd);
	return 0;
}

int remove_metadata(char *elf_file)
{
	struct list_head *pos;
	struct ta_metadata *remove_node;

	LIST_FOR_EACH(pos, head) {
		remove_node = LIST_ENTRY(pos, struct ta_metadata, list);
		if (strcmp(remove_node->elf_file_name, elf_file) == 0) {
			pthread_mutex_lock(&list_mutex);
			list_unlink(&remove_node->list);
			pthread_mutex_unlock(&list_mutex);

			free(remove_node);
			return 0;
		}
	}
	return -1;
}

struct ta_metadata *search_ta_by_uuid(TEE_UUID tee_uuid)
{
	struct list_head *pos;
	struct ta_metadata *node;

	LIST_FOR_EACH(pos, head) {
		node = LIST_ENTRY(pos, struct ta_metadata, list);
		if (bcmp(&node->appID, &tee_uuid, sizeof(TEE_UUID)) == 0)
			return node;
	}
	return NULL;
}
