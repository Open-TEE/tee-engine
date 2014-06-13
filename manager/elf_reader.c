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

const char *ta_section_name = ".ta_config";

struct list_head *head;

/*!
 *  \brief Initializes a list.
 *  \return 0 when initialization is successful, -1 otherwise.
 */
static int initialize_list()
{
	head = (struct list_head *) malloc(sizeof(struct list_head));
	if (!head) {
		syslog(LOG_ERR, "Error while initializing list.");
		return -1;
	}
	INIT_LIST(head);
	return 0;
}

/*!
 *  \brief Prints all parameters of TA metadata. Implemented for debugging purpose.
 */
static void print_ta_metadata(struct ta_metadata *ta_mdata)
{
	int i = 0;
	printf("------------------------------------------------------------------\n");
	printf("ELF file name : %s\n", ta_mdata->elf_file_name);
	printf("timelow : %x\n", ta_mdata->appID.timeLow);
	printf("timeMid : %x\n", ta_mdata->appID.timeMid);
	printf("timeHiAndVersion : %x\n", ta_mdata->appID.timeHiAndVersion);
	printf("clockSeqAndNode : [ ");
	for (; i < 8; i++) {
		printf("%x ", ta_mdata->appID.clockSeqAndNode[i]);
	}
	printf("]\n");
	printf("dataSize: %zx \n", ta_mdata->dataSize);
	printf("stackSize: %zu \n",ta_mdata->stackSize);
	printf("singletonInstance: %d \n", ta_mdata->singletonInstance);
	printf("multiSession: %d \n", ta_mdata->multiSession);
	printf("instanceKeepAlive: %d \n", ta_mdata->instanceKeepAlive);
	printf("------------------------------------------------------------------\n");
}

/*!
 *  \brief Prints elements of a list. Implemented for debugging purpose.
 */
static void print_ta_metadata_list()
{
	struct list_head *pos;
	struct ta_metadata *element;
	LIST_FOR_EACH (pos, head) {
		element = LIST_ENTRY(pos, struct ta_metadata, list);
		print_ta_metadata(element);
	}
	return;
}

/*!
 *  \brief Adds TA metadata to a list.
 *  \param TA metadata.
 *  \return 0 when adding TA metadata is successful, -1 otherwise.
 */
static int add_to_metadata_list(struct ta_metadata *ta_mdata)
{
	if (head == NULL) {
		/* List has not been initialized. */
		if (initialize_list() == 0) {
			syslog(LOG_INFO, "List initialization successful.");
		} else {
			syslog(LOG_ERR, "List initialization unsuccessful.");
			return -1;
		}
	}
	ta_mdata->list = (struct list_head){ &ta_mdata->list, &ta_mdata->list };
	list_add_after(&ta_mdata->list, head);
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
	unsigned int i = 0;
	struct ta_metadata *ta_mdata;
	size_t ta_metadata_size;

	/* Initialize ELF library. */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("ELF library initialization failed : %s.\n" , elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO,"ELF library initialization successful \n");
	}

	/* Open ELF file for reading */
	if ((elf_file_fd = open(elf_file, O_RDONLY, 0)) < 0) {
		syslog(LOG_ERR, "ope()n ELF file %s failed.\n", elf_file);
		return -1;
	} else {
		syslog(LOG_INFO, "open() ELF file %s successful.\n", elf_file);
	}

	if ((elf = elf_begin(elf_file_fd, ELF_C_READ, NULL)) == NULL) {
		syslog(LOG_ERR, "elf_begin() failed : %s.\n", elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO, "elf_begin() successful.\n");
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		syslog(LOG_ERR, "%s is not an ELF object.\n", elf_file);
		return -1;
	} else {
		syslog(LOG_INFO, "Confirmed %s is an ELF object.\n", elf_file);
	}

	if (elf_getshdrstrndx(elf, &shstrndx ) != 0) {
		syslog(LOG_ERR, "elf_getshdrstrndx () failed : %s.\n", elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO, "elf_getshdrstrndx () successfull.\n");
	}

	elf_scn = NULL;
	/* Scan ELF sections. */
	while ((elf_scn = elf_nextscn(elf, elf_scn)) != NULL) {
		/* Get section header */
		if (gelf_getshdr(elf_scn, &section_hdr) != &section_hdr) {
			syslog(LOG_INFO, "getshdr() failed : %s \n", elf_errmsg (-1));
		}
		/* Get section name */
		if ((section_name = elf_strptr(elf, shstrndx, section_hdr.sh_name)) == NULL) {
			syslog(LOG_INFO, "elf_strptr() failed : %s \n", elf_errmsg(-1));
		}
		/* Compare section name. */
		if (strcmp(ta_section_name, section_name) == 0) {
			syslog(LOG_INFO, "Identified section .ta_config.\n");
			elf_data = NULL;
			/* Retrieve data of an identified section.*/
			while ((elf_data = elf_getdata(elf_scn, elf_data)) != NULL) {
				section_data = (unsigned char *) elf_data->d_buf;
				i = 0;
				syslog(LOG_INFO,"Section data in hex format : ");
				for(; i < elf_data->d_size; i++) {
					syslog(LOG_INFO,"%x",section_data[i]);
				}
				ta_mdata = (struct ta_metadata *) malloc(sizeof(struct ta_metadata));
				ta_mdata->elf_file_name = elf_file;

				ta_metadata_size = sizeof(TEE_UUID) + (2 * sizeof(size_t)) +
					      (3 * sizeof(bool));
				memcpy(ta_mdata, section_data, ta_metadata_size);

				/* Add TA metadata to list. */
				add_to_metadata_list(ta_mdata);
			}
		}
	}
	elf_end(elf);
	close(elf_file_fd);
	return 0;
}

int remove_metadata(char *elf_file)
{
	struct list_head *pos;
	struct ta_metadata *node = NULL;
	struct ta_metadata *tmp;
	LIST_FOR_EACH (pos, head) {
		tmp = LIST_ENTRY(pos, struct ta_metadata, list);
		if (strcmp(tmp->elf_file_name, elf_file) == 0) {
			node = tmp;
			break;
		}
	}
	if (node != NULL) {
		list_unlink(&node->list);		
		free(node);
		syslog(LOG_INFO, "TA metadata of file %s is removed\n", elf_file);
		return 0;
	}
	return -1;
}

/*!
 *  \brief Matches TEE_UUIDs
 *  \param TEE_UUIDs to be compared.
 *  \return true when TEE UUIDs matches, -1 otherwise.
 */
bool tee_uuid_matches(TEE_UUID tee_uuid1, TEE_UUID tee_uuid2)
{
	int i = 0;
	if (tee_uuid1.timeHiAndVersion != tee_uuid2.timeHiAndVersion) {
		return false;
	}
	if (tee_uuid1.timeLow != tee_uuid2.timeLow) {
		return false;
	}
	if (tee_uuid1.timeMid != tee_uuid2.timeMid) {
		return false;
	}
	for ( ;i < 8; i++) {
		if (tee_uuid1.clockSeqAndNode[i] != tee_uuid2.clockSeqAndNode[i]) {
			return false;
		}
	}
	return true;
}

struct ta_metadata* search_ta_by_uuid(TEE_UUID tee_uuid)
{
	struct list_head *pos;
	struct ta_metadata *node;
	LIST_FOR_EACH(pos, head) {
		node = LIST_ENTRY(pos, struct ta_metadata, list);
		if(tee_uuid_matches(node->appID, tee_uuid)) {
			return node;
		}
	}
	return NULL;
}
