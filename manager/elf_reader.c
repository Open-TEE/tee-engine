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

const char *TA_SECTION_NAME = ".ta_config";

struct ta_metadata_list *head = NULL;
struct ta_metadata_list *current = NULL;

void print_ta_metadata(ta_metadata *ta_mdata) {
	int i = 0;
	printf("------------------------------------------------------------------\n");
	printf("ELF file name : %s\n", ta_mdata->elf_file_name);
	printf("timelow : %x\n", ta_mdata->appID.timeLow);
	printf("timeMid : %x\n", ta_mdata->appID.timeMid);
	printf("timeHiAndVersion : %x\n", ta_mdata->appID.timeHiAndVersion);
	printf("clockSeqAndNode : [ ");
	for(; i < 8; i++) {
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

int add_to_metadata_list(ta_metadata *ta_mdata)
{
	struct ta_metadata_list *node;
	if(head == NULL) {
		// List has not been created.
		head = (struct ta_metadata_list *)malloc(sizeof(struct ta_metadata_list));
		if(head == NULL) {
			syslog(LOG_ERR, "Node creation failed \n");
			return -1;
		}
		head->ta_mdata = ta_mdata;
		head->next = NULL;
		current = head;
	} else {
		node = (struct ta_metadata_list *)malloc(sizeof(struct ta_metadata_list));
		if (node == NULL ) {
			syslog(LOG_ERR, "Node creation failed \n");
			return -1;
		}
		node->ta_mdata = ta_mdata;
		node->next = NULL;
		current->next = node;
		current = node;
	}
	// REMOVE
	print_ta_metadata(ta_mdata);
	return 0;
}

void print_ta_metadata_list()
{
	struct ta_metadata_list *node = head;
	while(node != NULL) {
		print_ta_metadata(node->ta_mdata);
		node = node->next;
	}
	return;
}

size_t extract_data_and_stack_size(unsigned char *sec_data, int index, bool is_32bit, bool is_little_endian)
{
	size_t tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8;
	size_t value;
	if (is_32bit) {
		if (is_little_endian) {
			tmp1 = (size_t)sec_data[index + 3];
			tmp2 = (size_t)sec_data[index + 2];
			tmp3 = (size_t)sec_data[index + 1];
			tmp4 = (size_t)sec_data[index];
		} else {
			tmp1 = (size_t)sec_data[index];
			tmp2 = (size_t)sec_data[index + 1];
			tmp3 = (size_t)sec_data[index + 2];
			tmp4 = (size_t)sec_data[index + 3];
		}
		value = (size_t)((tmp1 << 24) | (tmp2 << 16) | (tmp3 << 8) | (tmp4));
	} else {
		if (is_little_endian) {
			tmp1 = (size_t)sec_data[index + 7];
			tmp2 = (size_t)sec_data[index + 6];
			tmp3 = (size_t)sec_data[index + 5];
			tmp4 = (size_t)sec_data[index + 4];
			tmp5 = (size_t)sec_data[index + 3];
			tmp6 = (size_t)sec_data[index + 2];
			tmp7 = (size_t)sec_data[index + 1];
			tmp8 = (size_t)sec_data[index];

		} else {
			tmp1 = (size_t)sec_data[index];
			tmp2 = (size_t)sec_data[index + 1];
			tmp3 = (size_t)sec_data[index + 2];
			tmp4 = (size_t)sec_data[index + 3];
			tmp5 = (size_t)sec_data[index + 4];
			tmp6 = (size_t)sec_data[index + 5];
			tmp7 = (size_t)sec_data[index + 6];
			tmp8 = (size_t)sec_data[index + 7];
		}
		value = (size_t)((tmp1 << 56) | (tmp2 << 48) | (tmp3 << 40) | (tmp4 << 32) |
				 (tmp5 << 24) | (tmp6 << 16) | (tmp7 << 8) | tmp8);
	}
	return value;
}

uint32_t get_timeLow(unsigned char *section_data)
{
	uint32_t timeLow, tmp1, tmp2, tmp3, tmp4;
	tmp1 = (uint32_t)section_data[0];
	tmp2 = (uint32_t)section_data[1];
	tmp3 = (uint32_t)section_data[2];
	tmp4 = (uint32_t)section_data[3];
	timeLow = (tmp1 << 24) | (tmp2 << 16) | (tmp3 << 8) | (tmp4);
	syslog(LOG_INFO, "timelow : %x\n", timeLow);
	return timeLow;
}

uint16_t get_timeMid(unsigned char *section_data)
{
	uint16_t timeMid, tmp1, tmp2;
	tmp1 = (uint16_t)section_data[4];
	tmp2 = (uint16_t)section_data[5];
	timeMid = (tmp1 << 8) | (tmp2);
	syslog(LOG_INFO, "timeMid : %x\n", timeMid);
	return timeMid;
}

uint16_t get_timeHiAndVersion(unsigned char *section_data)
{
	uint16_t timeHiAndVersion, tmp1, tmp2;
	tmp1 = (uint16_t)section_data[6];
	tmp2 = (uint16_t)section_data[7];
	timeHiAndVersion = (tmp1 << 8) | (tmp2);
	syslog(LOG_INFO, "timeHiAndVersion : %x\n", timeHiAndVersion);
	return timeHiAndVersion;
}

size_t get_dataSize(unsigned char *section_data, bool is_32bit, bool is_little_endian)
{
	size_t dataSize = extract_data_and_stack_size(section_data, 16, is_32bit, is_little_endian);
	syslog(LOG_INFO, "dataSize: %zx \n", dataSize);
	return dataSize;
}

size_t get_stackSize(unsigned char *section_data, bool is_32bit, bool is_little_endian)
{
	int start_index = is_32bit ? 20 : 24;
	size_t stackSize = extract_data_and_stack_size(section_data, start_index, is_32bit, is_little_endian);
	syslog(LOG_INFO, "stackSize: %zu \n", stackSize);
	return stackSize;
}

bool get_singletonInstance(unsigned char *section_data, bool is_32bit)
{
	bool singletonInstance;
	int index = is_32bit ? 24 : 32 ;
	singletonInstance = ((int)section_data[index]) == 0 ? false : true;
	syslog(LOG_INFO, "singletonInstance: %d \n", singletonInstance);
	return singletonInstance;
}

bool get_multiSession(unsigned char *section_data, bool is_32bit)
{
	bool multiSession;
	int index = is_32bit ? 25 : 33 ;
	multiSession = ((int)section_data[index]) == 0 ? false : true;
	syslog(LOG_INFO, "multiSession: %d \n", multiSession);
	return multiSession;
}

bool get_instanceKeepAlive(unsigned char *section_data, bool is_32bit)
{
	bool instanceKeepAlive;
	int index = is_32bit ? 26 : 34 ;
	instanceKeepAlive = ((int)section_data[index]) == 0 ? false : true;
	syslog(LOG_INFO, "instanceKeepAlive: %d \n", instanceKeepAlive);
	return instanceKeepAlive;
}

/*!
 * \brief read_metadata
 * From ELF file reads metadata stored in section .ta_config.
 * \param elf_file The complete file name of an ELF file.
 */
int read_metadata(char *elf_file)
{
	int elf_file_fd;
	int elf_class;
	Elf *elf;
	char *section_name;
	unsigned char *section_data;
	Elf_Scn *elf_scn;
	Elf_Data *elf_data ;
	GElf_Shdr section_hdr;
	size_t shstrndx;
	bool is_32bit;
	bool is_little_endian;
	char *ident;
	unsigned int i = 0;
	ta_metadata *ta_mdata;

	// Initialize ELF library.
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("ELF library initialization failed : %s \n" , elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO,"ELF library initialization successful \n");
	}

	// Open ELF file for reading
	if ((elf_file_fd = open(elf_file, O_RDONLY, 0)) < 0) {
		syslog(LOG_ERR, "ope()n ELF file %s failed. \n", elf_file);
		return -1;
	} else {
		syslog(LOG_INFO, "open() ELF file %s successful. \n", elf_file);
	}

	if ((elf = elf_begin(elf_file_fd, ELF_C_READ, NULL)) == NULL) {
		syslog(LOG_ERR, "elf_begin() failed : %s. \n", elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO, "elf_begin() successful. \n");
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		syslog(LOG_ERR, "%s is not an ELF object. \n", elf_file);
		return -1;
	} else {
		syslog(LOG_INFO, "Confirmed %s is an ELF object.\n", elf_file);
	}

	if ((elf_class = gelf_getclass(elf)) == ELFCLASSNONE) {
		syslog(LOG_ERR, "getclass() failed : %s. \n" , elf_errmsg(-1));
		return -1;
	}

	if (elf_class == ELFCLASS32) {
		is_32bit = true;
		syslog(LOG_INFO, "ELF object %s is 32 bit compliant.\n", elf_file);
	} else {
		is_32bit = false;
		syslog(LOG_INFO, "ELF object %s is 64 bit compliant.\n", elf_file);
	}

	ident = elf_getident(elf, (size_t *)NULL);
	if (ident[EI_DATA] == ELFDATA2LSB) {
		is_little_endian = true;
		syslog(LOG_INFO, "ELF object %s is little endian.\n", elf_file);
	} else if (ident[EI_DATA] == ELFDATA2MSB) {
		is_little_endian = false;
		syslog(LOG_INFO, "ELF object %s is big endian.\n", elf_file);
	} else {
		syslog(LOG_ERR, "Failed to get the byte order of ELF file. %s. \n", elf_errmsg(-1));
		return -1;
	}

	if (elf_getshdrstrndx(elf, &shstrndx ) != 0) {
		syslog(LOG_ERR, "elf_getshdrstrndx () failed : %s. \n", elf_errmsg(-1));
		return -1;
	} else {
		syslog(LOG_INFO, "elf_getshdrstrndx () successfull. \n");
	}

	elf_scn = NULL;
	// Scan ELF sections.
	while ((elf_scn = elf_nextscn(elf, elf_scn)) != NULL) {
		// Get section header
		if (gelf_getshdr(elf_scn, &section_hdr) != &section_hdr) {
			syslog(LOG_INFO, "getshdr() failed : %s \n", elf_errmsg (-1));
		}
		// Get section name
		if ((section_name = elf_strptr(elf, shstrndx, section_hdr.sh_name)) == NULL) {
			syslog(LOG_INFO, "elf_strptr() failed : %s \n", elf_errmsg(-1));
		}
		// Compare section name.
		if(strcmp(TA_SECTION_NAME, section_name) == 0) {
			syslog(LOG_INFO, "Identified section .ta_config.\n");
			elf_data = NULL;
			// Retrieve data of an identified section.
			while ((elf_data = elf_getdata(elf_scn, elf_data)) != NULL) {
				section_data = (unsigned char *) elf_data-> d_buf;
				i = 0;
				syslog(LOG_INFO,"Section data in hex format : ");
				for(; i < elf_data->d_size; i++) {
					syslog(LOG_INFO,"%x",section_data[i]);
				}
				syslog(LOG_INFO,"\n");

				ta_mdata = (ta_metadata*) malloc(sizeof(ta_metadata));
				ta_mdata->elf_file_name = elf_file;

				// Extract timeLow
				ta_mdata->appID.timeLow = get_timeLow(section_data);
				// Extract timeMid
				ta_mdata->appID.timeMid = get_timeMid(section_data);
				// Extract timeHiAndVersion
				ta_mdata->appID.timeHiAndVersion = get_timeHiAndVersion(section_data);

				// Extract clockSeqAndNode
				syslog(LOG_INFO, "clockSeqAndNode : [ ");
				for(i = 0; i < 8; i++) {
					ta_mdata->appID.clockSeqAndNode[i] = (uint8_t)(section_data[8+i]);
					syslog(LOG_INFO, "%x ",ta_mdata->appID.clockSeqAndNode[i]);
				}
				syslog(LOG_INFO, "]\n");

				// get data size
				ta_mdata->dataSize = get_dataSize(section_data, is_32bit, is_little_endian);
				// get stack size
				ta_mdata->stackSize = get_stackSize(section_data, is_32bit, is_little_endian);
				// get singletonInstance
				ta_mdata->singletonInstance = get_singletonInstance(section_data, is_32bit);
				// get multiSession
				ta_mdata->multiSession = get_multiSession(section_data, is_32bit);
				// get instanceKeepAlive
				ta_mdata->instanceKeepAlive = get_instanceKeepAlive(section_data, is_32bit);
				// Add TA metadata to list.
				add_to_metadata_list(ta_mdata);
			}
		}
	}
	elf_end(elf);
	close(elf_file_fd);
	return 0;	
}

struct ta_metadata_list* get_identified_TAs() {
	return head;
}

bool tee_uuid_matches(TEE_UUID tee_uuid1, TEE_UUID tee_uuid2) {
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

struct ta_metadata_list* search_ta_by_uuid(TEE_UUID tee_uuid) {
	struct ta_metadata_list *node = head;
	while(node != NULL) {
		if(tee_uuid_matches(node->ta_mdata->appID, tee_uuid)) {
			return node;
		}
		node = node->next;
	}
	return NULL;
}
