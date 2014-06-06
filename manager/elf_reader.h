#ifndef __TEE_ELF_READER__
#define __TEE_ELF_READER__

#include "data_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
	TEE_UUID appID;
	size_t dataSize;
	size_t stackSize;
	bool singletonInstance;
	bool multiSession;
	bool instanceKeepAlive;
	char *elf_file_name;
} ta_metadata;

struct ta_metadata_list {
	ta_metadata *ta_mdata;
	struct ta_metadata_list *next;
};

int read_metadata(char *);

struct ta_metadata_list* get_identified_TAs();

struct ta_metadata_list* search_ta_by_uuid(TEE_UUID tee_uuid);

#endif
