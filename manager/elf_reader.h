#ifndef __TEE_ELF_READER__
#define __TEE_ELF_READER__

#include "data_types.h"
#include "tee_list.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

struct ta_metadata_list {
	struct ta_metadata *ta_mdata;
	//struct ta_metadata_list *next;
	struct list_head *list;
};

int read_metadata(char *);

int remove_metadata(char *);

struct ta_metadata* search_ta_by_uuid(TEE_UUID tee_uuid);

#endif
