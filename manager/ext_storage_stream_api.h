/*
 * ext_stream_api.h
 *
 *  Created on: 6 Mar 2015
 *      Author: w
 */

#ifndef EMULATOR_MANAGER_EXT_STORAGE_BLOB_API_H_
#define EMULATOR_MANAGER_EXT_STORAGE_BLOB_API_H_

#include <stdint.h>
#include "tee_storage_common.h"

#define IS_VALID_STORAGE_BLOB(a) (a != 0 && a != 0xFFFFFFFF)

/* !/brief
 * returns valid storage id on success
 */

uint32_t ext_object_id_to_storage_id(char *objectid, size_t objectid_len);

uint32_t ext_open_storage_blob(char *objectID, size_t objectIDlen, bool create_if_not_exist);
void ext_close_storage_blob(uint32_t storage_blob_id);
void ext_delete_storage_blob(uint32_t storage_blob_id, void *objectID, size_t objectIDLen);

size_t ext_get_storage_blob_size(uint32_t storage_blob_id);



bool ext_change_object_ID(uint32_t storage_blob_id,
			  void *objectID, size_t objectIDLen,
			  void *new_objectID, size_t new_objectIDLen);


bool ext_alloc_for_enumerator(uint32_t *ID);
void ext_free_enumerator(uint32_t free_enum_ID);
void ext_reset_enumerator(uint32_t reset_enum_ID);
bool ext_start_enumerator(uint32_t start_enum_ID);
bool ext_get_next_obj_from_enumeration(uint32_t get_next_ID,
				       struct storage_obj_meta_data *recv_data_to_caller);

uint32_t ext_read_stream(uint32_t storage_blob_id, uint32_t offset, void *data, size_t datalen);
uint32_t ext_write_stream(uint32_t storage_blob_id, uint32_t offset, void *data, size_t datalen);
TEE_Result ext_truncate_storage_blob(uint32_t storage_blob_id, uint32_t size);


#endif /* EMULATOR_MANAGER_EXT_storage_blob_API_H_ */
