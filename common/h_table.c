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

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>


#include "h_table.h"

static const uint32_t H_TABLE_INIT_SIZE = 255; /* 2^8 */

struct __HashTableHandler {
	BUCKET **buckets;
	uint32_t h_table_size;
	uint32_t buckets_in_table;
	uint32_t hash_seed;
	/* For iterating through list */
	uint32_t x_index;
	BUCKET *y_index;
};

static uint32_t hash_func(HASHTABLE table, unsigned char *key, size_t key_len)
{
	/* MurmurHash2.0*/
	uint32_t m = 0x5bd1e995;
	uint32_t r = 24;
	uint32_t hash;
	uint32_t from_key_four_byte;
	unsigned char *key_ptr = (unsigned char*)key;

	hash = table->hash_seed ^ key_len;

	while (key_len >= 4) {
		from_key_four_byte = *(uint32_t*)key_ptr;

		from_key_four_byte *= m;
		from_key_four_byte ^= from_key_four_byte >> r;
		from_key_four_byte *= m;

		hash *= m;
		hash ^= from_key_four_byte;

		key_ptr += 4;
		key_len -= 4;
	}

	switch(key_len)
	{
	    case 3: hash ^= key_ptr[2] << 16;
	    case 2: hash ^= key_ptr[1] << 8;
	    case 1: hash ^= key_ptr[0];
		    hash *= m;
	};

	hash ^= hash >> 13;
	hash *= m;
	hash ^= hash >> 15;

	return hash % table->h_table_size;
}

void h_table_create(HASHTABLE *table, size_t size)
{	
	HASHTABLE tmp_table = NULL;

	if (!table)
		goto err;

	tmp_table = calloc(1, sizeof(struct __HashTableHandler));
	if (!tmp_table)
		goto err;

	tmp_table->buckets_in_table = 0;

	if (size == 0)
		tmp_table->h_table_size = H_TABLE_INIT_SIZE;
	else
		tmp_table->h_table_size = size;

	srand(time(NULL));
	tmp_table->hash_seed = (uint32_t)(rand());

	tmp_table->buckets = calloc(tmp_table->h_table_size, sizeof(BUCKET*));
	if (!tmp_table->buckets)
		goto err;

	*table = tmp_table;
	return;
err:
	free(tmp_table);
	*table = NULL;
}

int h_table_insert(HASHTABLE table, unsigned char *key, size_t key_len, void *data)
{
	uint32_t bucket_index = 0;
	BUCKET *new_bucket, *bucket_head;

	if (!table)
		return 1;

	bucket_index = hash_func(table, key, key_len);
	bucket_head = table->buckets[bucket_index];

	new_bucket = calloc(1, sizeof(BUCKET));
	if (!new_bucket)
		return 1;

	new_bucket->key = calloc(1, key_len);
	if (!new_bucket->key) {
		free(new_bucket);
		return 1;
	}

	memcpy(new_bucket->key, key, key_len);
	new_bucket->key_len = key_len;
	new_bucket->next = NULL;
	new_bucket->data = data;
	new_bucket->buck_fill = 1;

	if (!table->buckets[bucket_index]) {
		table->buckets[bucket_index] = new_bucket;
	}
	else {
		while (bucket_head->next)
			bucket_head = bucket_head->next;

		bucket_head->next = new_bucket;
	}

	table->buckets_in_table += 1;

	return 0;
}

void *h_table_get(HASHTABLE table, unsigned char *key, size_t key_len)
{
	uint32_t bucket_index;
	BUCKET *bucket_head;

	if (!table)
		return NULL;

	bucket_index = hash_func(table, key, key_len);
	bucket_head = table->buckets[bucket_index];

	while (bucket_head) {
		if (bucket_head->key_len == key_len && !bcmp(bucket_head->key, key, key_len))
			return bucket_head->data;

		bucket_head = bucket_head->next;
	}

	return NULL;
}

int h_table_remove(HASHTABLE table, unsigned char *key, size_t key_len)
{
	uint32_t bucket_index;
	BUCKET *del_buck, *pre_buck;

	if (!table)
		return 1;

	bucket_index = hash_func(table, key, key_len);
	del_buck = table->buckets[bucket_index];

	if (del_buck->key_len == key_len && !bcmp(del_buck->key, key, key_len)) {
		table->buckets[bucket_index] = del_buck->next;
		goto free_mem;
	}

	while (del_buck) {
		if (del_buck->key_len == key_len && !bcmp(del_buck->key, key, key_len)) {
			pre_buck->next = del_buck->next;
			goto free_mem;
		}
		pre_buck = del_buck;
		del_buck = del_buck->next;
	}

	return 1;

free_mem:
	free(del_buck->key);
	free(del_buck);
	table->buckets_in_table -= 1;
	return 0;
}

void h_table_free(HASHTABLE table)
{
	BUCKET *tmp;
	size_t i;

	if (!table)
		return;

	for (i = 0; i < table->h_table_size; ++i) {
		while (table->buckets[i]) {
			tmp = table->buckets[i];
			table->buckets[i] = table->buckets[i]->next;
			free(tmp->key);
			free(tmp);
		}
	}

	free(table->buckets);
	free(table);
}

void h_table_init_stepper(HASHTABLE table)
{
	if (!table)
		return;

	/* init first filled bucket */
	for (table->x_index = 0; table->x_index < table->h_table_size; ++table->x_index) {

		if (!table->buckets[table->x_index]) {
			continue;
		} else {
			table->y_index = table->buckets[table->x_index];
			return;
		}
	}
}

void *h_table_step(HASHTABLE table)
{
	BUCKET *ret_buck;

	if (!table)
		return NULL;

	ret_buck = table->y_index;

	if (ret_buck) {
		table->y_index = ret_buck->next;
		goto ret;
	}

	if (table->x_index == table->h_table_size)
		return NULL; /* End? */

	for (table->x_index = table->x_index; table->x_index < table->h_table_size; ++table->x_index) {

		if (!table->buckets[table->x_index]->buck_fill) {
			continue;
		} else {
			table->y_index = table->buckets[table->x_index];
			goto ret;
		}
	}

ret:
	return ret_buck->data;
}

int h_table_empty(HASHTABLE table)
{
	return table->buckets_in_table ? 0 : 1;
}
