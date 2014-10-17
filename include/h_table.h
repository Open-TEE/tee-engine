/*****************************************************************************
** Copyright (C) 2014 Tanel Dettenborn		                            **
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

/* TODO: Buckets are alloced dynamically, but hashtable not. Not the best soluiton if
 * hashtable size cannot be estimated at creation */

/* NOTE: Not a thread safe! */

#ifndef __H_TABLE_H__
#define	__H_TABLE_H__

#include <stdint.h>
#include <stdlib.h>

typedef struct __HashTableHandler *HASHTABLE;

void h_table_create(HASHTABLE *table, size_t size);
int h_table_insert(HASHTABLE table, unsigned char *key, size_t key_len, void *data);
void *h_table_get(HASHTABLE table, unsigned char *key, size_t key_len);
void *h_table_remove(HASHTABLE table, unsigned char *key, size_t key_len);
void h_table_free(HASHTABLE table);

/* Iteration funcs */
void h_table_init_stepper(HASHTABLE table);
void *h_table_step(HASHTABLE table);
int h_table_empty(HASHTABLE table);

#endif /* __H_TABLE_H__ */
