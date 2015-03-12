/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
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

#ifndef __TEE_OBJECT_HANDLE_H__
#define __TEE_OBJECT_HANDLE_H__

#include <stdio.h>
#include "tee_storage_api.h"

struct persistant_object_info {
	char obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t obj_id_len;
	uint32_t  storage_blob_id;
	size_t data_begin;
	/* size after data begin */
	size_t data_size;
	/* position in stream starting from data_begin */
	size_t data_position;
};

struct __TEE_ObjectHandle {
	struct persistant_object_info per_object;
	TEE_ObjectInfo objectInfo;
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t maxObjSizeBytes;
};

#endif /* __TEE_OBJECT_HANDLE_H__ */
