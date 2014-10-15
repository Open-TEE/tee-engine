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

#ifndef __TEE_OBJECT_ENUM_HANDLE_H__
#define __TEE_OBJECT_ENUM_HANDLE_H__

#include "tee_data_types.h"
#include "tee_storage_api.h"

struct storage_obj_meta_data {
	char obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	size_t obj_id_len;
	uint32_t attrs_count;
	uint32_t meta_size;
	TEE_ObjectInfo info;
};

#endif /* __TEE_OBJECT_ENUM_HANDLE_H__ */
