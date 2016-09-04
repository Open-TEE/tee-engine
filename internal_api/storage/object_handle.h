/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#ifndef __OBJECT_HANDLE_H__
#define __OBJECT_HANDLE_H__

#include <stdio.h>
#include "crypto/operation_handle.h"

struct persistant_object {
	char obj_id[TEE_OBJECT_ID_MAX_LEN + 1];
	uint32_t obj_id_len;
	uint32_t data_begin;
	uint32_t data_size;
	uint32_t data_position;
};

struct __TEE_ObjectHandle {
	struct persistant_object per_object;
	TEE_ObjectInfo objectInfo;
	struct gp_key *key;
};

#endif /* __OBJECT_HANDLE_H__ */
