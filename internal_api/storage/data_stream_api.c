/*****************************************************************************
** Copyright (C) 2015 Open-TEE project.	                                    **
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <types.h>
#include <unistd.h>

#include "../tee_panic_api.h"
#include "../tee_storage_api.h"
#include "object_handle.h"
#include "storage_utils.h"

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object,
			      void *buffer,
			      uint32_t size,
			      uint32_t *count)
{
	if (object == NULL || buffer == NULL || count == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_READ))
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);

	if (object->per_object.data_position >= object->per_object.data_size) {
		/* if creater or equal, need to return 0 read and set the position to end */
		object->per_object.data_position = object->per_object.data_size;
		*count = 0;
		return TEE_SUCCESS;
	}

	if (fseek(object->per_object.file, object->per_object.data_position, SEEK_SET) != 0)
		TEE_Panic(TEE_ERROR_GENERIC);

	*count = fread(buffer, 1, size, object->per_object.file);
	object->per_object.data_position += *count;
	return TEE_SUCCESS;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object,
			       void *buffer,
			       uint32_t size)
{
	long write_bytes;
	TEE_Result ret;

	if (object == NULL || buffer == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE))
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);

	if (object->per_object.data_position + size > TEE_MAX_DATA_SIZE)
		return TEE_ERROR_OVERFLOW;

	if (object->per_object.data_position > object->per_object.data_size) {

		ret = TEE_TruncateObjectData(object, object->per_object.data_position);
		if (ret != TEE_SUCCESS)
			return ret;
	}

	if (fseek(object->per_object.file, object->per_object.data_position, SEEK_SET) != 0)
		TEE_Panic(TEE_ERROR_GENERIC);

	write_bytes = fwrite(buffer, 1, size,object->per_object.file);
	if (write_bytes != size)
		TEE_Panic(TEE_ERROR_GENERIC);

	if ((write_bytes + object->per_object.data_position) > object->per_object.data_size)
		object->per_object.data_size = object->per_object.data_position + write_bytes;

	object->per_object.data_position += write_bytes;

	return TEE_SUCCESS;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object,
				  uint32_t size)
{
	if (object == NULL || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (!(object->objectInfo.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE))
		TEE_Panic(TEE_ERROR_ACCESS_DENIED);

	if (ftruncate(fileno(object->per_object.file), size) != 0) {
		if (errno == ENOSPC)
			return TEE_ERROR_STORAGE_NO_SPACE;
		TEE_Panic(TEE_ERROR_GENERIC);
	}

	object->per_object.data_size = size;

	return TEE_SUCCESS;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object,
			      int32_t offset,
			      TEE_Whence whence)
{
	uint32_t begin;
	uint32_t end;
	uint32_t pos;

	if (object == NULL  || !(object->objectInfo.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	begin = object->per_object.data_begin;
	end = object->per_object.data_size;
	pos = object->per_object.data_position;

	/* if whence is SEEK_CUR should stay as current pos */
	if (whence == TEE_DATA_SEEK_END)
		pos = end;
	else if (whence == TEE_DATA_SEEK_SET)
		pos = begin;

	pos += offset;

	/* check for underflow */
	if (pos < begin)
		pos = begin;

	if (pos > TEE_MAX_DATA_SIZE)
		return TEE_ERROR_OVERFLOW;

	object->per_object.data_position = pos;

	return TEE_SUCCESS;
}
