/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

#include "ta_internal_thread_tui.h"
#include "com_protocol.h"
#include "dynamic_loader.h"
#include "ta_exit_states.h"
#include "ta_extern_resources.h"
#include "ta_internal_thread.h"
#include "tee_data_types.h"
#include "tee_cancellation.h"
#include "ta_io_thread.h"
#include "tee_list.h"
#include "tee_logging.h"
#include "cmp.h"

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

struct array {
	size_t len;
	size_t pos;
	uint8_t *buf;
};

static bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t limit)
{
	struct array *a = (struct array *) ctx->buf;

	/* Check that we don't read past the end of array */
	if (a->pos + limit > a->len)
		limit = a->len - a->pos;

	memcpy(data, &(a->buf[a->pos]), limit);

	/* Increment current read position */
	a->pos += limit;

	return limit;
}

static size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count)
{
	struct array *a = (struct array *) ctx->buf;

	/* Increase size of buffer every time it is being written to */
	a->buf = realloc(a->buf, a->len + count);
	if (a->buf == NULL) {
		a->len = 0;

		OT_LOG(LOG_ERR, "Out of memory");
		return 0;
	}

	memcpy(&(a->buf[a->len]), data, count);

	/* Increment the length of the buffer */
	a->len += count;

	return count;
}

TEE_Result tui_check_text_format(char *text,
				 uint32_t *width,
				 uint32_t *height,
				 uint32_t *lastIndex)
{
	struct ta_task *new_ta_task = NULL;
	cmp_ctx_t cmp;
	struct array msg = {sizeof(struct com_msg_tui_ta2display),
		            0,
	                    calloc(1, sizeof(struct com_msg_tui_ta2display))};

	/* Serialize CheckTextFormat Request into Messagepack format */
	cmp_init(&cmp, &msg, buffer_reader, buffer_writer);

	if (!cmp_write_str(&cmp, text, strlen(text))) {
		OT_LOG(LOG_ERR, "Serialization error");
		return TEE_ERROR_GENERIC;
	}

	new_ta_task = calloc(1, sizeof(struct ta_task));
	if (!new_ta_task) {
		OT_LOG(LOG_ERR, "Out of memory");
		return TEE_ERROR_GENERIC;
	}

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	//return wait_and_handle_invoke_cmd_resp(paramTypes, params, returnOrigin, ta_shm);

err_1:
	/* TODO: Free memory allocations on error */
	return TEE_ERROR_GENERIC;
}
