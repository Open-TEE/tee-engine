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

	OT_LOG(LOG_ERR, "len: %zu, pos: %zu", a->len, a->pos);

	/* Check that we don't read past the end of array */
	if (a->pos + limit > a->len)
		limit = a->len - a->pos;

	OT_LOG(LOG_ERR, "memcpy %p %p %zu", data, &(a->buf[a->pos]), limit);
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

	OT_LOG(LOG_ERR, "len: %i count: %i", a->len, count);

	return count;
}

static bool init_request(struct array *msg, struct ta_task **new_ta_task)
{
	struct com_msg_tui_ta2display msg_hdr;

	msg->len = sizeof(struct com_msg_tui_ta2display);
	msg->pos = 0;
	msg->buf = calloc(1, sizeof(struct com_msg_tui_ta2display));
	if (msg->buf == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		return false;
	}

	memset(&msg_hdr, 0, sizeof(msg_hdr));

	msg_hdr.msg_hdr.msg_type = COM_TYPE_QUERY;
	msg_hdr.msg_hdr.msg_name = COM_MSG_NAME_TUI_TA2DISPLAY_MSG;

	memcpy(msg->buf, &msg_hdr, sizeof(msg_hdr));

	*new_ta_task = calloc(1, sizeof(struct ta_task));
	if (*new_ta_task == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		return false;
	}

	return true;
}

static bool wait_for_response(struct com_msg_tui_ta2display **msg,
			      struct array *msg_array)
{
	OT_LOG(LOG_ERR, "Waiting for respo");

	if (!wait_response_msg())
		return false;

	OT_LOG(LOG_ERR, "Got respo, len: %zu", response_msg_len);

	*msg = response_msg;
	msg_array->buf = response_msg;
	msg_array->len = response_msg_len;

	response_msg = NULL;
	response_msg_len = 0;

	return true;
}

static TEE_Result wait_and_handle_tui_check_text_format_resp(uint32_t *width,
							     uint32_t *height,
							     uint32_t *lastIndex)
{
	struct com_msg_tui_ta2display *msg = NULL;
	struct array msg_array = {0,
				  sizeof(struct com_msg_tui_ta2display),
				  NULL};
	uint32_t array_size = 0;
	cmp_ctx_t cmp;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!wait_for_response(&msg, &msg_array))
		goto err;

	/* Deserialize MessagePack structure */
	cmp_init(&cmp, &msg_array, buffer_reader, buffer_writer);

	OT_LOG(LOG_ERR, "Cmp init");

	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 3 ||
	    !cmp_read_uint(&cmp, width) ||
	    !cmp_read_uint(&cmp, height) ||
	    !cmp_read_uint(&cmp, lastIndex)) {
		OT_LOG(LOG_ERR, "Deserialization error: %s", cmp_strerror(&cmp));
		goto err;
	}

	OT_LOG(LOG_ERR, "width: %u, height: %u, lastIndex: %u", *width, *height, *lastIndex);

err:
	free(msg);

	return ret;
}

TEE_Result tui_check_text_format(char *text,
				 uint32_t *width,
				 uint32_t *height,
				 uint32_t *lastIndex)
{
	struct ta_task *new_ta_task = NULL;
	cmp_ctx_t cmp;
	struct array msg = {0, 0, NULL};

	if (!init_request(&msg, &new_ta_task))
		goto err;

	/* Serialize CheckTextFormat Request into Messagepack format */
	cmp_init(&cmp, &msg, buffer_reader, buffer_writer);

	if (!cmp_write_str(&cmp, text, strlen(text))) {
		OT_LOG(LOG_ERR, "Serialization error");
		goto err;
	}

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_tui_check_text_format_resp(width, height, lastIndex);

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}
