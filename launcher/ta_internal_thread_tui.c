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
	limit = a->pos + limit > a->len ? a->len - a->pos : limit;

	/* Read amount of data specified by limit */
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

	/* Write data into buffer */
	memcpy(&(a->buf[a->len]), data, count);

	/* Increment the length of the buffer */
	a->len += count;

	return count;
}

static bool init_request(struct array *msg,
			 struct ta_task **new_ta_task,
			 uint8_t msg_name)
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
	msg_hdr.msg_hdr.msg_name = msg_name;

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
	if (!wait_response_msg())
		return false;

	*msg = response_msg;
	msg_array->buf = response_msg;
	msg_array->len = response_msg_len;

	response_msg = NULL;
	response_msg_len = 0;

	return true;
}

static TEE_Result wait_and_handle_tui_check_text_format(uint32_t *width,
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

	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 4 ||
	    !cmp_read_uint(&cmp, &ret) ||
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

	/* Parameter check */
	if (width == NULL || height == NULL || lastIndex == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	text = text == NULL ? "" : text;

	if (!init_request(&msg, &new_ta_task, COM_MSG_NAME_TUI_CHECK_TEXT_FORMAT))
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

	return wait_and_handle_tui_check_text_format(width, height, lastIndex);

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}

struct buttoninfo_text {
	char text[256];
	uint32_t length;
};

static struct buttoninfo_text buttoninfo_texts[TEE_TUI_NUMBER_BUTTON_TYPES];

static bool deserialize_buttoninfo(cmp_ctx_t *cmp,
				   TEE_TUIScreenButtonInfo *buttonInfo,
				   uint32_t i)
{
	uint32_t array_size = 0;

	memset(&buttoninfo_texts[i], 0, sizeof(struct buttoninfo_text));
	buttoninfo_texts[i].length = sizeof(buttoninfo_texts[i].text);

	if (!cmp_read_array(cmp, &array_size) ||
	    array_size != 5 ||
	    !cmp_read_str(cmp, buttoninfo_texts[i].text, &buttoninfo_texts[i].length) ||
	    !cmp_read_uint(cmp, &buttonInfo->buttonWidth) ||
	    !cmp_read_uint(cmp, &buttonInfo->buttonHeight) ||
	    !cmp_read_bool(cmp, &buttonInfo->buttonTextCustom) ||
	    !cmp_read_bool(cmp, &buttonInfo->buttonImageCustom))
		return false;

	buttonInfo->buttonText = buttoninfo_texts[i].text;

	return true;
}

static bool deserialize_buttoninfo_array(cmp_ctx_t *cmp,
					 TEE_TUIScreenInfo *screenInfo)
{
	uint32_t array_size = 0;
	uint32_t i;

	if (!cmp_read_array(cmp, &array_size) ||
	    array_size != TEE_TUI_NUMBER_BUTTON_TYPES)
		return false;

	for (i = 0; i < TEE_TUI_NUMBER_BUTTON_TYPES; ++i) {
		if (!deserialize_buttoninfo(cmp, &screenInfo->buttonInfo[i], i))
			return false;
	}

	return true;
}

static TEE_Result wait_and_handle_tui_get_screen_info(TEE_TUIScreenInfo *screenInfo)
{
	struct com_msg_tui_ta2display *msg = NULL;
	//struct com_msg_tui_display_init *msg = NULL;
	struct array msg_array = {0,
				  sizeof(struct com_msg_tui_ta2display),
				  NULL};
	uint32_t array_size = 0;
	cmp_ctx_t cmp;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!wait_for_response(&msg, &msg_array))
		goto err;

	/* Initialize screenInfo structure to 0 */
	memset(screenInfo, 0, sizeof(TEE_TUIScreenInfo));

	/* Deserialize MessagePack structure */
	cmp_init(&cmp, &msg_array, buffer_reader, buffer_writer);

	/* Deserialization */
	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 17 ||
	    !cmp_read_uint(&cmp, &ret) ||
	    !cmp_read_uint(&cmp, &screenInfo->grayscaleBitsDepth) ||
	    !cmp_read_uint(&cmp, &screenInfo->redBitsDepth) ||
	    !cmp_read_uint(&cmp, &screenInfo->greenBitsDepth) ||
	    !cmp_read_uint(&cmp, &screenInfo->blueBitsDepth) ||
	    !cmp_read_uint(&cmp, &screenInfo->widthInch) ||
	    !cmp_read_uint(&cmp, &screenInfo->heightInch) ||
	    !cmp_read_uint(&cmp, &screenInfo->maxEntryFields) ||
	    !cmp_read_uint(&cmp, &screenInfo->entryFieldLabelWidth) ||
	    !cmp_read_uint(&cmp, &screenInfo->entryFieldLabelHeight) ||
	    !cmp_read_uint(&cmp, &screenInfo->maxEntryFieldLength) ||
	    !cmp_read_uchar(&cmp, &screenInfo->labelColor[0]) ||
	    !cmp_read_uchar(&cmp, &screenInfo->labelColor[1]) ||
	    !cmp_read_uchar(&cmp, &screenInfo->labelColor[2]) ||
	    !cmp_read_uint(&cmp, &screenInfo->labelWidth) ||
	    !cmp_read_uint(&cmp, &screenInfo->labelHeight) ||
	    !deserialize_buttoninfo_array(&cmp, screenInfo))
		OT_LOG(LOG_ERR, "Deserialization error: %s", cmp_strerror(&cmp));

err:
	free(msg);

	return ret;
}

TEE_Result tui_get_screen_info(TEE_TUIScreenOrientation screenOrientation,
			       uint32_t nbEntryFields,
			       TEE_TUIScreenInfo *screenInfo)
{
	struct ta_task *new_ta_task = NULL;
	cmp_ctx_t cmp;
	struct array msg = {0, 0, NULL};

	/* Parameter check */
	/* TODO: Check screenOrientation against property gpd.tee.tui.orientation */
	if (screenInfo == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (!init_request(&msg, &new_ta_task, COM_MSG_NAME_TUI_GET_SCREEN_INFO))
		goto err;

	/* Serialize GetScreenInfo Request into Messagepack format */
	cmp_init(&cmp, &msg, buffer_reader, buffer_writer);

	/* Serialization */
	if (!cmp_write_array(&cmp, 2) ||
	    !cmp_write_uint(&cmp, screenOrientation) ||
	    !cmp_write_uint(&cmp, nbEntryFields)) {
		OT_LOG(LOG_ERR, "Serialization error");
		goto err;
	}

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_tui_get_screen_info(screenInfo);

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}

static TEE_Result wait_and_handle_tui_init_session()
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

	/* Deserialization */
	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 1 ||
	    !cmp_read_uint(&cmp, &ret))
		OT_LOG(LOG_ERR, "Deserialization error: %s", cmp_strerror(&cmp));

err:
	free(msg);

	return ret;
}

TEE_Result tui_init_session()
{
	struct ta_task *new_ta_task = NULL;
	struct array msg = {0, 0, NULL};

	if (!init_request(&msg, &new_ta_task, COM_MSG_NAME_TUI_INIT_SESSION))
		goto err;

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_tui_init_session();

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}

static TEE_Result wait_and_handle_tui_close_session()
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

	/* Deserialization */
	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 1 ||
	    !cmp_read_uint(&cmp, &ret))
		OT_LOG(LOG_ERR, "Deserialization error: %s", cmp_strerror(&cmp));

err:
	free(msg);

	return ret;
}

TEE_Result tui_close_session()
{
	struct ta_task *new_ta_task = NULL;
	struct array msg = {0, 0, NULL};

	if (!init_request(&msg, &new_ta_task, COM_MSG_NAME_TUI_CLOSE_SESSION))
		goto err;

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_tui_close_session();

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}

static bool deserialize_entryfields(cmp_ctx_t *cmp,
				    TEE_TUIEntryField *entryFields,
				    uint32_t entryFieldCount)
{
	/* TODO: Better error checks for entryField fields */

	uint32_t i = 0;
	uint32_t array_size = 0;

	if (!cmp_read_array(cmp, &array_size) ||
	    array_size != entryFieldCount) {
		OT_LOG(LOG_ERR, "Returned array size does not match entryFieldCount");
		return false;
	}

	for (i = 0; i < array_size; ++i) {
		uint32_t length = entryFields[i].bufferLength;

		if (entryFields[i].buffer == NULL) {
			OT_LOG(LOG_ERR, "Entryfield buffer has NULL pointer.");
			return false;
		}

		if (!cmp_read_str(cmp, entryFields[i].buffer, &length))
			return false;
	}

	return true;
}

static TEE_Result wait_and_handle_tui_display_screen(bool closeTUISession,
						     TEE_TUIEntryField *entryFields,
						     uint32_t entryFieldCount,
						     TEE_TUIButtonType *selectedButton)
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

	/* Deserialization */
	if (!cmp_read_array(&cmp, &array_size) ||
	    array_size != 3 ||
	    !cmp_read_uint(&cmp, &ret) ||
	    !deserialize_entryfields(&cmp, entryFields, entryFieldCount) ||
	    !cmp_read_uint(&cmp, selectedButton)) {
		OT_LOG(LOG_ERR, "Deserialization error: %s", cmp_strerror(&cmp));
		goto err;
	}

	if (closeTUISession)
		tui_close_session();

err:
	free(msg);

	return ret;
}

static bool serialize_image(cmp_ctx_t *cmp,
			    TEE_TUIImage *image)
{
	if (!cmp_write_array(cmp, 4) ||
	    !cmp_write_uint(cmp, image->source))
		return false;

	/* TODO: Image source can be Object */
	if (image->source == TEE_TUI_REF_SOURCE) {
		if (!cmp_write_str(cmp, image->ref.image, image->ref.imageLength))
			return false;
	} else {
		/* TODO: Use hack for now, write uint32_t value 0 */
		if (!cmp_write_str(cmp, "\0", 0))
			return false;
	}

	if (!cmp_write_uint(cmp, image->width) ||
	    !cmp_write_uint(cmp, image->height))
		return false;

	return true;
}

static bool serialize_screenlabel(cmp_ctx_t *cmp,
				  TEE_TUIScreenLabel *label)
{
	/* text can be null */
	char *text = label->text == NULL ? "\0" : label->text;

	if (!cmp_write_array(cmp, 9) ||
	    !cmp_write_str(cmp, text, strlen(text)) ||
	    !cmp_write_uint(cmp, label->textXOffset) ||
	    !cmp_write_uint(cmp, label->textYOffset) ||
	    !cmp_write_u8(cmp, label->textColor[0]) ||
	    !cmp_write_u8(cmp, label->textColor[1]) ||
	    !cmp_write_u8(cmp, label->textColor[2]) ||
	    !serialize_image(cmp, &label->image) ||
	    !cmp_write_uint(cmp, label->imageXOffset) ||
	    !cmp_write_uint(cmp, label->imageYOffset))
		return false;

	return true;
}

static bool serialize_button(cmp_ctx_t *cmp,
			     TEE_TUIButton *button)
{
	bool defaults;
	char *text;
	TEE_TUIImage *image;

	/* Used in the case of defaults */
	TEE_TUIImage no_image;
	memset(&no_image, 0, sizeof(no_image));
	no_image.source = TEE_TUI_NO_SOURCE;

	/* use defaults? */
	defaults = button == NULL;

	if (!cmp_write_array(cmp, 3) ||
	    !cmp_write_bool(cmp, defaults))
		return false;

	/* text can be null */
	text = defaults || button->text == NULL ? "\0" : button->text;

	image = defaults ? &no_image : &button->image;

	if (!cmp_write_str(cmp, text, strlen(text)) ||
	    !serialize_image(cmp, image))
		return false;

	return true;
}

static bool serialize_buttons(cmp_ctx_t *cmp,
			      TEE_TUIScreenConfiguration *screenConfiguration)
{
	uint32_t i;

	/* Array element for each button */
	if (!cmp_write_array(cmp, TEE_TUI_NUMBER_BUTTON_TYPES))
		return false;

	/* Go through every button and serialize */
	for (i = 0; i < TEE_TUI_NUMBER_BUTTON_TYPES; ++i) {
		if (!serialize_button(cmp, screenConfiguration->buttons[i]))
			return false;
	}

	return true;
}

static bool serialize_requestedbuttons(cmp_ctx_t *cmp,
				       TEE_TUIScreenConfiguration *screenConfiguration)
{
	uint32_t i;

	/* Array element for each button */
	if (!cmp_write_array(cmp, TEE_TUI_NUMBER_BUTTON_TYPES))
		return false;

	/* Go through every requestedbutton and serialize */
	for (i = 0; i < TEE_TUI_NUMBER_BUTTON_TYPES; ++i) {
		if (!cmp_write_bool(cmp, screenConfiguration->requestedButtons[i]))
			return false;
	}

	return true;
}

static bool serialize_screenconfiguration(cmp_ctx_t *cmp,
					  TEE_TUIScreenConfiguration *screenConfiguration)
{
	if (!cmp_write_array(cmp, 4) ||
	    !cmp_write_uint(cmp, screenConfiguration->screenOrientation) ||
	    !serialize_screenlabel(cmp, &screenConfiguration->label) ||
	    !serialize_buttons(cmp, screenConfiguration) ||
	    !serialize_requestedbuttons(cmp, screenConfiguration))
		return false;

	return true;
}

static bool serialize_entryfield(cmp_ctx_t *cmp,
				 TEE_TUIEntryField *entryField)
{
	if (!cmp_write_array(cmp, 6) ||
	    !cmp_write_str(cmp, entryField->label, strlen(entryField->label)) ||
	    !cmp_write_uint(cmp, entryField->mode) ||
	    !cmp_write_uint(cmp, entryField->type) ||
	    !cmp_write_uint(cmp, entryField->minExpectedLength) ||
	    !cmp_write_uint(cmp, entryField->maxExpectedLength) ||
	    !cmp_write_uint(cmp, entryField->bufferLength))
		return false;

	return true;
}

static bool serialize_entryfields(cmp_ctx_t *cmp,
				  TEE_TUIEntryField *entryFields,
				  uint32_t entryFieldCount)
{
	uint32_t i;

	/* Array element for each entry field */
	if (!cmp_write_array(cmp, entryFieldCount))
		return false;

	/* Go through every entryfield and serialize */
	for (i = 0; i < entryFieldCount; ++i) {
		if (!serialize_entryfield(cmp, &entryFields[i]))
			return false;
	}

	return true;
}

TEE_Result tui_display_screen(TEE_TUIScreenConfiguration *screenConfiguration,
			      bool closeTUISession,
			      TEE_TUIEntryField *entryFields,
			      uint32_t entryFieldCount,
			      TEE_TUIButtonType *selectedButton)
{
	struct ta_task *new_ta_task = NULL;
	cmp_ctx_t cmp;
	struct array msg = {0, 0, NULL};

	/* TODO: Check Entryfield buffer sizes */
	/* TODO: Panic reasons:
	 *       * If at least on of the in or out parameters, or one of the
	 *         buffers they refer, to is in shared memory.
	 *       * If label fields do not match the values returned by the
	 *         function TEE_TUIGetScreenInfo for the corresponding
	 *         orientation and number of entry fields.
	 *       * If button fields do not match the values returned by the
	 *         function TEE_TUIGetScreenInfo for the corresponding
	 *         orientation and number of entry fields.
	 *       * If entry fields do not match the values returned by the
	 *         function TEE_TUIGetScreenInfo for the corresponding
	 *         orientation and number of entry fields. In particular if
	 *         the length of at least one output string of an entry field
	 *         does not follow the rules in section 4.4.12.
	 *       * If the requested buttons to be displayed do not match one
	 *         of the authorized combinations described in section 3.3.
	 */
	/* Parameter check */
	if (screenConfiguration == NULL || selectedButton == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (!init_request(&msg, &new_ta_task, COM_MSG_NAME_TUI_DISPLAY_SCREEN))
		goto err;

	/* Serialize GetScreenInfo Request into Messagepack format */
	cmp_init(&cmp, &msg, buffer_reader, buffer_writer);

	/* Serialization */
	if (!cmp_write_array(&cmp, 3) ||
	    !serialize_screenconfiguration(&cmp, screenConfiguration) ||
	    !cmp_write_bool(&cmp, closeTUISession) ||
	    !serialize_entryfields(&cmp, entryFields, entryFieldCount)) {
		OT_LOG(LOG_ERR, "Serialization error");
		goto err;
	}

	new_ta_task->msg_len = msg.len;
	new_ta_task->msg = msg.buf;

	add_msg_done_queue_and_notify(new_ta_task);

	return wait_and_handle_tui_display_screen(closeTUISession,
						  entryFields,
						  entryFieldCount,
						  selectedButton);

err:
	/* Free memory allocations on error */
	free(new_ta_task);
	free(msg.buf);

	return TEE_ERROR_GENERIC;
}
