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

#include "tee_tui_api.h"
#include "callbacks.h"

TEE_Result TEE_TUICheckTextFormat(char *text,
				  uint32_t *width,
				  uint32_t *height,
				  uint32_t *lastIndex)
{
	TEE_Result (*check_text_format)(char *,
					uint32_t *,
					uint32_t *,
					uint32_t *) =
		fn_ptr_tui_check_text_format();

	return check_text_format(text, width, height, lastIndex);
}

TEE_Result TEE_TUIGetScreenInfo(TEE_TUIScreenOrientation screenOrientation,
				uint32_t nbEntryFields,
				TEE_TUIScreenInfo *screenInfo)
{
	TEE_Result (*get_screen_info)(TEE_TUIScreenOrientation,
				      uint32_t,
				      TEE_TUIScreenInfo *) =
		fn_ptr_tui_get_screen_info();

	return get_screen_info(screenOrientation, nbEntryFields, screenInfo);
}

TEE_Result TEE_TUIInitSession()
{
	TEE_Result (*init_session)() =
		fn_ptr_tui_init_session();

	return init_session();
}

TEE_Result TEE_TUICloseSession()
{
	TEE_Result (*close_session)() =
		fn_ptr_tui_close_session();

	return close_session();
}

TEE_Result TEE_TUIDisplayScreen(TEE_TUIScreenConfiguration *screenConfiguration,
				bool closeTUISession,
				TEE_TUIEntryField *entryFields,
				uint32_t entryFieldCount,
				TEE_TUIButtonType *selectedButton)
{
	TEE_Result (*display_screen)(TEE_TUIScreenConfiguration *,
				     bool,
				     TEE_TUIEntryField *,
				     uint32_t,
				     TEE_TUIButtonType *) =
		fn_ptr_tui_display_screen();

	return display_screen(screenConfiguration,
			      closeTUISession,
			      entryFields,
			      entryFieldCount,
			      selectedButton);
}
