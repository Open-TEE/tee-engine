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

#include "tee_internal_api.h"
#include "tee_tui_data_types.h"

TEE_Result tui_check_text_format(char *text,
				 uint32_t *width,
				 uint32_t *height,
				 uint32_t *lastIndex);

TEE_Result tui_get_screen_info(TEE_TUIScreenOrientation screenOrientation,
			       uint32_t nbEntryFields,
			       TEE_TUIScreenInfo *screenInfo);

TEE_Result tui_init_session();

TEE_Result tui_close_session();

TEE_Result tui_display_screen(TEE_TUIScreenConfiguration *screenConfiguration,
			      bool closeTUISession,
			      TEE_TUIEntryField *entryFields,
			      uint32_t entryFieldCount,
			      TEE_TUIButtonType *selectedButton);
