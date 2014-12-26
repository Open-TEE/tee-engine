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

#ifndef __LOGIC_THREAD_TUI_H__
#define __LOGIC_THREAD_TUI_H__

#include "extern_resources.h"

void tui_send_error_msg(uint32_t ret, proc_t destination);

void tui_display_init(struct manager_msg *man_msg);
void tui_check_text_format(struct manager_msg *man_msg);
void tui_get_screen_info(struct manager_msg *man_msg);
void tui_init_session(struct manager_msg *man_msg);
void tui_close_session(struct manager_msg *man_msg);
void tui_display_screen(struct manager_msg *man_msg);

/* TODO: Remove */
void tui_display_ta_msg(struct manager_msg *man_msg);

#endif /* __LOGIC_THREAD_TUI_H__ */
