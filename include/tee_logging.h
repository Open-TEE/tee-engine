/*****************************************************************************
** Copyright (C) 2014 Intel Corperation.                                    **
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

#ifndef __TEE_LOGGING_H__
#define __TEE_LOGGING_H__

#include <syslog.h>

#define OT_LOG(level, message) syslog(level, "%s:%s:%d  %s\n", \
	__FILE__, __func__, __LINE__, message);

#endif /* __TEE_LOGGING_H__ */
