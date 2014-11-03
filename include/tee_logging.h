/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#define DBG_LOCATION "%s:%s:%d  "

/*!
  Print message to syslog with addidional information.
*/
#define OT_LOG(level, message, ...)                                                                \
	syslog(level, DBG_LOCATION message, __FILE__, __func__, __LINE__, ##__VA_ARGS__);

/*!
  Print message to syslog without addidional infromation.
*/
#define OT_LOG1(level, message, ...) syslog(level, message, ##__VA_ARGS__);

#endif /* __TEE_LOGGING_H__ */
