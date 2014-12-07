/*****************************************************************************
** Copyright (C) 2014 Tanel Dettenborn.	                                    **
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

#ifndef __TEE_CANCELLATION_H__
#define __TEE_CANCELLATION_H__

#include <stdbool.h>

bool TEE_GetCancellationFlag(void);
bool TEE_UnmaskCancellation(void);
bool TEE_MaskCancellation(void);

#endif /* __TEE_CANCELLATION_H__ */
