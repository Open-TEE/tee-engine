/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
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

#include <stdio.h>
#include <stdlib.h>

#include "tee_panic.h"
#include "tee_logging.h"

void TEE_Panic(TEE_Result panicCode)
{
	panicCode = panicCode;

	printf("P A N I C !\n");

	OT_LOG(LOG_DEBUG, "TA panicked and panic func has been reached\n");

	exit(panicCode);
}
