/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#include "dynamic_loader.h"
#include "conf_parser.h"
#include "core_control_resources.h"
#include "tee_logging.h"

#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

TEE_Result load_ta(const char *path, struct ta_interface **callbacks)
{
	struct ta_interface tmp_cb;
	char *err = NULL;

	memset((void *)&tmp_cb, 0, sizeof(struct ta_interface));
	*callbacks = NULL;

	dlerror();

	tmp_cb.library = dlopen(path, RTLD_LAZY);
	if (!tmp_cb.library) {
		OT_LOG(LOG_DEBUG, "Failed to load library : %s : %s", path, dlerror());
		return TEE_ERROR_GENERIC;
	}

	/* To be a valid TA it must not have any errors when loading the lbrary AND
	 * it MUST provide each of the 5 entry functions listed below!!
	 */

	*(void **)(&tmp_cb.create) = dlsym(tmp_cb.library, "TA_CreateEntryPoint");
	err = dlerror();
	if (err != NULL || !tmp_cb.create) {
		OT_LOG(LOG_DEBUG, "Failed to find CreateEntryPoint : %s : %s", path, err);
		goto err_cleanup;
	}

	*(void **)(&tmp_cb.destroy) = dlsym(tmp_cb.library, "TA_DestroyEntryPoint");
	err = dlerror();
	if (err != NULL || !tmp_cb.destroy) {
		OT_LOG(LOG_DEBUG, "Failed to find DestroyEntryPoint : %s : %s", path, err);
		goto err_cleanup;
	}

	*(void **)(&tmp_cb.open_session) = dlsym(tmp_cb.library, "TA_OpenSessionEntryPoint");
	err = dlerror();
	if (err != NULL || !tmp_cb.open_session) {
		OT_LOG(LOG_DEBUG, "Failed to find OpenSessionEntryPoint : %s : %s", path, err);
		goto err_cleanup;
	}

	*(void **)(&tmp_cb.invoke_cmd) = dlsym(tmp_cb.library, "TA_InvokeCommandEntryPoint");
	err = dlerror();
	if (err != NULL || !tmp_cb.invoke_cmd) {
		OT_LOG(LOG_DEBUG, "Failed to find InvokeCommandEntryPoint : %s : %s", path, err);
		goto err_cleanup;
	}

	*(void **)(&tmp_cb.close_session) = dlsym(tmp_cb.library, "TA_CloseSessionEntryPoint");
	err = dlerror();
	if (err != NULL || !tmp_cb.close_session) {
		OT_LOG(LOG_DEBUG, "Failed to find CloseSession Entry point : %s : %s", path, err);
		goto err_cleanup;
	}

	*callbacks = TEE_Malloc(sizeof(struct ta_interface), 0);
	if (!*callbacks) {
		OT_LOG(LOG_DEBUG, "Out of memory");
		goto err_cleanup;
	}

	memcpy(*callbacks, (void *)&tmp_cb, sizeof(struct ta_interface));

err_cleanup:

	if (err || !*callbacks) {
		if (tmp_cb.destroy)
			tmp_cb.destroy();
		dlclose(tmp_cb.library);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

void unload_ta(struct ta_interface *callbacks)
{
	if (!callbacks)
		return;

	dlerror();

	/* Call the TA cleanup routine */
	callbacks->destroy();

	if (dlclose(callbacks->library))
		OT_LOG(LOG_DEBUG, "Error while closing library : %s", dlerror());

	TEE_Free(callbacks);

	return;
}
