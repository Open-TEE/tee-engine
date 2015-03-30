/*****************************************************************************
** Copyright (C) 2015 Tanel Dettenborn.                                     **
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

#include <seccomp.h>
#include <sys/prctl.h>
#include <stddef.h>

#include "tee_logging.h"
#include "tee_seccomp.h"

static int manager_io_thread_filter(scmp_filter_ctx ctx)
{
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
		goto err;
#ifdef OT_LOGGING
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
		goto err;
#endif

	return 0;
err:
	OT_LOG(LOG_ERR, "Failed to generate manager IO thread filter");
	return 1;
}

static int manager_logic_thread_filter(scmp_filter_ctx ctx)
{
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0) < 0)
		goto err;
#ifdef OT_LOGGING
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
		goto err;
#endif

	return 0;
err:
	OT_LOG(LOG_ERR, "Failed to generate manager logic thread filter");
	return 1;
}

static int ta_io_thread_filter(scmp_filter_ctx ctx)
{
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) < 0)
		goto err;
#ifdef OT_LOGGING
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto err;
#endif

	return 0;
err:
	OT_LOG(LOG_ERR, "Failed to generate TA IO thread filter");
	return 1;
}

static int ta_logic_thread_filter(scmp_filter_ctx ctx)
{
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
		goto err;
#ifdef OT_LOGGING
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0)
		goto err;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
		goto err;
#endif

	return 0;
err:
	OT_LOG(LOG_ERR, "Failed to generate TA logic thread filter");
	return 1;
}

int tee_set_seccomp_filter(uint8_t ot_thread)
{
	scmp_filter_ctx ctx = NULL;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		OT_LOG(LOG_ERR, "prctl PR_SET_NO_NEW_PRIVS failed");
		return -1;
	}

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		OT_LOG(LOG_ERR, "Seccomp init failed");
		goto err;
	}

	switch (ot_thread) {
	case SET_MANAGER_IO_THREAD_FILTER:
		if (manager_io_thread_filter(ctx))
			goto err;
		break;

	case SET_MANAGER_LOGIC_THREAD_FILTER:
		if (manager_logic_thread_filter(ctx))
			goto err;
		break;

	case SET_TA_IO_THREAD_FILTER:
		if (ta_io_thread_filter(ctx))
			goto err;
		break;

	case SET_TA_LOGIC_THREAD_FILTER:
		if (ta_logic_thread_filter(ctx))
			goto err;
		break;

	default:
		goto err;
	}

	if (seccomp_load(ctx) < 0) {
		OT_LOG(LOG_ERR, "Seccomp filter load failed");
		goto err;
	}

	seccomp_release(ctx);
	return 0;

err:
	seccomp_release(ctx);
	return 1;
}
