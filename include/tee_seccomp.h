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

#ifndef __TEE_SECCOMP_H__
#define __TEE_SECCOMP_H__

/* For enabling seccomp, compile open-tee -DHAVE_SECCOMP */

/* Useful documentation: Syscall needed for syslog():
 *	open, fstat, mmap, read, lseek, close, munmap, socket, connect, sendto and exit_group */

/* Useful documentation: OpenTEE all system calls. There might be more calls than in this list,
 * because error path could call unlisted system call:
	rt_sigreturn, exit_group, exit, write, clone, socketpair, brk, open, fstat, mmap, read,
	close, munmap, prctl, set_robust_list, eventfd2, futex, mprotect, access, epoll_create,
	stat, poll, inotify_init, inotify_add_watch, getuid, epoll_ctl, openat, lseek, getdents,
	socket, connect, unlink, bind, sendto, listen, rt_sigprocmask, epoll_wait, accept, readv,
	writev, fcntl, getppid, gettid, statfs, ftruncate, recvmsg, kill, sendmsg, getpid */

/* tee_set_seccomp_filter paramters */
#define SET_MANAGER_IO_THREAD_FILTER	0xA1
#define SET_MANAGER_LOGIC_THREAD_FILTER	0xA2
#define SET_TA_IO_THREAD_FILTER		0xA3
#define SET_TA_LOGIC_THREAD_FILTER	0xA4

/* Used filters are collected into this file. Filters can be moved to more proper location
 * when it is decited how seccomp is deployed. This is an abstarction layer */

/*!
 * \brief tee_set_seccomp_filter
 * Function is generating and loading seccomp filter for thread
 * \param ot_thread which thread filter is generated and loaded
 * \return 0 on success
 */
int tee_set_seccomp_filter(uint8_t ot_thread);

#endif /* __TEE_SECCOMP_H__ */
