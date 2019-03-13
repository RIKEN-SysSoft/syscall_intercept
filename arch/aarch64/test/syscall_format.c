/*
 * Copyright 2017-2018, Intel Corporation
 * syscall_format.c COPYRIGHT FUJITSU LIMITED 2019
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * syscall_format.c
 * A simple test program that makes a lot of basic syscalls.
 * Basic in the sense of there being no special case for handling
 * them in syscall_intercept. The main goal is to test logging
 * of these syscalls.
 *
 */

#ifdef __clang__

#pragma clang optimize off
#pragma clang diagnostic ignored "-Wnonnull"
#pragma clang diagnostic ignored "-Wunused-result"
#pragma clang diagnostic ignored "-Wall"

#elif defined(__GNUC_MINOR__)

#pragma GCC optimize "-O0"
#pragma GCC diagnostic ignored "-Wnonnull"
#pragma GCC diagnostic ignored "-Wunused-result"
#pragma GCC diagnostic ignored "-Wall"

#endif

/* Avoid "warning _FORTIFY_SOURCE requires compiling with optimization (-O)" */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <linux/kexec.h>
#include <linux/mempolicy.h>
#include <mqueue.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/quota.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "libsyscall_intercept_hook_point.h"
#include "magic_syscalls.h"

static bool test_in_progress;

static long mock_result = 22;

/*
 * hook
 * The hook function used for all logged syscalls in this test. This test would
 * be impractical, if all these syscalls would be forwarded to the kernel.
 * Mocking all the syscalls guarantees the reproducibility of syscall results.
 */
static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) syscall_number;
	(void) arg0;
	(void) arg1;
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;

	if (!test_in_progress)
		return 1;

	*result = mock_result;

	return 0;
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;

	intercept_hook_point = hook;

	test_in_progress = true;

	void *p0 = (void *)0x123000;
	void *p1 = (void *)0x234000;

	magic_syscall_start_log(argv[1], "1");

	/* VM management */
	mock_result = -EINVAL;
	mmap(NULL, 0, 0, 0, 0, 0);
	mock_result = 22;
	mmap(p0, 0x8000, PROT_EXEC, MAP_SHARED, 99, 0x1000);
	mprotect(p0, 0x4000, PROT_READ);
	mprotect(NULL, 0x4000, PROT_WRITE);
	munmap(p0, 0x4000);
	munmap(NULL, 0x4000);
	brk(p0);
	brk(NULL);
	mremap(p0, ((size_t)UINT32_MAX) + 7, ((size_t)UINT32_MAX) + 77,
			MREMAP_MAYMOVE);

	syscall(SYS_gettid);

	syscall(SYS_futex, p0, FUTEX_WAKE, 7L, p0, p1, 1L);

	syscall(SYS_exit, 0);
	syscall(888, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5);

	test_in_progress = false;
	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
