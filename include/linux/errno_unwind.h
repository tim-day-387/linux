/* SPDX-License-Identifier: GPL-2.0 */
/*
 * errno_unwind - attribute failing syscalls to the kernel function that
 * originated the negative errno, using the function graph tracer's return
 * value recording.
 */
#ifndef _LINUX_ERRNO_UNWIND_H
#define _LINUX_ERRNO_UNWIND_H

#include <linux/types.h>

#ifdef CONFIG_ERRNO_UNWIND

/*
 * Number of distinct errno values tracked per syscall invocation. A single
 * call chain rarely propagates more than a couple of distinct error codes,
 * so a small table is plenty and keeps the per-task footprint tiny.
 */
#define ERRNO_UNWIND_SLOTS 8

struct errno_unwind_slot {
	int		val;	/* negative errno returned to userspace */
	int		depth;	/* graph depth of the deepest returner seen */
	unsigned long	func;	/* deepest function that returned that errno */
};

/*
 * Per-task transient state, valid only between the sys_enter and sys_exit
 * tracepoints of the current syscall. Only ever touched by the owning task
 * (in tracepoint/fgraph context), so it needs no locking.
 */
struct errno_unwind_task {
	bool				armed;	/* inside a tracked syscall */
	u8				n;	/* used entries in slot[] */
	long				nr;	/* syscall number in flight */
	struct errno_unwind_slot	slot[ERRNO_UNWIND_SLOTS];
};

static inline void errno_unwind_init_task(struct errno_unwind_task *eu)
{
	eu->armed = false;
	eu->n = 0;
}

#endif /* CONFIG_ERRNO_UNWIND */
#endif /* _LINUX_ERRNO_UNWIND_H */
