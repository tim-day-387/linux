// SPDX-License-Identifier: GPL-2.0
/*
 * errno_unwind - automatically attribute failing syscalls to the kernel
 * function that originated the negative errno.
 *
 * When a syscall returns a value in the errno range [-MAX_ERRNO, -1], we want
 * to know *which* function first produced that error code, rather than just
 * the syscall that propagated it back to userspace.
 *
 * Mechanism:
 *   - The sys_enter/sys_exit tracepoints bracket each syscall and give us the
 *     syscall number and the final return value reliably and arch-portably.
 *   - In between, the function graph tracer (with return-value recording)
 *     reports every traced function's return value as the call stack unwinds.
 *   - For each distinct errno value seen during the syscall we keep the
 *     *deepest* function (by graph call depth) that returned it. An errno
 *     propagates upward unchanged, so the deepest frame returning value V is
 *     the one nearest to where V was first produced -- its originator -- while
 *     the syscall entry stubs and wrappers that merely pass it through sit at
 *     shallow depths and are ignored.
 *   - At sys_exit, we look up the deepest returner of the syscall's final errno
 *     and fold (syscall, errno, originator) into an aggregated table exposed
 *     via /proc/errno_unwind.
 *
 * Why depth and not call-chain linkage: the SYSCALL_DEFINE wrappers
 * (__x64_sys_, __se_sys_ and __do_sys_ prefixed) and the do_*() workers they
 * invoke are tail calls, and the __do_sys_ body is inlined. Tail-call
 * optimization collapses the caller/callee frames in exactly that layer, so an
 * approach that hands the originator "up to the parent frame" loses it there
 * and ends up crediting the wrapper (e.g. __se_sys_unlinkat) instead of the
 * real source. Depth only needs each frame's own return, so it is robust to
 * that collapse.
 *
 * Caveats (inherent to ftrace / undecidable at this granularity):
 *   - Inlined functions have no separate frame; attribution lands on the
 *     nearest non-inlined caller.
 *   - "Deepest returner of V" can be fooled if an *unrelated* subtree returns
 *     the same errno value V deeper than the real originator but has its result
 *     ignored. Distinct errno values are always disambiguated correctly; only
 *     same-value collisions are ambiguous, and resolving them would require
 *     value/taint tracking the kernel does not have at runtime.
 *
 * Usage:
 *   echo 1 > /proc/errno_unwind   # start tracing
 *   echo 0 > /proc/errno_unwind   # stop tracing
 *   echo c > /proc/errno_unwind   # clear the table
 *   cat   /proc/errno_unwind      # dump syscall -> originator map
 */

#define pr_fmt(fmt) "errno_unwind: " fmt

#include <linux/err.h>
#include <linux/ftrace.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>

#include <asm/syscall.h>
#include <asm/unistd.h>

#include <trace/events/syscalls.h>
#include <trace/syscall.h>

/* Aggregated (syscall, errno, originator) result table. */
#define EU_MAX_ENTRIES 1024

struct eu_entry {
	long		nr;	/* syscall number */
	long		err;	/* negative errno returned to userspace */
	unsigned long	func;	/* originating function (0 if unknown) */
	u64		count;	/* number of times observed */
};

static struct eu_entry eu_table[EU_MAX_ENTRIES];
static int eu_count;
static bool eu_overflow;
static DEFINE_SPINLOCK(eu_lock);

/*
 * Syscall metadata lives in a dedicated section bracketed by these linker
 * symbols; each entry's ->syscall_nr is filled in early in boot by
 * init_ftrace_syscalls(), well before this module's late_initcall.
 */
extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

/* Snapshot mapping syscall nr -> short name ("unlinkat"), built at init. */
static const char **eu_sys_name;

/* Serializes enable/disable; @eu_enabled reflects current registration state. */
static DEFINE_MUTEX(eu_enable_lock);
static bool eu_enabled;

/* Resolve a syscall number to its short name for pretty output. */
static const char *eu_syscall_name(long nr)
{
	if (eu_sys_name && nr >= 0 && nr < NR_syscalls)
		return eu_sys_name[nr];
	return NULL;
}

/* Fold one observation into the aggregated table. */
static void eu_record(long nr, long err, unsigned long func)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&eu_lock, flags);
	for (i = 0; i < eu_count; i++) {
		if (eu_table[i].nr == nr && eu_table[i].err == err &&
		    eu_table[i].func == func) {
			eu_table[i].count++;
			goto out;
		}
	}
	if (eu_count < EU_MAX_ENTRIES) {
		eu_table[eu_count].nr = nr;
		eu_table[eu_count].err = err;
		eu_table[eu_count].func = func;
		eu_table[eu_count].count = 1;
		eu_count++;
	} else {
		eu_overflow = true;
	}
out:
	spin_unlock_irqrestore(&eu_lock, flags);
}

/*
 * Function graph callbacks. The entry gate keeps tracing confined to the
 * syscall handler subtree (armed only between sys_enter and sys_exit), which
 * also keeps the overhead off of interrupt and other non-syscall contexts.
 */
static int notrace eu_graph_entry(struct ftrace_graph_ent *trace,
				  struct fgraph_ops *gops,
				  struct ftrace_regs *fregs)
{
	if (!current->errno_unwind.armed)
		return 0;
	/*
	 * Stay on the syscall's own call chain: an interrupt taken mid-syscall
	 * would push deeper frames whose errno returns are unrelated to the
	 * syscall and could win the "deepest returner" comparison.
	 */
	if (in_interrupt())
		return 0;
	return 1;
}

static void notrace eu_graph_return(struct ftrace_graph_ret *trace,
				    struct fgraph_ops *gops,
				    struct ftrace_regs *fregs)
{
	struct errno_unwind_task *eu = &current->errno_unwind;
	int val, depth, i;

	if (!eu->armed)
		return;
	/* Only interested in functions returning a negative errno. */
	if (!IS_ERR_VALUE(trace->retval))
		return;
	val = (int)(long)trace->retval;
	depth = trace->depth;

	/* Keep the deepest function returning each distinct errno value. */
	for (i = 0; i < eu->n; i++) {
		if (eu->slot[i].val == val) {
			if (depth > eu->slot[i].depth) {
				eu->slot[i].depth = depth;
				eu->slot[i].func = trace->func;
			}
			return;
		}
	}

	if (eu->n < ERRNO_UNWIND_SLOTS) {
		eu->slot[eu->n].val = val;
		eu->slot[eu->n].depth = depth;
		eu->slot[eu->n].func = trace->func;
		eu->n++;
	}
}

static struct fgraph_ops eu_fgraph_ops = {
	.entryfunc = eu_graph_entry,
	.retfunc   = eu_graph_return,
};

/* Tracepoint probes that bracket each syscall. */
static void eu_probe_sys_enter(void *data, struct pt_regs *regs, long id)
{
	struct errno_unwind_task *eu = &current->errno_unwind;

	eu->armed = true;
	eu->n = 0;
	eu->nr = id;
}

static void eu_probe_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	struct errno_unwind_task *eu = &current->errno_unwind;
	unsigned long func = 0;
	int i;

	if (!eu->armed)
		return;
	eu->armed = false;

	if (!IS_ERR_VALUE((unsigned long)ret))
		return;

	for (i = 0; i < eu->n; i++) {
		if (eu->slot[i].val == (int)ret) {
			func = eu->slot[i].func;
			break;
		}
	}

	eu_record(eu->nr, ret, func);
}

static int eu_enable(void)
{
	int ret;

	lockdep_assert_held(&eu_enable_lock);

	ret = register_trace_sys_enter(eu_probe_sys_enter, NULL);
	if (ret)
		return ret;

	ret = register_trace_sys_exit(eu_probe_sys_exit, NULL);
	if (ret)
		goto unreg_enter;

	/* Trace all kernel functions; the entry gate narrows it at runtime. */
	ftrace_ops_set_global_filter(&eu_fgraph_ops.ops);
	ret = register_ftrace_graph(&eu_fgraph_ops);
	if (ret)
		goto unreg_exit;

	eu_enabled = true;
	pr_info("tracing enabled\n");
	return 0;

unreg_exit:
	unregister_trace_sys_exit(eu_probe_sys_exit, NULL);
unreg_enter:
	unregister_trace_sys_enter(eu_probe_sys_enter, NULL);
	tracepoint_synchronize_unregister();
	return ret;
}

static void eu_disable(void)
{
	lockdep_assert_held(&eu_enable_lock);

	unregister_ftrace_graph(&eu_fgraph_ops);
	unregister_trace_sys_enter(eu_probe_sys_enter, NULL);
	unregister_trace_sys_exit(eu_probe_sys_exit, NULL);
	tracepoint_synchronize_unregister();

	eu_enabled = false;
	pr_info("tracing disabled\n");
}

static void eu_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&eu_lock, flags);
	eu_count = 0;
	eu_overflow = false;
	spin_unlock_irqrestore(&eu_lock, flags);
}

static int eu_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i;

	seq_printf(m, "# errno_unwind: tracing %s\n",
		   READ_ONCE(eu_enabled) ? "on" : "off");
	seq_printf(m, "# %-20s %-12s %12s  %s\n",
		   "syscall", "errno", "count", "originating function");

	spin_lock_irqsave(&eu_lock, flags);
	for (i = 0; i < eu_count; i++) {
		struct eu_entry *e = &eu_table[i];
		const char *name = eu_syscall_name(e->nr);

		if (name)
			seq_printf(m, "%-20s %-12pe %12llu  ",
				   name, ERR_PTR(e->err), e->count);
		else
			seq_printf(m, "nr=%-17ld %-12pe %12llu  ",
				   e->nr, ERR_PTR(e->err), e->count);

		if (e->func)
			seq_printf(m, "%pS\n", (void *)e->func);
		else
			seq_puts(m, "<unknown>\n");
	}
	if (eu_overflow)
		seq_puts(m, "# table full: some entries were dropped\n");
	spin_unlock_irqrestore(&eu_lock, flags);

	return 0;
}

static int eu_open(struct inode *inode, struct file *file)
{
	return single_open(file, eu_show, NULL);
}

static ssize_t eu_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char c;
	int ret = 0;

	if (!count)
		return 0;
	if (get_user(c, ubuf))
		return -EFAULT;

	mutex_lock(&eu_enable_lock);
	switch (c) {
	case '1':
		if (!eu_enabled)
			ret = eu_enable();
		break;
	case '0':
		if (eu_enabled)
			eu_disable();
		break;
	case 'c':
	case 'C':
		eu_clear();
		break;
	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&eu_enable_lock);

	return ret ? ret : count;
}

static const struct proc_ops eu_proc_ops = {
	.proc_open    = eu_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = eu_write,
};

static int __init eu_init(void)
{
	struct syscall_metadata **p;

	/*
	 * Build a nr -> short-name table from the syscall metadata section.
	 * The metadata strings ("sys_unlinkat") live in rodata for the life of
	 * the kernel, so we store the pointers (past the "sys_" prefix) rather
	 * than copy them.
	 */
	eu_sys_name = kcalloc(NR_syscalls, sizeof(*eu_sys_name), GFP_KERNEL);
	if (eu_sys_name) {
		for (p = __start_syscalls_metadata; p < __stop_syscalls_metadata; p++) {
			struct syscall_metadata *meta = *p;
			const char *name;

			if (!meta || !meta->name ||
			    meta->syscall_nr < 0 || meta->syscall_nr >= NR_syscalls)
				continue;
			name = meta->name;
			if (!strncmp(name, "sys_", 4))
				name += 4;
			eu_sys_name[meta->syscall_nr] = name;
		}
	}

	if (!proc_create("errno_unwind", 0644, NULL, &eu_proc_ops)) {
		kfree(eu_sys_name);
		eu_sys_name = NULL;
		return -ENOMEM;
	}

	pr_info("ready; 'echo 1 > /proc/errno_unwind' to start\n");
	return 0;
}
late_initcall(eu_init);
