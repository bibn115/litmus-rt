/* G-EDF with message passing
 */

#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/sched_plugin.h>
#include <litmus/edf_common.h>
#include <litmus/sched_trace.h>
#include <litmus/trace.h>

#include <litmus/preempt.h>
#include <litmus/budget.h>

#include <litmus/bheap.h>

#include <litmus/mailbox.h>

#ifdef CONFIG_SCHED_CPU_AFFINITY
#include <litmus/affinity.h>
#endif

#include <linux/module.h>

/* cpu_entry_t - maintain the linked and scheduled state
 */
typedef struct  {
	int 			cpu;
	struct task_struct*	linked;		/* only RT tasks */
	struct task_struct*	scheduled;	/* only RT tasks */
	raw_spinlock_t		lock;
} cpu_entry_t;
DEFINE_PER_CPU_SHARED_ALIGNED(cpu_entry_t, gedf_cpu_entries);

cpu_entry_t* gedf_cpus[NR_CPUS];

static rt_domain_t gedf;

/* master state*/
struct {
	int cpu_online[NR_CPUS];
	int cpu_idle[NR_CPUS];
	pid_t linked_pid[NR_CPUS];
	lt_t  linked_prio[NR_CPUS];
	int link_idx;
	int min_cached;
} master_state;


/* Uncomment this if you want to see all scheduling decisions in the
 * TRACE() log.
#define WANT_ALL_SCHED_EVENTS
*/


static inline cpu_entry_t *cpu_state(int cpu)
{
	cpu_entry_t *entry = *(gedf_cpus + cpu);
	BUG_ON(cpu < 0 || cpu >= (int) NR_CPUS || cpu == gedf.release_master);
	return entry;
}

/* preempt - force a CPU to reschedule
 */
static void preempt(cpu_entry_t *entry)
{
	preempt_if_preemptable(entry->scheduled, entry->cpu);
}

/* **************** master state management ************** */

/* update_cpu_position - update master's snapshot of CPU state
 */
static void update_cpu_position(cpu_entry_t *entry)
{
	if (entry->linked) {
		master_state.cpu_idle[entry->cpu]    = 0;
		master_state.linked_pid[entry->cpu]  = entry->linked->pid;
		master_state.linked_prio[entry->cpu] = get_deadline(entry->linked);
		TRACE("new pos P%d ldl:%llu lpid:%lu\n",
		      entry->cpu,
		      master_state.linked_prio[entry->cpu],
		      master_state.linked_pid[entry->cpu]);
	} else {
		master_state.cpu_idle[entry->cpu] = 1;
		TRACE("new pos P%d now idle\n", entry->cpu);
		/* speed up searches for idle CPUs */
		master_state.link_idx = entry->cpu;
	}
	master_state.min_cached = 0;
}

static int gedf_cpu_valid(int cpu)
{
	return master_state.cpu_online[cpu];
}

static int gedf_cpu_idle(int cpu)
{
	return master_state.cpu_online[cpu] && master_state.cpu_idle[cpu];
}

static int cpu_lower_prio(int a, int b)
{
	/* check for later deadline */
	if (lt_after(master_state.linked_prio[a], master_state.linked_prio[b]))
		return 1;
	/* break by PID */
	else if (master_state.linked_prio[a] == master_state.linked_prio[b])
		return master_state.linked_pid[a] > master_state.linked_pid[b];
	else
		return 0;
}

static int gedf_preempt(struct task_struct* task, int cpu)
{
	TRACE_TASK(task, "preempt-check dl:%llu idle:%d ldl:%llu lpid:%lu\n",
		   get_deadline(task), gedf_cpu_idle(cpu),
		   master_state.linked_prio[cpu], master_state.linked_pid[cpu]);
	if (gedf_cpu_idle(cpu))
		return 1;
	else if (lt_before(get_deadline(task), master_state.linked_prio[cpu]))
		return 1;
	else if (get_deadline(task) == master_state.linked_prio[cpu] &&
		 task->pid < master_state.linked_pid[cpu])
		return 1;
	else
		return 0;
}

static int find_lowest_prio_or_idle_cpu(void)
{
	int start, pos;
	int min_idx;

	start = pos = master_state.link_idx;

	/* if the position is still valid, just reuse it */
	if (master_state.min_cached)
		return pos;

	while (!gedf_cpu_valid(pos))
		pos = (pos + 1) % NR_CPUS;

	if (gedf_cpu_idle(pos)) {
		master_state.link_idx = pos;
		return pos;
	} else {
		min_idx = pos;
		pos = (pos + 1) % NR_CPUS;
	}

	TRACE(">>> pre-min search start:%d pos:%d min:%d\n", start, pos, min_idx);

	for (; pos != start; pos = (pos + 1) % NR_CPUS) {
		if (gedf_cpu_idle(pos)) {
			min_idx = pos;
			break;
		} else if (gedf_cpu_valid(pos) &&
			   cpu_lower_prio(pos, min_idx))
			min_idx = pos;
	TRACE(">>> min search start:%d pos:%d min:%d\n", start, pos, min_idx);
	}

	TRACE(">>> post-min search start:%d pos:%d min:%d\n", start, pos, min_idx);

	master_state.link_idx = min_idx;
	master_state.min_cached = 1;
	return min_idx;
}



/* **************** helper functions ************** */

static cpu_entry_t *locked_cpu_state(int cpu)
{
	cpu_entry_t *state = cpu_state(cpu);
	raw_spin_lock(&state->lock);
	return state;
}

static void unlock_cpu_state(cpu_entry_t *state)
{
	raw_spin_unlock(&state->lock);
}

/* assumes interrupts off */
static cpu_entry_t *lock_scheduled_on(struct task_struct *task)
{
	int cpu;
	cpu_entry_t *sched_on;

	while (1) {
		cpu = tsk_rt(task)->scheduled_on;

		if (cpu != NO_CPU) {
			sched_on = locked_cpu_state(cpu);
			/* check if the task is scheduled */
			if (tsk_rt(task)->scheduled_on == cpu)
				/* yes, return locked */
				return sched_on;
			else
				/* no, moved, try again */
				unlock_cpu_state(sched_on);
		} else
			return NULL;
	}
}


/* assumes interrupts off */
static cpu_entry_t *lock_linked_on(struct task_struct *task)
{
	int cpu;
	cpu_entry_t *linked_on;

	while (1) {
		cpu = tsk_rt(task)->linked_on;

		if (cpu != NO_CPU) {
			linked_on = locked_cpu_state(cpu);
			/* check if the task is scheduled */
			if (tsk_rt(task)->linked_on == cpu) {
				BUG_ON(linked_on->linked != task);
				/* yes, return locked */
				return linked_on;
			} else
				/* no, moved, try again */
				unlock_cpu_state(linked_on);
		} else
			return NULL;
	}
}



/* **************** main scheduling functions ************** */

static int task_is_stale(struct task_struct *t)
{
	if (unlikely(tsk_rt(t)->job_completed)) {
		TRACE_TASK(t, "stale; completed\n");
		return 1;
	} else if (unlikely(tsk_rt(t)->job_suspended)) {
		TRACE_TASK(t, "stale; suspended\n");
		return 1;
	} else if (unlikely(tsk_rt(t)->job_exited)) {
		TRACE_TASK(t, "stale, exited\n");
		return 1;
	} else
		return 0;
}

static void queue_task(struct task_struct *task)
{
	/* sanity check before insertion */
	BUG_ON(!task);
	BUG_ON(tsk_rt(task)->linked_on != NO_CPU);

	if (task_is_stale(task)) {
		/* no point in adding this task to anywhere if it is already stale */
		TRACE_TASK(task, "not queueing task b/c it is stale\n");
		return;
	}

	BUG_ON(is_queued(task));

	if (is_early_releasing(task) || is_released(task, litmus_clock())) {
		TRACE_TASK(task, "queue_task::add_ready\n");
		__add_ready(&gedf, task);
	} else {
		TRACE_TASK(task, "queue_task::add_release\n");
		/* it has got to wait */
		__add_release(&gedf, task);
	}
}


static struct task_struct * dequeue_task(void)
{
	struct task_struct *t = NULL;

	/* Filter all tasks that got put in the queue
	 * just before they became unavailable for execution. */
	do {
		t = __take_ready(&gedf);
		/* The flags might not be stable yet because t could
		 * still be executing, but we filter what we can
		 * get at this point. */
	} while (t && task_is_stale(t));

	return t;
}

static struct task_struct *maybe_swap(struct task_struct *t, int lowest_cpu)
{
	struct task_struct *tmp;
	cpu_entry_t *entry;

	entry = lock_scheduled_on(t);
	if (entry) {
		/* still scheduled, should swap */
		TRACE_TASK(t, "swapped to P%d instead of P%d \n", entry->cpu, lowest_cpu);

		tmp = entry->linked;
		TRACE_TASK(tmp, "got swapped out\n");
		if (tmp)
			tsk_rt(tmp)->linked_on = NO_CPU;

		entry->linked = t;
		tsk_rt(t)->linked_on = entry->cpu;

		update_cpu_position(entry);
		unlock_cpu_state(entry);
		preempt(entry);

		if (entry->cpu == lowest_cpu) {
			/* Corner case: no true swap, we wanted to
			 * link here anyway. */
			if (tmp)
				queue_task(tmp);
			tmp = NULL;
		}

		return tmp;
	} else if (task_is_stale(t))
		/* no longer scheduled => flags are stable, check again */
		return NULL;
	else
		/* not scheduled, still valid, ok let's go! */
		return t;
}

static void check_for_preemptions(void)
{
	struct task_struct *t, *preempted;
	int cpu;
	cpu_entry_t *entry;

	while (1) {
		t = dequeue_task();

		TRACE_TASK(t, "considered for scheduling\n");

		if (!t) {
			TRACE("EMPTY\n");
			break;
		}

		BUG_ON(tsk_rt(t)->linked_on != NO_CPU);

		cpu = find_lowest_prio_or_idle_cpu();

		if (gedf_preempt(t, cpu)) {
			t = maybe_swap(t, cpu);
			if (t) {
				entry = locked_cpu_state(cpu);

				preempted = entry->linked;
				if (preempted)
					tsk_rt(preempted)->linked_on = NO_CPU;
				entry->linked = t;
				tsk_rt(t)->linked_on = cpu;

				/* Check for race: the task might _just_ become
				 * stale. After we set linked_on, we need to
				 * check again for staleness. The task_exit code
				 * does the reverse: it first sets job_exited and
				 * then checks linked_on.  */
				smp_wmb();
				if (task_is_stale(entry->linked)) {
					TRACE_TASK(entry->linked, "became stale after linking\n");
					/* undo preemption */
					tsk_rt(entry->linked)->linked_on = NO_CPU;
					entry->linked = NULL;
				} else
					TRACE_TASK(t, "linked to P%d\n", entry->cpu);

				update_cpu_position(entry);

				unlock_cpu_state(entry);
				preempt(entry);

				TRACE_TASK(preempted, "preempted from P%d\n", entry->cpu);

				if (preempted)
					queue_task(preempted);
			}
		} else {
			/* insufficient priority to preempt */
			queue_task(t);
			break;
		}
	}
}

static void update_cpu_position_unlocked(int cpu)
{
	cpu_entry_t *entry = locked_cpu_state(cpu);
	update_cpu_position(entry);
	unlock_cpu_state(entry);
}

/* **************** message passing interface ************** */


static void send_to_master(mailbox_callback_f fn, struct task_struct *t)
{
	int cpu = smp_processor_id();

	if (cpu == gedf.release_master)
		fn(cpu, t);
	else {
		add_mailbox_call(fn, cpu, t);
		TS_CLIENT_REQUEST_LATENCY_START;
		smp_send_mailbox(gedf.release_master);
	}
}

static void on_task_new(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	TRACE_TASK(t, "%s from P%d \n", __FUNCTION__, sender_id);

	queue_task(t);
	check_for_preemptions();

	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}

static void on_queue_flushed(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	TRACE_TASK(t, "%s from %d \n", __FUNCTION__, sender_id);

	mb();
	tsk_rt(t)->safe_to_exit += 1;

	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}

#define JOB_EXIT_OFFSET 2

static void on_exit(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;
	int was_linked_on;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	was_linked_on = tsk_rt(t)->job_exited - JOB_EXIT_OFFSET;

	TRACE_TASK(t, "%s from %d, was_linked_on:%d\n", __FUNCTION__,
		   sender_id, was_linked_on);

	if (was_linked_on != NO_CPU)
		update_cpu_position_unlocked(was_linked_on);

	if (is_queued(t)) {
		TRACE_TASK(t, "is_queued()\n");
		/* FIXME: how to determine whether the task is in a release
		 * heap?  If the task happens to be in a release heap, this
		 * will crash.  As a temporary workaround, this should work as
		 * long as tasks exit themselves (like rtspin does).
		 */

		/* remove from ready queue */
		remove(&gedf, t);
	}

	/* If some messages including this task are still in flight, then we
	 * will get in trouble once they arrive. To work around this problem,
	 * we send ourself a message that, once it is received, will imply that
	 * all messages involving this task have been processed.
	 *
	 * To this end, we add on_queue_flushed to the end of all
	 * mailboxes. Since mailboxes work in FIFO order, this should flush all
	 * pending messages.
	 */
	mailbox_broadcast(on_queue_flushed, NR_CPUS, t);

	check_for_preemptions();

	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}

static void on_resume(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;
	cpu_entry_t* cpu_state;
	lt_t now;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	TRACE_TASK(t, "%s from P%d exited:%d\n", __FUNCTION__, sender_id,
		   tsk_rt(t)->job_exited);

	if (unlikely(tsk_rt(t)->job_exited))
		goto out;

	/* It better be marked as suspended. */
	BUG_ON(!tsk_rt(t)->job_suspended);

	/* Let's make sure this task isn't currently
	 * being processed as completed. */
	cpu_state = lock_scheduled_on(t);
	/* If cpu_state == NULL, then t is no longer scheduled
	 * and we can go ahead and just do the update
	 */
	now = litmus_clock();
	if (!tsk_rt(t)->completed && is_sporadic(t) && is_tardy(t, now)) {
		/* new sporadic release */
		release_at(t, now);
		sched_trace_task_release(t);
	}
	/* can be scheduled again */
	tsk_rt(t)->job_suspended = 0;
	if (cpu_state)
		unlock_cpu_state(cpu_state);

	queue_task(t);
	check_for_preemptions();

out:
	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}

static void on_job_completion(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	TRACE_TASK(t, "%s from P%d exited:%d\n", __FUNCTION__, sender_id,
		   tsk_rt(t)->job_exited);

	if (unlikely(tsk_rt(t)->job_exited))
		goto out;

	/* It better be marked as completed! */
	BUG_ON(!tsk_rt(t)->job_completed);

	/* Cannot be linked anymore! */
	BUG_ON(lock_linked_on(t) != NULL);

	/* Could have been added to ready queue in the mean time. */
	if (is_queued(t))
		remove(&gedf, t);

	/* Clear the flag used to detect stale tasks in the ready queue. */
	tsk_rt(t)->job_completed = 0;
	/* Clear the flag used to communicate job completions to the scheduler. */
	tsk_rt(t)->completed = 0;
	prepare_for_next_period(t);
	if (is_early_releasing(t) || is_released(t, litmus_clock()))
		sched_trace_task_release(t);

	queue_task(t);

out:
	update_cpu_position_unlocked(sender_id);
	check_for_preemptions();


	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}

static void on_job_suspension(unsigned int sender_id, void *arg)
{
	unsigned long flags;
	struct task_struct *t = (struct task_struct *) arg;

	local_irq_save(flags);
	TS_DSP_HANDLER_START;

	TRACE_TASK(t, "%s from P%d exited:%d\n", __FUNCTION__, sender_id,
		   tsk_rt(t)->job_exited);

	if (unlikely(tsk_rt(t)->job_exited))
		goto out;

	/* We don't actually have to much here. The task is gone
	 * and will be reported to us when it resumes. However,
	 * we need to make sure that it wasn't queued in the mean
	 * while. */

	/* If job_suspended == 0, then the message raced with
	 * the job resuming and we simply ignore this event. */
	if (tsk_rt(t)->job_suspended) {

		/* Cannot be linked anymore! */
		BUG_ON(lock_linked_on(t) != NULL);

		/* Could have been added to ready queue in the mean time. */
		if (is_queued(t))
			remove(&gedf, t);
	} else {
		TRACE_TASK(t, "not suspended anymore? Ignored.\n");
	}


out:
	/* In any case, the CPU that this task was linked to
	 * needs to get a new assignment. */
	update_cpu_position_unlocked(sender_id);
	check_for_preemptions();

	TS_DSP_HANDLER_END;
	local_irq_restore(flags);
}


#define send_task_new(t)      send_to_master(on_task_new, t)
#define send_task_exit(t)     send_to_master(on_exit, t)
#define send_task_resumed(t)  send_to_master(on_resume, t)
#define send_job_completed(t) send_to_master(on_job_completion, t)
#define send_job_suspended(t) send_to_master(on_job_suspension, t)




/* **************** plugin callbacks ************** */


static noinline void gedf_release_jobs(rt_domain_t* rt, struct bheap* tasks)
{
	unsigned long flags;

	local_irq_save(flags);

	TRACE("Tasks released! Checking for preemptions.\n");

	__merge_ready(rt, tasks);
	check_for_preemptions();

	local_irq_restore(flags);
}

static long gedf_admit_task(struct task_struct* t)
{
	return 0;
}

/* assumes interrupts off */
static void gedf_task_exit(struct task_struct * t)
{
	cpu_entry_t* cpu_state;

	BUG_ON(!is_realtime(t));
	/* flag remains non-zero even if not linked */
	BUILD_BUG_ON(JOB_EXIT_OFFSET + NO_CPU <= 0);

	/* The order here is important. We first need to prevent master
	 * from linking us anywhere. THEN we lock_linked_on(), at which
	 * point we are sure that if linked_on == NO_CPU, we are
	 * not becoming linked afterwards. */
	tsk_rt(t)->job_exited = JOB_EXIT_OFFSET + NO_CPU;
	smp_wmb();

	/* let's see if this task is still in use somewhere */
	cpu_state = lock_linked_on(t);
	if (cpu_state) {
		TRACE_TASK(t, "exit-unlinked from P%d\n", cpu_state->cpu);
		/* ok, let's unlink this task */
		tsk_rt(t)->linked_on    = NO_CPU;
		cpu_state->linked       = NULL;

		/* We can't update the cpu_position here; need to let master
		 * do this. */
		tsk_rt(t)->job_exited = JOB_EXIT_OFFSET + cpu_state->cpu;
		unlock_cpu_state(cpu_state);
	} else {
		TRACE_TASK(t, "not linked on exit\n");
	}

	cpu_state = lock_scheduled_on(t);
	if (cpu_state) {
		TRACE_TASK(t, "still scheduled on P%d\n", cpu_state->cpu);
		/* is not going to be a real-time task any longer */
		cpu_state->scheduled = NULL;
		unlock_cpu_state(cpu_state);
	} else
		TRACE_TASK(t, "not scheduled on exit\n");

	/* let master finish the cleanup */
	send_task_exit(t);

	TRACE_TASK(t, "RIP\n");
}

/* called with interrupts on, no locks held */
static void gedf_task_cleanup(struct task_struct * t)
{
	BUG_ON(is_realtime(t));

	/* wait for master to process the exit */
	while (tsk_rt(t)->safe_to_exit != NUM_MAILBOXES) {
		TRACE_TASK(t, "waiting for a safe exit\n");
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(10);
	}

	TRACE_TASK(t, "Cleaned!\n");
}

/*	Prepare a task for running in RT mode
 */
static void gedf_task_new(struct task_struct * t, int on_rq, int is_scheduled)
{
	unsigned long 		flags;
	cpu_entry_t* 		entry;
	int cpu;

	local_irq_save(flags);

	cpu  = smp_processor_id();

	TRACE_TASK(t, "task new on_rq:%d sched:%d task_cpu:%d\n",
		on_rq, is_scheduled, task_cpu(t));

	/* setup job params */
	release_at(t, litmus_clock());

	tsk_rt(t)->linked_on = NO_CPU;
	if (is_scheduled && task_cpu(t) != gedf.release_master) {
		/* patch up CPU state */
		entry = cpu_state(task_cpu(t));

		raw_spin_lock(&entry->lock);
		entry->scheduled = t;
		tsk_rt(t)->scheduled_on =  entry->cpu;
		raw_spin_unlock(&entry->lock);

		/* Tell CPU running this task to stop scheduling unlinked
		 * real-time task. Master will link it somewhere
		 * once notified, if appropriate. */
		preempt(entry);
	} else {
		tsk_rt(t)->scheduled_on = NO_CPU;
	}

	if (is_running(t)) {
		/* Not suspended.
		 * Let master know it has something to do */
		send_task_new(t);
	} else
		tsk_rt(t)->job_suspended = 1;

	local_irq_restore(flags);
}

static void gedf_task_wake_up(struct task_struct *task)
{
	unsigned long flags;
	lt_t now;
	cpu_entry_t *cpu_state;

	local_irq_save(flags);

	now = litmus_clock();

	TRACE_TASK(task, "wake_up at %llu\n", now);

	cpu_state = lock_linked_on(task);
	if (cpu_state)
		/* came back before anyone noticed => nothing to do */
		raw_spin_unlock(&cpu_state->lock);
	else
		/* task became unlinked => has to go through master */
		send_task_resumed(task);

	local_irq_restore(flags);
}

static struct task_struct *clear_out_linked(cpu_entry_t *entry, struct task_struct *t)
{
	struct task_struct* next = NULL;

	if (entry->linked == t) {
		tsk_rt(t)->linked_on = NO_CPU;
		entry->linked = NULL;
	} else {
		next = entry->linked;
		if (next)
			tsk_rt(next)->scheduled_on = entry->cpu;
	}
	entry->scheduled = NULL;
	tsk_rt(t)->scheduled_on = NO_CPU;

	return next;
}

/* assumes entry is locked */
static struct task_struct * gedf_job_completion(cpu_entry_t *entry, struct task_struct *t)
{
	struct task_struct* next;

	int forced = budget_enforced(t) && budget_exhausted(t);
	TRACE_TASK(t, "completes.\n");

	next = clear_out_linked(entry, t);
	tsk_rt(t)->job_completed = 1;

	unlock_cpu_state(entry);

	send_job_completed(t);
	sched_trace_task_completion(t, forced);

	return next;
}

static struct task_struct * gedf_job_suspension(cpu_entry_t *entry, struct task_struct *t)
{
	struct task_struct* next;

	TRACE_TASK(t, "suspends.\n");

	next = clear_out_linked(entry, t);
	tsk_rt(t)->job_suspended = 1;

	unlock_cpu_state(entry);

	send_job_suspended(t);

	return next;
}

static struct task_struct * gedf_job_preemption(cpu_entry_t *entry, struct task_struct *t)
{
	struct task_struct* next;

	TRACE_TASK(t, "preempted.\n");

	next = entry->linked;
	if (next)
		tsk_rt(next)->scheduled_on = entry->cpu;
	if (t)
		tsk_rt(t)->scheduled_on = NO_CPU;

	entry->scheduled = NULL;
	unlock_cpu_state(entry);

	return next;
}

static struct task_struct* gedf_schedule(struct task_struct * prev)
{
	cpu_entry_t* entry = &__get_cpu_var(gedf_cpu_entries);
	int out_of_time, sleep, preempt, exists, blocks;
	struct task_struct* next = NULL;

	/* Bail out early if we are the release master.
	 * The release master never schedules any real-time tasks; */
	if (unlikely(gedf.release_master == entry->cpu)) {
		sched_state_task_picked();
		return NULL;
	}

	raw_spin_lock(&entry->lock);
#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "invoked gedf_schedule.\n");
#endif

	BUG_ON(entry->scheduled && !is_realtime(entry->scheduled));
	BUG_ON(entry->linked && !is_realtime(entry->linked));

	exists      = entry->scheduled != NULL;
	blocks      = exists && !is_running(entry->scheduled);
	out_of_time = exists && budget_enforced(entry->scheduled)
	                     && budget_exhausted(entry->scheduled);
	sleep	    = exists && is_completed(entry->scheduled);
	preempt     = entry->scheduled != entry->linked;

	if (exists) {
		TRACE_TASK(prev, "blocks:%d out_of_time:%d sleep:%d preempt:%d\n",
			   blocks, out_of_time, sleep, preempt);
	}


	sched_state_task_picked();

	if (blocks) {
		next = gedf_job_suspension(entry, entry->scheduled);
	} else if (sleep || out_of_time) {
		next = gedf_job_completion(entry, entry->scheduled);
	} else if (preempt) {
		next = gedf_job_preemption(entry, entry->scheduled);
	} else {
		next = entry->linked;
		unlock_cpu_state(entry);
	}
	/* NOTE: entry is unlocked at this point */

#ifdef WANT_ALL_SCHED_EVENTS
	if (next)
		TRACE_TASK(next, "scheduled at %llu\n", litmus_clock());
	else if (exists && !next)
		TRACE("becomes idle at %llu.\n", litmus_clock());
#endif

	return next;
}


/* _finish_switch - we just finished the switch away from prev
 */
static void gedf_finish_switch(struct task_struct *prev)
{
	cpu_entry_t* 	entry = &__get_cpu_var(gedf_cpu_entries);

	entry->scheduled = is_realtime(current) ? current : NULL;
#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "switched away from\n");
#endif
}


static long gedf_activate_plugin(void)
{
	int cpu;
	cpu_entry_t *entry;

#ifdef CONFIG_RELEASE_MASTER
	gedf.release_master = atomic_read(&release_master_cpu);
#endif

	/* the dedicated scheduler needs a release master */
	if (gedf.release_master == NO_CPU) {
		printk(KERN_ERR "Cannot use dedicated scheduling core "
		       "if none is configured. Set release master first.\n");
		return -EINVAL;
	}

	memset(&master_state, 0, sizeof(master_state));

	for_each_online_cpu(cpu) {
		entry = &per_cpu(gedf_cpu_entries, cpu);
		entry->linked    = NULL;
		entry->scheduled = NULL;
#ifdef CONFIG_RELEASE_MASTER
		if (cpu != gedf.release_master) {
#endif
			TRACE(__FILE__ ": Initializing CPU #%d.\n", cpu);
			master_state.cpu_online[cpu] = 1;
			update_cpu_position(entry);
#ifdef CONFIG_RELEASE_MASTER
		} else {
			TRACE(__FILE__ ": CPU %d is release master.\n", cpu);
		}
#endif
	}
	return 0;
}

/*	Plugin object	*/
static struct sched_plugin gedf_plugin __cacheline_aligned_in_smp = {
	.plugin_name		= "G-EDF-MP",
	.finish_switch		= gedf_finish_switch,
	.task_new		= gedf_task_new,
	.complete_job		= complete_job,
	.schedule		= gedf_schedule,
	.task_wake_up		= gedf_task_wake_up,
	.admit_task		= gedf_admit_task,
	.task_exit		= gedf_task_exit,
	.task_cleanup		= gedf_task_cleanup,
	.activate_plugin	= gedf_activate_plugin,
};


static int __init init_gedf_mp(void)
{
	int cpu;
	cpu_entry_t *entry;

	/* initialize CPU state */
	for (cpu = 0; cpu < NR_CPUS; cpu++)  {
		entry = &per_cpu(gedf_cpu_entries, cpu);
		gedf_cpus[cpu] = entry;
		entry->cpu 	 = cpu;
		raw_spin_lock_init(&entry->lock);
	}
	edf_domain_init(&gedf, NULL, gedf_release_jobs);
	return register_sched_plugin(&gedf_plugin);
}


module_init(init_gedf_mp);
