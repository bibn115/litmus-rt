						\
#include <linux/spinlock.h>
#include <linux/sched.h>

#include <litmus/trace.h>
#include <litmus/mailbox.h>

typedef struct {
	mailbox_callback_f callback;
	unsigned int sender_id; /* cpu id of the sender (IPI) */
	void *arg;
} __attribute__((aligned(64))) mailbox_data_t;

#define MAILBOX_BUFSIZE (2 << 19)

#define _CEIL(x, y) (((x) / (y)) + (((x) % (y)) != 0))

#define CPUS_PER_MAILBOX _CEIL(NR_CPUS, NUM_MAILBOXES)


static struct ft_buffer *mb_buf[NUM_MAILBOXES];

void init_mailbox_buffer(void)
{
	int i = 0;

	for (i = 0; i < NUM_MAILBOXES; i++) {
		mb_buf[i] = alloc_ft_buffer(MAILBOX_BUFSIZE, sizeof(mailbox_data_t));
		BUG_ON(!mb_buf[i]);
	}
}

static inline struct ft_buffer *choose_mailbox(unsigned int sender)
{
	/* floor => neighboring CPUs use the same mailbox => biased towards
	 * on-socket sharing (assuming physical neighbors are numbered
	 * consecutively, looking at actual topology could be added as option)
	 */
	return mb_buf[sender / CPUS_PER_MAILBOX];
}

static void __add_mailbox_call(
	struct ft_buffer *buf,
	mailbox_callback_f callback,
	unsigned int sender_id,
	void *arg)
{
	mailbox_data_t *data;

	if (unlikely(!ft_buffer_start_write(buf, (void **) &data)))
		BUG(); /* prototype: mailbox delivery may not fail */
	data->callback = callback;
	data->arg = arg;
	data->sender_id = sender_id;
	ft_buffer_finish_write(buf, data);
}

void add_mailbox_call(mailbox_callback_f callback, unsigned int sender_id, void *arg)
{
	struct ft_buffer *buf = choose_mailbox(sender_id);
	__add_mailbox_call(buf, callback, sender_id, arg);
}


void mailbox_broadcast(mailbox_callback_f callback, unsigned int sender_id, void *arg)
{
	int i;

	for (i = 0; i < NUM_MAILBOXES; i++)
		__add_mailbox_call(mb_buf[i], callback, sender_id, arg);
}

static volatile int already_in_mailbox_isr = 0;

void mailbox_arrived(void)
{
	int i, loop = 1;
	mailbox_data_t data;
	unsigned long flags;


	/* If we are taking a nested interrupt, quit immediately and
	 * let the outer IRQ handler finish the queue processing.
	 */
	if (already_in_mailbox_isr)
		return;
	else
		already_in_mailbox_isr = 1;

	local_irq_save(flags);

	while (loop) {
		loop = 0;

		/* Loop over mailboxes, picking only one message from each
		 * queue at a time to avoid starvation of higher-indexed
		 * queues.
		 */
		for (i = 0; i < NUM_MAILBOXES; i++)
			if (ft_buffer_read(mb_buf[i], &data)) {
				TS_CLIENT_REQUEST_LATENCY_END(data.sender_id);
				(data.callback)(data.sender_id, data.arg);

				/* Turn on interrupts briefly to
				 * avoid long irq-off section.
				 *
				 * Lockdep will warn that turning on IRQs in
				 * hard IRQ context is bad. The alternatives here
				 * would be to move this loop into a kthread,
				 * which adds context switch overhead on the
				 * critical path, or to simply hog the core
				 * running this loop constantly.
				 *
				 * Limited stack depth is only a problem if
				 * we permit arbitrary stack growth. However,
				 * checking already_in_mailbox_isr check ensures
				 * that we nest ISRs at most one level deep,
				 * which should not blow the stack.
				 * So we simply ignore the Linux warning and
				 * accept limited ISR recursion at this point.
				 */
				local_irq_enable();

				BUG_ON(irqs_disabled());

				local_irq_disable();
				loop = 1;
			}
	}

	already_in_mailbox_isr = 0;
	local_irq_restore(flags);
}
