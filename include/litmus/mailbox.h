#ifndef LITMUS_MAILBOX_H
#define LITMUS_MAILBOX_H

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/percpu.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>

#include <litmus/ftdev.h>
#include <litmus/feather_buffer.h>

typedef void (*mailbox_callback_f)(unsigned int sender_id, void *arg);

#define _NUM_MAILBOXES 8
#define NUM_MAILBOXES (_NUM_MAILBOXES > NR_CPUS ? NR_CPUS : _NUM_MAILBOXES)

void init_mailbox_buffer(void);
void add_mailbox_call(mailbox_callback_f callback, unsigned int sender_id, void *arg);
void mailbox_arrived(void);

void mailbox_broadcast(mailbox_callback_f callback, unsigned int sender_id, void *arg);

#endif
