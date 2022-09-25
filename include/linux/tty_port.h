/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_PORT_H
#define _LINUX_TTY_PORT_H

#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/tty_buffer.h>
#include <linux/wait.h>

struct attribute_group;
struct tty_driver;
struct tty_port;
struct tty_struct;

/**
 * struct tty_port -- port level information
 *
 * @buf: buffer for this port, locked internally
 * @tty: back pointer to &struct tty_struct, valid only if the tty is open. Use
 *   tty_port_tty_get() to obtain it (and tty_kref_put() to release).
 * @itty: internal back pointer to &struct tty_struct. Avoid this. It should be
 *    eliminated in the long term.
 * @ops: tty port operations (like activate, shutdown), see &struct
 *   tty_port_operations
 * @client_ops: tty port client operations (like receive_buf, write_wakeup).
 *      By default, tty_port_default_client_ops is used.
 * @lock: lock protecting @tty
 * @blocked_open: # of procs waiting for open in tty_port_block_til_ready()
 * @count: usage count
 * @open_wait: open waiters queue (waiting e.g. for a carrier)
 * @delta_msr_wait: modem status change queue (waiting for MSR changes)
 * @flags: user TTY flags (%ASYNC_)
 * @iflags: internal flags (%TTY_PORT_)
 * @console: when set, the port is a console
 * @mutex: locking, for open, shutdown and other port operations
 * @buf_mutex: @xmit_buf alloc lock
 * @xmit_buf: optional xmit buffer used by some drivers
 * @xmit_fifo: optional xmit buffer used by some drivers
 * @close_delay: delay in jiffies to wait when closing the port
 * @closing_wait: delay in jiffies for output to be sent before closing
 * @drain_delay: set to zero if no pure time based drain is needed else set to
 *       size of fifo
 * @kref: references counter. Reaching zero calls @ops->destruct() if non-%NULL
 *    or frees the port otherwise.
 * @client_data: pointer to private data, for @client_ops
 *
 * Each device keeps its own port level information. &struct tty_port was
 * introduced as a common structure for such information. As every TTY device
 * shall have a backing tty_port structure, every driver can use these members.
 *
 * The tty port has a different lifetime to the tty so must be kept apart.
 * In addition be careful as tty -> port mappings are valid for the life
 * of the tty object but in many cases port -> tty mappings are valid only
 * until a hangup so don't use the wrong path.
 *
 * Tty port shall be initialized by tty_port_init() and shut down either by
 * tty_port_destroy() (refcounting not used), or tty_port_put() (refcounting).
 *
 * There is a lot of helpers around &struct tty_port too. To name the most
 * significant ones: tty_port_open(), tty_port_close() (or
 * tty_port_close_start() and tty_port_close_end() separately if need be), and
 * tty_port_hangup(). These call @ops->activate() and @ops->shutdown() as
 * needed.
 */
struct tty_port {
    struct tty_bufhead  buf;
    struct tty_struct   *tty;
    struct tty_struct   *itty;
    const struct tty_port_operations *ops;
    const struct tty_port_client_operations *client_ops;
    spinlock_t      lock;
    int         blocked_open;
    int         count;
    wait_queue_head_t   open_wait;
    wait_queue_head_t   delta_msr_wait;
    unsigned long       flags;
    unsigned long       iflags;
    unsigned char       console:1;
    struct mutex        mutex;
    struct mutex        buf_mutex;
    unsigned char       *xmit_buf;
    DECLARE_KFIFO_PTR(xmit_fifo, unsigned char);
    unsigned int        close_delay;
    unsigned int        closing_wait;
    int         drain_delay;
    struct kref     kref;
    void            *client_data;
};

struct tty_port_client_operations {
    int (*receive_buf)(struct tty_port *port, const unsigned char *,
                       const unsigned char *, size_t);
    void (*write_wakeup)(struct tty_port *port);
};

extern const struct tty_port_client_operations
tty_port_default_client_ops;

void tty_port_init(struct tty_port *port);

/**
 * struct tty_port_operations -- operations on tty_port
 * @carrier_raised: return 1 if the carrier is raised on @port
 * @dtr_rts: raise the DTR line if @raise is nonzero, otherwise lower DTR
 * @shutdown: called when the last close completes or a hangup finishes IFF the
 *  port was initialized. Do not use to free resources. Turn off the device
 *  only. Called under the port mutex to serialize against @activate and
 *  @shutdown.
 * @activate: called under the port mutex from tty_port_open(), serialized using
 *  the port mutex. Supposed to turn on the device.
 *
 *  FIXME: long term getting the tty argument *out* of this would be good
 *  for consoles.
 *
 * @destruct: called on the final put of a port. Free resources, possibly incl.
 *  the port itself.
 */
struct tty_port_operations {
    int (*carrier_raised)(struct tty_port *port);
    void (*dtr_rts)(struct tty_port *port, int raise);
    void (*shutdown)(struct tty_port *port);
    int (*activate)(struct tty_port *port, struct tty_struct *tty);
    void (*destruct)(struct tty_port *port);
};

void tty_port_destroy(struct tty_port *port);

void tty_port_link_device(struct tty_port *port,
                          struct tty_driver *driver,
                          unsigned index);

struct device *
tty_port_register_device_attr_serdev(struct tty_port *port,
                                     struct tty_driver *driver,
                                     unsigned index,
                                     struct device *device,
                                     void *drvdata,
                                     const struct attribute_group **attr_grp);

#endif /* _LINUX_TTY_PORT_H */