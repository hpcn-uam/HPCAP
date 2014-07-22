#ifndef _HPCAP_IXGBE_H_
#define _HPCAP_IXGBE_H_

#include <linux/cdev.h>

#include "../../../include/hpcap.h"


#define packet_buf(ring,i) ( (u8 *) ( ring->window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK)*MAX_DESCR_SIZE ) )
#define packet_dma(ring,i) ( (u64) ( ring->dma_window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK) * MAX_DESCR_SIZE ) )

#define MAX_LISTENERS 4
#define RX_MODE_READ 1
#define RX_MODE_MMAP 2

#define distance( primero, segundo, size) ( (primero<=segundo) ? (segundo-primero) : ( (size-primero)+segundo) )
#define used_bytes(plist) ( distance( (plist)->bufferRdOffset, (plist)->bufferWrOffset, (plist)->bufsz ) )
//#define avail_bytes(plist) ( distance( (plist)->bufferWrOffset, (plist)->bufferRdOffset, (plist)->bufsz ) )
#define avail_bytes(plist) ( ((plist)->bufsz) - used_bytes(plist) )
struct hpcap_listener {
	pid_t pid;
	int kill;
	u64 bufferWrOffset; //written by 1 producer
	u64 bufferRdOffset; //written by consumer
	int first;
	u64 bufsz;
};

struct hpcap_buf {
	/* Identifiers */
	int adapter;
	int queue;
	/* Status flags */
	atomic_t opened;
	int max_opened;
	atomic_t mapped;
	int created;
	/* RX-buf */
	char * bufferCopia;
	u64 bufSize;
	u64 bufferFileSize;
	struct task_struct *hilo;
	struct hpcap_listener global;
	atomic_t num_list;
	struct hpcap_listener listeners[MAX_LISTENERS];
	/* Atomic variables avoiding multiple concurrect accesses to the same methods */
	atomic_t readCount;
	atomic_t mmapCount;
	/* MISC */
	char name[100];
	struct cdev chard; /* Char device structure */
	#ifdef REMOVE_DUPS
		struct hpcap_dup_info ** dupTable;
	#endif
};

int hpcap_mmap(struct file *, struct vm_area_struct *);
int hpcap_open(struct inode *, struct file *);
int hpcap_release(struct inode *, struct file *);
ssize_t hpcap_read(struct file *, char __user *, size_t, loff_t *);
long hpcap_ioctl(struct file *,unsigned int, unsigned long);


extern int hpcap_stop_poll_threads(struct ixgbe_adapter *);
extern int hpcap_launch_poll_threads(struct ixgbe_adapter *);
extern int hpcap_unregister_chardev(struct ixgbe_adapter *);
extern int hpcap_register_chardev(struct ixgbe_adapter *, u64, int);

#endif
