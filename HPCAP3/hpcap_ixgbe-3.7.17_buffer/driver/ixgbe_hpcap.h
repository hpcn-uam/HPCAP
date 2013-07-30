#ifndef _HPCAP_IXGBE_H_
#define _HPCAP_IXGBE_H_

#include <linux/cdev.h>

#include "../include/hpcap.h"


#define packet_buf(ring,i) ( (u8 *) ( ring->window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK)*MAX_PACKET_SIZE ) )
#define packet_dma(ring,i) ( (u64) ( ring->dma_window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK) * MAX_PACKET_SIZE ) )

#define MAX_LISTENERS 2
#define RX_MODE_READ 1
#define RX_MODE_MMAP 2

struct hpcap_listener {
	pid_t pid;
	int kill;
	atomic_t bufferCount; //written by both producer and consumer
	u32 bufferWrOffset; //written by 1 producer
	u32 bufferRdOffset; //written by consumer
	int first;
};

#ifdef REMOVE_DUPS
	struct hpcap_dup_info {
		u64 tstamp;
		u16 len;
		u8 data[DUP_CHECK_LEN];
	};
#endif

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
	u32 bufSize;
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
		struct hpcap_dup_info * dupTable;
	#endif
};

int hpcap_mmap(struct file *, struct vm_area_struct *);
int hpcap_open(struct inode *, struct file *);
int hpcap_release(struct inode *, struct file *);
ssize_t hpcap_read(struct file *, char __user *, size_t, loff_t *);
long hpcap_ioctl(struct file *,unsigned int, unsigned long);
int hpcap_rx(struct ixgbe_ring *, u32 , char *, u32 , int, u64 *, u16
#ifdef REMOVE_DUPS
	, struct hpcap_dup_info *
#endif
);


extern int hpcap_stop_poll_threads(struct ixgbe_adapter *);
extern int hpcap_launch_poll_threads(struct ixgbe_adapter *);
extern int hpcap_unregister_chardev(struct ixgbe_adapter *);
extern int hpcap_register_chardev(struct ixgbe_adapter *, u32, int);

#endif
