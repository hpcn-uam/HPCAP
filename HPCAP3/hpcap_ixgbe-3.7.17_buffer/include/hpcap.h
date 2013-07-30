#ifndef _HPCAP_H_
#define _HPCAP_H_


#define MAX_DEVICES	16
#define MAX_RINGS	64 //

#define minimo(a,b) ((a) < (b) ? (a) : (b))
#define maximo(a,b) ((a) > (b) ? (a) : (b))

#ifdef __KERNEL__

#include <asm/ioctl.h>

#define HPCAP_MAJOR 1010 //
#define HPCAP_NAME "hpcap"

#define MAX_BUFS 16


#define ns(a) ( (a*HZ) / 1000ul*1000ul*1000ul )

#else	/* __KERNEL__ */

#include <string.h>
#include <stdint.h>
#include <linux/types.h>
#include <sys/time.h>
#include <linux/ioctl.h>

#define __user
#define IFNAMSIZ 16
#define ETH_ALEN 6

#endif	/* __KERNEL__ */

#define MAX_PACKET_SIZE	2048

static inline void prefetcht0(void *p)
{
	asm volatile("prefetcht0 (%0)\n\t"
			: 
			: "r" (p)
		    );
}

static inline void prefetchnta(void *p)
{
	asm volatile("prefetchnta (%0)\n\t"
			: 
			: "r" (p)
		    );
}

/*********************************************************************************
 PARAMS
*********************************************************************************/
#define HPCAP_MAX_IFS 1ul
#define HPCAP_MAX_QUEUES 1ul


/************************************************
* JUMBO
*  uncomment this define to enable support
*  for jumboframes (may affect performance)
************************************************/
//#define JUMBO
#ifdef JUMBO
	#define MAX_JUMBO_SIZE 15872 // 15.5 KB
	#define MAX_DESCRIPTORS ( 1 + ((MAX_JUMBO_SIZE)/(MAX_PACKET_SIZE)) ) // max number of descriptors that a JUMBOFRAME can take
#else
	#define MAX_DESCRIPTORS 1
#endif

/************************************************
* PRINT_DEBUG
*  uncomment this define in order to enable some
*  printk that may help debugging at the cost of
*  performance
************************************************/
//#define PRINT_DEBUG

/************************************************
* BUF_DEBUG
*  uncomment this define in order to ease buffer
*  debugging (will set to 0 the buffer at the 
*  begining and in padding areas) at the cost
*  performance
************************************************/
//#define BUF_DEBUG

/************************************************
* DO_BUF_ALLOC
*  uncomment this define in order to make the
*  buffers to dynamically allocated
************************************************/
//#define DO_BUF_ALLOC
#ifdef DO_BUF_ALLOC
	#define HPCAP_BUF_SIZE (4ul*1024ul*1024ul)
#else
	#define HPCAP_BUF_SIZE ( 1024ul*1024ul*1024ul / (HPCAP_MAX_IFS*HPCAP_MAX_QUEUES) )
#endif

/************************************************
* DO_BUF_ALLOC
*  uncomment this define in order to make the
*  buffers to dynamically allocated
************************************************/
//#define REMOVE_DUPS
#ifdef REMOVE_DUPS
        #define DUP_CHECK_LEN 68
        #define DUP_WINDOW_SIZE 1024
        #define DUP_TIME_WINDOW (2ul*1000ul*1000ul*1000ul) //this value is specified in ns
#endif

#define HPCAP_IBS 1048576ul
#define HPCAP_OBS 1048576ul
#define HPCAP_BS 1048576ul
#define HPCAP_COUNT 2048ul //256ul //3072ul //768ul //3072=384*8 para ficheros de 3GB
#define HPCAP_FILESIZE (HPCAP_BS*HPCAP_COUNT) //tiene que ser multiplo de oblock=8M
/********************************************************************************/

#define HPCAP_OK 0
#define HPCAP_ERR -1

/***********************************************
 IOCTL commands
***********************************************/
#define HPCAP_IOC_MAGIC 69
#define HPCAP_IOC_POP  _IOW(HPCAP_IOC_MAGIC, 1, int)
#define HPCAP_IOC_WAIT _IOR(HPCAP_IOC_MAGIC, 2, int *)
#define HPCAP_IOC_POPWAIT _IOW(HPCAP_IOC_MAGIC, 3, int *)
#define HPCAP_IOC_KILLWAIT _IO(HPCAP_IOC_MAGIC, 4 )
#define HPCAP_IOC_BUFOFF _IOR(HPCAP_IOC_MAGIC, 5, int *)
#define HPCAP_IOC_WROFF _IOR(HPCAP_IOC_MAGIC, 6, int *)
/**********************************************/

#ifndef __KERNEL__

struct hpcap_handle {
	int fd;
	
	int adapter_idx;
	int queue_idx;

	int rdoff;
	int avail;

	u_char *buf;
	u_char *page;
	int bufoff;
	int size;
	int bufSize;
};

int hpcap_open(struct hpcap_handle *handle, int adapter_idx, int queue_idx);
void hpcap_close(struct hpcap_handle *handle);
int hpcap_wait(struct hpcap_handle *handle, int count);
int hpcap_ack(struct hpcap_handle *handle, int count);
int hpcap_map(struct hpcap_handle *handle);
int hpcap_unmap(struct hpcap_handle *handle);
int hpcap_ack_wait(struct hpcap_handle *handle, int ackcount, int waitcount);
int hpcap_ack_wait_timeout(struct hpcap_handle *handle, int ackcount, int waitcount,int timeout_ns);
int hpcap_wroff(struct hpcap_handle *handle);
int hpcap_ioc_killwait(struct hpcap_handle *handle);
#endif

#endif	/* _HPCAP_H_ */
