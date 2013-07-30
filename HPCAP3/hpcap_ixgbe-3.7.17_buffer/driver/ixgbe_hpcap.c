/*******************************************************************************

	PacketShader Kernel code for Intel 10 Gigabit PCI Express Linux driver
	Copyright(c) 1999 - 2011 Intel Corporation.
	
	Date:
		4-Jan-2011: updated to be ixgbe-3.7.17 equivalent

*******************************************************************************/

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/delay.h>
#ifdef HAVE_SCTP
	#include <linux/sctp.h>
#endif
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#ifdef NETIF_F_TSO
	#include <net/checksum.h>
	#ifdef NETIF_F_TSO6
		#include <net/ip6_checksum.h>
	#endif
#endif
#ifdef SIOCETHTOOL
	#include <linux/ethtool.h>
#endif
#include <linux/kthread.h>
#include <linux/cdev.h>


#include "../include/hpcap.h"
#include "ixgbe.h"

#ifdef DEV_HPCAP

#include "ixgbe_hpcap.h"



/* Las siguientes dos variables se rellenan en ixgbe_probe() */
int adapters_found;
struct ixgbe_adapter * adapters[HPCAP_MAX_IFS];

/*********************************************************************************
 MMAP-related functions
*********************************************************************************/

void hpcap_vma_open(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct hpcap_buf *bufp;

	if( filp )
	{
		bufp = filp->private_data;
		printk(KERN_NOTICE "HPCAP%dq%d: VMA open, virt %lx, phys %lx\n", bufp->adapter, bufp->queue, vma->vm_start, vma->vm_pgoff << PAGE_SHIFT);
	}
}
void hpcap_vma_close(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct hpcap_buf *bufp;
	unsigned long len;
	#ifndef DO_BUF_ALLOC
		unsigned long mapaddr, kaddr;
	#endif

	if( filp )
	{
		bufp = filp->private_data;
		printk(KERN_NOTICE "HPCAP%dq%d: VMA close\n", bufp->adapter, bufp->queue);
		
		#ifndef DO_BUF_ALLOC
			kaddr = (unsigned long) bufp->bufferCopia;
			kaddr = ( kaddr >> PAGE_SHIFT ) << PAGE_SHIFT;
			len = vma->vm_end - vma->vm_start;
			for( ; len > 0; kaddr += PAGE_SIZE, len -= PAGE_SIZE)
			{
				ClearPageReserved( vmalloc_to_page( (void *) kaddr) );
			}
		#endif
	}
}

static struct vm_operations_struct hpcap_vm_ops = {
	.open = hpcap_vma_open,
	.close = hpcap_vma_close,
};

int get_buf_offset(void *buf)
{
	unsigned long int phys, pfn;

	phys = __pa( buf );
	pfn = phys >> PAGE_SHIFT;

	return ( phys - (pfn<<PAGE_SHIFT) );
}

int hpcap_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct hpcap_buf *bufp = filp->private_data;
	unsigned long len;
	#ifdef DO_BUF_ALLOC
		unsigned long int phys, pfn;
	#else
		unsigned long mapaddr, kaddr;
                struct page *page;
		int npag, err;
	#endif

	if( !bufp )
	{
		printk("HPCAP: mmapping undefined char device\n");
		return -1;
	}

	/* Avoid two simultaneous mmap() calls from different threads/applications  */
	if( atomic_inc_return(&bufp->mmapCount) != 1 )
	{
		while( atomic_read(&bufp->mmapCount) != 1 );
	}
	//printk("HPCAP: mmaping hpcap%dq%d\n", bufp->adapter, bufp->queue);

	len = vma->vm_end - vma->vm_start;
	#ifdef DO_BUF_ALLOC
		phys = virt_to_phys((void *)bufp->bufferCopia);
		pfn = phys >> PAGE_SHIFT;
		if( remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot) )
		{
			printk(KERN_INFO "HPCAP: Error when trying to remap_pfn_range: size:%lu hpcap_buf_Size%lu\n", len, HPCAP_BUF_SIZE);
			return -EAGAIN;
		}
		printk( KERN_INFO "HPCAP: hpcap%dq%d's buffer mapped at 0x%08lx, sized %lu bytes [offset=%lu] [ALLOC]\n", bufp->adapter, bufp->queue, vma->vm_start, len, phys-(pfn<<PAGE_SHIFT) );
	#else
		kaddr = (unsigned long) bufp->bufferCopia;
		kaddr = ( kaddr >> PAGE_SHIFT ) << PAGE_SHIFT;
		npag = 0;
		for( mapaddr = vma->vm_start; mapaddr < vma->vm_end; mapaddr += PAGE_SIZE)
		{
			page = vmalloc_to_page( (void *) kaddr);
	                SetPageReserved(page);
	                err = vm_insert_page(vma, mapaddr, page);
	                if (err)
	                        break;
	                kaddr += PAGE_SIZE;
			npag++;
        	}
		if( err )
		{
			kaddr = (unsigned long) bufp->bufferCopia;
			kaddr = ( kaddr >> PAGE_SHIFT ) << PAGE_SHIFT;
			for( ; len > 0; kaddr += PAGE_SIZE, len -= PAGE_SIZE)
			{
	                        ClearPageReserved( vmalloc_to_page( (void *) kaddr) );
			}
		}
		printk( KERN_INFO "HPCAP: hpcap%dq%d's buffer mapped as %d different pages\n", bufp->adapter, bufp->queue, npag );
	#endif
	
	vma->vm_ops = &hpcap_vm_ops;
	hpcap_vma_open(vma);	
	atomic_dec(&bufp->mmapCount);
	
	return 0;
}
/*********************************************************************************
 MMAP-related functions (end)
*********************************************************************************/

/*
 * check_duplicate
 * return value: 1 if the packet is a duplicate, 0 otherwise
*/
#ifdef REMOVE_DUPS
int check_duplicate(u32 hw_hash, u16 len, u8 *pkt, struct timespec * tv, struct hpcap_dup_info * duptable)
{
	u32 pos = hw_hash % DUP_WINDOW_SIZE;
	struct hpcap_dup_info *p = &duptable[pos];
	u64 tstamp = (tv->tv_sec*1000ul*1000ul*1000ul) + tv->tv_nsec;
	int ret=0;
	u16 minim=min(len,(u16)DUP_CHECK_LEN);
	
	if( (p->tstamp!=0) && ( (tstamp-p->tstamp) <= DUP_TIME_WINDOW ) )
	{
		if( (p->len == len) && (memcmp( p->data, pkt, min(p->len, minim)) == 0) )
		{
			ret=1;
		}
	}
	p->tstamp = tstamp;
	p->len = len;
	memcpy( p->data, pkt, minim );
	return ret;
}
#endif

/*********************************************************************************
 RX-related functions
*********************************************************************************/
//#define BUF_ALIGN 4
#define RAW_HLEN (2*sizeof(u32)+2*sizeof(u16))
#define CALC_CAPLEN(cap,len) ( (cap==0) ? (len) : (minimo(cap,len)) )
//int paqn=0;
int hpcap_rx(struct ixgbe_ring *rx_ring, u32 limit, char *pkt_buf, u32 bufsize, int offs, u64 *fs, u16 caplen
#ifdef REMOVE_DUPS
	, struct hpcap_dup_info *duptable
#endif
)
{
	union ixgbe_adv_rx_desc *rx_desc;

	u16 len=64, capl, fraglen;
	u32 staterr;
	int qidx = rx_ring->next_to_clean;
	int next_qidx = 0;//rx_ring->next_to_clean;
	u32 cnt = 0;
	u8 *src;
	u32 total_rx_packets = 0, total_rx_bytes = 0;
	u64 aux=0;
	int offset=offs;
	u64 filesize = *fs;
	struct timespec tv;
	unsigned char tmp_h[RAW_HLEN];
	#ifdef RX_DEBUG
		int r_idx = rx_ring->reg_idx;
		struct ixgbe_adapter *adapter = rx_ring->adapter; //different from version 2.0.38
	#endif
	u8* jf_src[MAX_DESCRIPTORS];
	int jf=0, i=0;
	u16 padlen=0, padding=0;
	#ifdef REMOVE_DUPS
		u32 rss_hash=0;
		u32 total_dup_packets = 0;
	#endif
	

	if( limit <= 0 )
		return 0;

	src = packet_buf(rx_ring, qidx);

	prefetcht0(pkt_buf + (offset + 64 * 0) % HPCAP_BUF_SIZE );
	prefetcht0(pkt_buf + (offset + 64 * 1) % HPCAP_BUF_SIZE );
	prefetchnta(IXGBE_RX_DESC(rx_ring, qidx + 0));//different from version 2.0.38
	prefetchnta(IXGBE_RX_DESC(rx_ring, qidx + 1));//different from version 2.0.38
	
	#ifdef DO_PREFETCH
		prefetchnta(src + MAX_PACKET_SIZE * 0);
		prefetchnta(src + MAX_PACKET_SIZE * 1);
		prefetchnta(src + MAX_PACKET_SIZE * 2);
		prefetchnta(src + MAX_PACKET_SIZE * 3);
	#endif

	while (cnt < limit) 
	{
		len = 0;
		jf = 0;
		next_qidx = qidx;
		#ifdef JUMBO
		do
		{
		#endif
			rx_desc = IXGBE_RX_DESC(rx_ring, next_qidx);//different from version 2.0.38
			staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
			src = packet_buf(rx_ring, next_qidx);
	
			#ifdef DO_PREFETCH
				prefetchnta(src + MAX_PACKET_SIZE * 4);
				//if (len > 64)
				//	prefetchnta(src + MAX_PACKET_SIZE * 4 + 64);
			#endif

			prefetchnta(rx_desc + 2);
			prefetcht0(pkt_buf + offset + 64 * 2);

			next_qidx = (next_qidx + 1) % rx_ring->count;

			if( !(staterr & IXGBE_RXD_STAT_DD) )
				goto done;
			if( !pkt_buf )
				goto ignore;
	
			
			#ifdef RX_DEBUG
				if (unlikely(staterr & IXGBE_RXDADV_ERR_FRAME_ERR_MASK))
				{
					printk(KERN_INFO "found error frames\n");
					goto ignore;
				}
			#endif
			
			len += le16_to_cpu( rx_desc->wb.upper.length );
			jf_src[jf] = src;
			jf++;
		#ifdef JUMBO
		}while( !(staterr & IXGBE_RXD_STAT_EOP) );
		#ifdef RX_DEBUG
			if( jf > 1 )
				printk( KERN_INFO "[HPCAP] LAST descriptor - %d BYTES (%d fragments)\n", len, jf);
		#endif
		#endif
		
		#ifdef REMOVE_DUPS
			if ( duptable && check_duplicate(rss_hash, len, jf_src[1], &tv, duptable) )
			{
				total_dup_packets++;
				goto ignore;
			}
		#endif
		
		getnstimeofday(&tv);

		capl = CALC_CAPLEN(caplen, len);
		
		/* PADDING CHECK */
		if( unlikely( (filesize+capl+2*RAW_HLEN) > HPCAP_FILESIZE) )
		{
			//There is need for padding
			padding = 1;
			padlen = HPCAP_FILESIZE - filesize - RAW_HLEN; //padding header not included
		}

		// if there is no room for packet (or packet + padding if needed), finish rx
		if( ( (cnt+capl+RAW_HLEN) > limit ) ||
			( padding && ( (cnt+capl+padlen+2*RAW_HLEN) > limit ) ) )
		{
			// no room for this packet in buffer
			break;
		}
		

		/******************************************
		 Packet format in the RAW stream:
		   ... | Seconds 32b | Nanosec 32b | Caplen 16b | Length 16b | ... data ... |
		 NOTE:
			if( secs==0 && nsecs==0 ) ==> there is a padding block of 'length' bytes
		******************************************/
		
		
		if( unlikely( padding ) )
		{
			*((u32 *)tmp_h) = 0;
			*((u32 *)&tmp_h[sizeof(u32)]) = 0;
			*((u16 *)&tmp_h[2*sizeof(u32)]) = padlen;//for padding, caplen = len
			*((u16 *)&tmp_h[2*sizeof(u32)+sizeof(u16)]) = padlen;//for padding, caplen = len
			// write the padding header into the buffer
			if( (offset + RAW_HLEN) > HPCAP_BUF_SIZE )
			{
				aux=HPCAP_BUF_SIZE-offset;
				memcpy(pkt_buf+offset, tmp_h, aux);
				memcpy(pkt_buf, &tmp_h[aux], RAW_HLEN-aux);
			}
			else
				memcpy(pkt_buf+offset, tmp_h, RAW_HLEN);
			offset = (offset+RAW_HLEN) % HPCAP_BUF_SIZE;
			
			// write the padding into the buffer
			#ifdef BUF_DEBUG
			if( padlen > 0 )
			{
				if( (offset+padlen) > HPCAP_BUF_SIZE )
				{
					aux=HPCAP_BUF_SIZE-offset;
					memset(pkt_buf+offset, 0, aux);
					memset(pkt_buf, 0, padlen-aux );
				}
				else
					memset(pkt_buf+offset, 0, padlen);
			}
			#endif
			
			filesize = 0;
			offset = (offset+padlen) % HPCAP_BUF_SIZE;
			cnt += padlen+RAW_HLEN;
			padding = 0;
		}
		
		// write the packet header into the buffera
		*((u32 *)tmp_h) = tv.tv_sec;
		*((u32 *)&tmp_h[sizeof(u32)]) = tv.tv_nsec;
		*((u16 *)&tmp_h[2*sizeof(u32)]) = capl;
		*((u16 *)&tmp_h[2*sizeof(u32)+sizeof(u16)]) = len;
		if( (offset + RAW_HLEN) > HPCAP_BUF_SIZE )
		{
			aux = HPCAP_BUF_SIZE-offset;
			memcpy(pkt_buf+offset, tmp_h, aux);
			memcpy(pkt_buf, &tmp_h[aux], RAW_HLEN-aux);
		}
		else
			memcpy(pkt_buf+offset, tmp_h, RAW_HLEN);
		offset = (offset+RAW_HLEN) % HPCAP_BUF_SIZE;
		cnt += RAW_HLEN + capl;
		filesize += RAW_HLEN + capl;

		// write the packet into the buffer	
		#ifdef JUMBO
		for(i=0; (i<jf) && (capl >0);i++)
		{
		#else
			i=0;
		#endif
			src = jf_src[i];
			fraglen = minimo(capl, MAX_PACKET_SIZE);
			if( (offset+fraglen) > HPCAP_BUF_SIZE )
			{
				aux=HPCAP_BUF_SIZE-offset;
				memcpy(pkt_buf+offset, src, aux);
				memcpy(pkt_buf, &src[aux], fraglen-aux );
			}
			else
				memcpy(pkt_buf+offset, src, fraglen);
			offset = (offset+fraglen) % HPCAP_BUF_SIZE;
		#ifdef JUMBO
			capl -= fraglen;
		}
		#endif
		
		total_rx_bytes += len;
ignore:
		total_rx_packets++;
		rx_desc->read.pkt_addr = rx_desc->read.hdr_addr = cpu_to_le64(packet_dma(rx_ring, qidx));
		qidx = next_qidx;
	}

done:
	if( total_rx_packets > 0 )
	{
		rx_ring->queued = qidx;
		rx_ring->next_to_clean = qidx;
		rx_ring->next_to_use = (qidx == 0) ? (rx_ring->count - 1) : (qidx - 1);
		ixgbe_release_rx_desc(rx_ring, rx_ring->next_to_use);
		
		if( pkt_buf )
		{
			rx_ring->stats.packets += total_rx_packets;
			rx_ring->stats.bytes += total_rx_bytes;
			rx_ring->total_packets += total_rx_packets;
			rx_ring->total_bytes += total_rx_bytes;
		}
	}

	*fs = filesize;
	return cnt;
}

/*********************************************************************************
 RX-related functions (end)
*********************************************************************************/


/*********************************************************************************
 listerner-related functions
*********************************************************************************/
void hpcap_rst_listener(struct hpcap_listener *list)
{
	list->pid = 0;
	list->kill = 0;
	atomic_set( &list->bufferCount, 0);
	list->bufferWrOffset = 0;
	list->bufferRdOffset = 0;
	list->first = 1;
}

/*
 NOTE:
	if global == NULL => list is the global listener
*/
void hpcap_push_listener(struct hpcap_listener *list, int count, struct hpcap_listener *global, u32 bufsize)
{
	if( !global )
	{// global listener
		atomic_add(count,&list->bufferCount); // written by both producer and consumer
		list->bufferWrOffset = (list->bufferWrOffset + count) % bufsize; //written by producer
	}
	else if( list->pid != 0 )
	{
		if( list->first == 1 )
		{
			list->first = 0;
			atomic_set( &list->bufferCount, atomic_read(&global->bufferCount) );
			list->bufferWrOffset = global->bufferWrOffset;
			list->bufferRdOffset = global->bufferRdOffset;
			//printk("[Listener %d] inicializao a: count=%d, wrOff=%lu, rdOff=%lu\n", list->pid, atomic_read(&list->bufferCount), list->bufferWrOffset, list->bufferRdOffset);
		}
		else
		{
			atomic_add(count,&list->bufferCount); // written by both producer and consumer
			list->bufferWrOffset = (list->bufferWrOffset + count) % bufsize; //written by producer
		}
	}
}

void hpcap_pop_listener(struct hpcap_listener *list, int count, u32 bufsize )
{
	list->bufferRdOffset = (list->bufferRdOffset + count) % bufsize; // written by consumer
	atomic_sub(count, &list->bufferCount); // written by both producer and consumer
}

//distancia en un buffer circular de tamano HPCAP_BUF_SIZE
//#define distance( primero, segundo ) ( (primero<=segundo) ? (segundo-primero) : ( (HPCAP_BUF_SIZE-primero)+segundo) )
#define distance( primero, segundo, size) ( (primero<=segundo) ? (segundo-primero) : ( (size-primero)+segundo) )
int hpcap_pop_global_listener(struct hpcap_listener *global, struct hpcap_listener *listeners, u32 bufsize)
{
	int i;
	u32 minDist = bufsize+1;
	int dist;
	
	for(i=0; i<MAX_LISTENERS; i++)
	{
		if( ( listeners[i].pid != 0 ) && ( listeners[i].first != 1 ) )
		{
			dist = distance( global->bufferRdOffset,  listeners[i].bufferRdOffset, bufsize);
			if( dist < minDist )
			{
				minDist = dist;
			}
		}
	}
	if( (minDist <= HPCAP_BUF_SIZE) && (minDist > 0)  )
	{
		//printk("[POP global] %d bytes\n", minDist);
		hpcap_pop_listener( global, minDist, bufsize);
		return minDist;
	}
	return 0;
}

/*
 return value:
 	 0 : everything OK
	-1 : PID already registered
	-2 : no listeners available
*/
int hpcap_add_listener(struct hpcap_listener *list, pid_t pid)
{
	int i=0,ret=-2;
	int j=-1;

	for(i=0;i<MAX_LISTENERS;i++)
	{
		/* check if that PID has already been registered */
		if( list[i].pid == pid )
		{
			ret = -1;
			return -1;
		}
		else if( list[i].pid == 0 )
		{
			j=i;
		}
	}
	if(j != -1 )
	{
		//printk("Adding listener %d: PID=%d\n", j, pid);
		list[j].pid = pid;
		ret = 0;
	}
	return ret;
}

/*
 return value:
 	!NULL : everything OK
	 NULL : uregistered PID
*/
struct hpcap_listener * hpcap_get_listener(struct hpcap_listener *list, pid_t pid)
{
	int i=0;
	
	for(i=0;i<MAX_LISTENERS;i++)
	{
		if( list[i].pid == pid )
		{
			//printk("Se ha encontrado Listener con PID %d (%d)\n", pid, i);
			return &list[i];
		}
	}
	printk("No se ha encontrado Listener con PID %d\n", pid);
	return NULL;
}

/*
 return value:
 	 0 : everything OK
	-1 : uregistered PID
*/
int hpcap_del_listener(struct hpcap_listener *list, pid_t pid)
{
	struct hpcap_listener *aux;

	aux = hpcap_get_listener( list, pid);
	if(aux)
	{
		//printk("Deleting listener: PID=%d\n", pid);
		hpcap_rst_listener( aux );
		return 0;
	}
	return -1;
}

int hpcap_wait_listener(struct hpcap_listener *list, int desired)
{
	int avail=0;

	avail=atomic_read(&list->bufferCount); // bufferCount lo escriben productor y consumidor
	//while( avail == 0 )
	while( ( !list->kill ) && ( avail < desired ) )
	{
		schedule_timeout( ns(200000) );//100us
		avail=atomic_read(&list->bufferCount);
	}
	if( list->kill )
		return -1;
	return avail;
}
/*int hpcap_wait_listener_user(struct hpcap_listener *list, int *data)
{
	int avail=0;
	int desired=data[0];

	avail=atomic_read(&list->bufferCount); // bufferCount lo escriben productor y consumidor
	while( avail < desired )
	{
		schedule_timeout( ns(500000) );
		avail=atomic_read(&list->bufferCount);
	}
	data[0] = list->bufferRdOffset;
	data[1] = avail;
	//copy_to_user(data, rets, 2*sizeof(int) );

	return avail;
}
*/

#define SLEEP_QUANT 200
int hpcap_wait_listener_user(struct hpcap_listener *list, int *data)
{
	int avail=0;
	int desired=data[0];
	int timeout_ns=data[2];
	int num_loops=(timeout_ns/SLEEP_QUANT);//max_loops, if negative -> infinite loop
	

	//set_current_state(TASK_UNINTERRUPTIBLE);//new

	avail=atomic_read(&list->bufferCount); // bufferCount lo escriben productor y consumidor
	//printk("[HPCAP DEBUG PID:%u]antes bucle hpcap_wait_listener, timeout_ns:%d num_loops:%d avail:%d read:%u\n",current->pid,timeout_ns,num_loops,avail,list->bufferRdOffset);

//        printk("MAX:%u curr:%u\n",MAX_SCHEDULE_TIMEOUT,ns(1000000));
//        printk("MAX:%u curr:%u\n",MAX_SCHEDULE_TIMEOUT,ns(1000000));

	while( ( !list->kill ) && (avail < desired) && ( (num_loops>0) || (timeout_ns<0) ) )
	{
		//printk("[HPCAP DEBUG PID:%u]en el bucle hpcap_wait_listener, timeout_ns:%d num_loops:%d avail:%d read:%u\n",current->pid,timeout_ns,num_loops,avail,list->bufferRdOffset);
		schedule_timeout( ns(SLEEP_QUANT) );
		//ndelay( SLEEP_QUANT );
		avail=atomic_read(&list->bufferCount);
		num_loops--;
	}
	if( list->kill )
		return -1;
	data[0] = list->bufferRdOffset;
	data[1] = avail;
	//printk("despues bucle hpcap_wait_listener\n");

	//copy_to_user(data, rets, 2*sizeof(int) );

	//printk("[HPCAP DEBUG PID:%u]exiting hpcap_wait_listener_user\n",current->pid);
	return avail;
}
/*********************************************************************************
 listerner-related functions (end)
*********************************************************************************/


/*********************************************************************************
 basic chardev methods
*********************************************************************************/
int hpcap_open(struct inode *inode, struct file *filp)
{
	struct hpcap_buf *pbuf = container_of(inode->i_cdev, struct hpcap_buf, chard);
	int ret;

	if( !pbuf )
	{
		printk("HPCAP: trying to open undefined chardev\n");
		return -1;
	}
	
	filp->private_data = pbuf;
	#ifdef PRINT_DEBUG
		printk("[HPCAP] PID:%d- opening char device for hpcap%dq%d\n",current->pid,pbuf->adapter, pbuf->queue);
	#endif
	
	if( atomic_inc_return(&pbuf->opened) > pbuf->max_opened )
	{
		printk("HPCAP%d-%d: already opened %d times (max:%d), can't be re-opened\n", pbuf->adapter, pbuf->queue, atomic_read(&pbuf->opened), pbuf->max_opened);
		atomic_dec(&pbuf->opened);
		return -1;
	}
	ret = hpcap_add_listener(pbuf->listeners, current->pid);
	if( ret == 0 )
		atomic_inc( &pbuf->num_list );

	return 0;
}

int hpcap_release(struct inode *inode, struct file *filp)
{
	struct hpcap_buf *pbuf = filp->private_data;
	int ret;
	
	if( !pbuf )
	{
		printk("HPCAP: trying to close undefined chardev\n");
		return -1;
	}
	#ifdef PRINT_DEBUG
		printk("[HPCAP] closing char device for hpcap%dq%d\n", pbuf->adapter, pbuf->queue);
	#endif

	ret = hpcap_del_listener(pbuf->listeners, current->pid);
	if( ret == 0 )
		atomic_dec( &pbuf->num_list );


	atomic_dec(&pbuf->opened);
	filp->private_data = NULL;

	return 0;
}

ssize_t hpcap_read(struct file *filp, char __user *dstBuf, size_t count,loff_t *f_pos)
{
	ssize_t retval = 0;
	int avail, offset,aux;
	struct hpcap_buf *buf = filp->private_data;
	struct hpcap_listener *list = NULL;
	pid_t pid = current->pid;
	
	if( !buf )
	{
		printk("HPCAP: trying to read from undefined chardev\n");
		return -1;
	}

	/* Avoid two simultaneous read() calls from different threads/applications  */
	#if MAX_LISTENERS <= 1
		if( atomic_inc_return(&buf->readCount) != 1 )
		{
			while( atomic_read(&buf->readCount) != 1 );
		}
	#endif

	#if MAX_LISTENERS > 1
		list = hpcap_get_listener(buf->listeners, pid);
	#else
		list = &buf->global;
	#endif
	if( !list )
	{
		printk("HPCAP: device hpcap%dq%d, unregistered listener for PID=%d\n", buf->adapter, buf->queue, pid);
		return -1;
	}
	avail=hpcap_wait_listener( list, count );
	retval = minimo(count, avail);
	offset = list->bufferRdOffset;
	if( offset + retval > HPCAP_BUF_SIZE )
	{
		aux = HPCAP_BUF_SIZE-offset;
		copy_to_user(dstBuf, &buf->bufferCopia[offset], aux);
		copy_to_user(&dstBuf[aux], buf->bufferCopia, retval-aux);
	}
	else
	{
		copy_to_user(dstBuf, &buf->bufferCopia[offset], retval);
	}
	hpcap_pop_listener( list, retval, buf->bufSize);

	#if MAX_LISTENERS <= 1
		atomic_dec(&buf->readCount);
	#endif

	return retval;
}


long hpcap_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret=0, i=0;
	u32 acks;
	struct hpcap_buf *buf = filp->private_data;
	struct hpcap_listener *list = NULL;

	/*
	printk("hpcap_ioctl called() cmd=%u arg=%lu\n", cmd, arg);
	*/
	
	if( !buf )
	{
		printk("HPCAP: ioctl-ing undefined char device\n");
		return -1;
	}

	/* Avoid two simultaneous ioctl() calls from different threads/applications  */
	/*if( atomic_inc_return(&buf->ioctlCount) != 1 )
	{
		while( atomic_read(&buf->ioctlCount) != 1 );
	}*/

	switch (cmd)
	{
		case HPCAP_IOC_POPWAIT:
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			acks = ((int *)arg)[1];
			if( acks > 0)
			{
				hpcap_pop_listener( list, acks, buf->bufSize );
			}
			hpcap_wait_listener_user( list, (int *)arg );
			break;

		case HPCAP_IOC_POP:
			//printk("User POP: %d bytes\n", arg);
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			hpcap_pop_listener( list, arg, buf->bufSize);
			break;

		case HPCAP_IOC_WAIT:
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			hpcap_wait_listener_user( list, (int *)arg );
			//printk("User wait: avail=%d, off=%d\n", ( (int *) arg)[1], ( (int *) arg)[0] );
			break;

		case HPCAP_IOC_WROFF:
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			*((u32 *)arg) = list->bufferWrOffset;
			break;

		case HPCAP_IOC_KILLWAIT:
			printk("[KILL] hpcap%dq%d\n", buf->adapter, buf->queue);
			#if MAX_LISTENERS > 1
				for(i=0;i<MAX_LISTENERS;i++)
				{
					printk("Killing listener %d\n",i);
					buf->listeners[i].kill = 1;
				}
			#endif
			printk("Killing global listener");
			buf->global.kill = 1;
			break;

		case HPCAP_IOC_BUFOFF:
			( (int *) arg )[0] = get_buf_offset( buf->bufferCopia );
			( (int *) arg )[1] = buf->bufSize;
			break;
	
		default:
			ret = -ENOTTY;
	};

	//atomic_dec(&buf->ioctlCount);
	//printk("hpcap_ioctl returns %d\n", ret);
	return ret;
}

/*********************************************************************************
 basic chardev methods (end)
*********************************************************************************/



/*********************************************************************************
 POLLING threads
*********************************************************************************/
int hpcap_poll(void *arg)
{
	struct ixgbe_ring *rx_ring = arg;
	struct hpcap_buf *buf = rx_ring->buf;
	int retval=0;
	u32 avail=0;
	u16 caplen = adapters[buf->adapter]->caplen;
	u8 *rxbuf=NULL;
	#if MAX_LISTENERS > 1
		int i;
	#endif

	//set_current_state(TASK_UNINTERRUPTIBLE);//new
	printk("HPCAP: Hello, I'm kernel thread %sq%d\n", rx_ring->adapter->netdev->name, buf->queue);
    	while( !kthread_should_stop() )
	{
		if( atomic_read(&buf->num_list) <= 0 )
			rxbuf=NULL;
		else
			rxbuf=buf->bufferCopia;
		
		avail = HPCAP_BUF_SIZE-atomic_read(&buf->global.bufferCount);
		retval = hpcap_rx(rx_ring, avail, rxbuf, buf->bufSize, buf->global.bufferWrOffset, &buf->bufferFileSize, caplen);
		if( retval > avail )
		{
			printk("Leyendo mas de lo que se puede!!!!! (leidos:%d, avail=%u, BUF=%lu, bufcount=%d)\n", retval, avail, HPCAP_BUF_SIZE, atomic_read(&buf->global.bufferCount) );
		}
		if( retval == 0 )
		{
			#if MAX_LISTENERS > 1
				for(i=0;i<MAX_LISTENERS;i++)
				{
					if( ( buf->listeners[i].pid != 0 ) && ( buf->listeners[i].first == 1 ) )
						hpcap_push_listener( &buf->listeners[i], 0, &buf->global, buf->bufSize);//synchronize with global listener
				}
			#endif
			schedule_timeout( ns(200) );//100 ns
		}
		else
		{
			/* When new data is received, ALL listeners must be updated */
			hpcap_push_listener( &buf->global, retval, NULL, buf->bufSize);
			#if MAX_LISTENERS > 1
				for(i=0;i<MAX_LISTENERS;i++)
				{
					hpcap_push_listener( &buf->listeners[i], retval, &buf->global, buf->bufSize);
				}
			#endif
		}
		#if MAX_LISTENERS > 1
			/* Update RdPointer according to the slowest listener */
			retval=hpcap_pop_global_listener( &buf->global, buf->listeners, buf->bufSize);
		#endif
	}
	printk("HPCAP: Bye, kernel thread (%sq%d)\n", rx_ring->adapter->netdev->name, buf->queue);

	return 0;
}

int hpcap_stop_poll_threads(struct ixgbe_adapter *adapter)
{
	int i;
	
	for(i=0;i<adapter->num_rx_queues;i++)
	{
		struct hpcap_buf  *bufp=adapter->rx_ring[i]->buf;
		if(bufp->created==1)
		{
			kthread_stop(bufp->hilo);
			bufp->created=0;
			printk("HPCAP: kthread hpcap%dq%d successfully stopped\n", adapter->bd_number, i);
		}
	}
	return 0;
}

int hpcap_launch_poll_threads(struct ixgbe_adapter *adapter)
{
	int i;
	
	for(i=0;i<adapter->num_rx_queues;i++)
	{
		struct hpcap_buf  *bufp=adapter->rx_ring[i]->buf;
		if( bufp->created == 0 )
		{
			#ifdef BUF_DEBUG
				memset( bufp->bufferCopia, 0, HPCAP_BUF_SIZE);
			#endif
			bufp->hilo = kthread_create( hpcap_poll, (void *)adapter->rx_ring[i], bufp->name);
			kthread_bind(bufp->hilo, adapter->core + 2*i);
			wake_up_process(bufp->hilo);
			bufp->created=1;
		}
	}
	return 0;
}

/*********************************************************************************
 POLLING threads (end)
*********************************************************************************/


/*********************************************************************************
 REGISTER/UNREGISTER chardevs
*********************************************************************************/


static struct file_operations hpcap_fops = {
	.open = hpcap_open,
	.read = hpcap_read,
	.release = hpcap_release,
	.mmap = hpcap_mmap,
	.unlocked_ioctl = hpcap_ioctl,
};

int hpcap_buf_clear(struct hpcap_buf *bufp)
{
	if( ( bufp->created == 1 ) || ( atomic_read(&bufp->mapped) == 1 ) || ( atomic_read(&bufp->opened) != 0 ) )
	{
		printk("[HPCAP] Error: trying to unregister cdev in use (if%d,q%d)  (created=%d, mapped=%d, opened=%d)\n", bufp->adapter, bufp->queue, bufp->created, atomic_read(&bufp->mapped), atomic_read(&bufp->opened) );
		#if 0
		printk("Lets's wait\n");
		//while( ( bufp->created == 1 ) || ( atomic_read(&bufp->mapped) == 1 ) || ( atomic_read(&bufp->opened) != 0 ) );
		hpcap_stop_poll_threads( adapters[bufp->adapter] );
		printk("done\n");
		#endif
	}
	#ifdef DO_BUF_ALLOC
		if( bufp->bufferCopia )
		{
			kfree( bufp->bufferCopia );
			//vfree( bufp->bufferCopia );
		}
	#endif
	bufp->bufferCopia = NULL;
	return 0;
}

#ifndef DO_BUF_ALLOC
	//char auxBufs[HPCAP_MAX_IFS][HPCAP_MAX_QUEUES][HPCAP_BUF_SIZE];
	char auxBufs[HPCAP_BUF_SIZE];
#endif
int hpcap_buf_init(struct hpcap_buf *bufp, struct ixgbe_adapter *adapter, int queue,struct cdev *chard, u32 size, int ifnum)
{
	int i;
	
	hpcap_rst_listener( &bufp->global );
	for(i=0;i<MAX_LISTENERS;i++)
	{
		hpcap_rst_listener( &bufp->listeners[i] );
	}
	
	bufp->bufferFileSize = 0;
	atomic_set( &bufp->num_list, 0);
	atomic_set( &bufp->readCount, 0 );
	atomic_set( &bufp->mmapCount, 0 );
	bufp->hilo = NULL;
	bufp->adapter = adapter->bd_number;
	bufp->queue = queue;
	bufp->created = 0;
	atomic_set( &bufp->mapped, 0);
	atomic_set( &bufp->opened, 0 );
	bufp->max_opened = MAX_LISTENERS+1;
	sprintf(bufp->name, "hpcapPoll%dq%d", adapter->bd_number, queue);
	
	#ifdef DO_BUF_ALLOC
		bufp->bufferCopia = kmalloc_node( sizeof(char)*HPCAP_BUF_SIZE, GFP_KERNEL, adapter->numa_node );
		bufp->bufSize = HPCAP_BUF_SIZE;
	#else
		bufp->bufSize = size/adapter->num_rx_queues;
		bufp->bufferCopia = &auxBufs[ size*ifnum + bufp->queue*bufp->bufSize ];
		printk("[hpcap%dq%d] offset:%u, size:%u, total:%lu\n", bufp->adapter, bufp->queue, size*ifnum + bufp->queue*bufp->bufSize, bufp->bufSize, HPCAP_BUF_SIZE );
	#endif
	if( !(bufp->bufferCopia) )
	{
		printk("Error when allocating bufferCopia-%d.%d [size=%lu]\n", adapter->bd_number, queue, HPCAP_BUF_SIZE );
		return -1;
	}
	printk("Success when allocating bufferCopia-%d.%d [size=%lu]\n", adapter->bd_number, queue, HPCAP_BUF_SIZE );
	printk( KERN_INFO "\tvirt_addr_valid(): %d\n", virt_addr_valid(bufp->bufferCopia) );


	#ifdef REMOVE_DUPS
		if( adapter->dup_mode == 0 )
		{
			bufp->dupTable = NULL;
		}
		else
		{
			int i;
			bufp->dupTable = kmalloc_node( sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE, GFP_KERNEL, adapter->numa_node );
			if( !(bufp->dupTable) )
			{
				printk("Error when allocating dupTable for hpcap%dq%d\n", adapter->bd_number, queue);
			}
			else
				printk("Success allocating %d Bytes for Dup buffer in hpcap%dq%d\n",  sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE,adapter->bd_number, queue);
			for( i=0; i<DUP_WINDOW_SIZE; i++ )
			{
				bufp->dupTable[i].tstamp = 0;
			}
		}
	#endif

	return 0;
}


int hpcap_unregister_chardev(struct ixgbe_adapter *adapter)
{
	int i,major;
	struct hpcap_buf *bufp;
	dev_t dev;

	major = HPCAP_MAJOR+adapter->bd_number;

	for(i=0;i<adapter->num_rx_queues;i++)
	{
		bufp = adapter->rx_ring[i]->buf;
		if( bufp )
		{
			if( hpcap_buf_clear(bufp) != 0 )
			{
				continue;
			}
			cdev_del(&bufp->chard);
			dev = MKDEV(major, i);
			unregister_chrdev_region(dev, 1);
			kfree(bufp);
			adapter->rx_ring[i]->buf = NULL;
		}
	}
	return 0;	
}


int hpcap_register_chardev(struct ixgbe_adapter *adapter, u32 size, int ifnum)
{
	int i,ret=0,major=0;
	dev_t dev = 0;
	struct hpcap_buf *bufp=NULL;

	major = HPCAP_MAJOR+adapter->bd_number;
	for(i=0;i<adapter->num_rx_queues;i++)
	{
		/*registramos un dispositivo por cola*/
		bufp = kmalloc( sizeof(struct hpcap_buf), GFP_KERNEL );
		if( !bufp )
		{
			printk("HPCAP: Error allocating hpcap_buf struct for hpcap%dq%d\n", adapter->bd_number, i );
			ret = -1;
			break;
		}
		adapter->rx_ring[i]->buf = bufp;

		dev = MKDEV(major, i);
		ret = register_chrdev_region(dev, 1, HPCAP_NAME) ;
		if( ret != 0 )
		{
			printk("HPCAP: Error allocating (major,minor) region for hpcap%dq%d\n", adapter->bd_number, i);
			ret = -1;
			break;
		}

		hpcap_buf_init(bufp, adapter, i, &bufp->chard, size, ifnum);
		cdev_init(&bufp->chard, &hpcap_fops);
		bufp->chard.owner=THIS_MODULE;
		bufp->chard.ops = &hpcap_fops;
		ret = cdev_add (&bufp->chard, dev/*primer num. al que el dispositivo responde*/,1);
		if( ret < 0 )
		{
			printk(KERN_ERR "HPCAP: Error %d adding char device \"hpcap%dq%d\"", ret, adapter->bd_number, i);
			ret = -1;
			break;
		}
		bufp=NULL;
	}

	if( ret == -1 )
		hpcap_unregister_chardev(adapter);
	return ret;
}


/*********************************************************************************
 REGISTER/UNREGISTER chardevs (end)
*********************************************************************************/

#endif /* DEV_HPCAP */
