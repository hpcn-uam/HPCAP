/*******************************************************************************

	HPCAP Kernel code for Intel 10 Gigabit PCI Express Linux driver
	
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


#include "../../include/hpcap.h"
#if defined(HPCAP_IXGBE)
	#include "../hpcap_ixgbe-3.7.17_buffer/driver/ixgbe.h"
#elif defined(HPCAP_IXGBEVF)
	#include "../hpcap_ixgbevf-2.14.2/driver/ixgbevf.h"
#endif

#ifdef DEV_HPCAP

#include "driver_hpcap.h"



/* Las siguientes dos variables se rellenan en ixgbe[vf]_probe() */
int adapters_found;
HW_ADAPTER * adapters[HPCAP_MAX_NIC];

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
		unsigned long kaddr;
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
		int npag, err=0;
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
int check_duplicate(u32 hw_hash, u16 len, u8 *pkt, struct timespec * tv, struct hpcap_dup_info ** duptable)
{
	u32 pos = hw_hash % DUP_WINDOW_SIZE;
	struct hpcap_dup_info *p = NULL;
	u64 tstamp = (tv->tv_sec*1000ul*1000ul*1000ul) + tv->tv_nsec;
	int ret=0,i=0;
	u16 minim=min(len,(u16)DUP_CHECK_LEN);
	u64 dif=0,dif2=0;
	u64 k=0;

	for(i=0;i<DUP_WINDOW_LEVELS;i++)
	{
		p = &((duptable[i])[pos]);

		if( p->tstamp != 0 )
		{
			dif2 =  tstamp-p->tstamp;
			if( dif2 <= DUP_TIME_WINDOW )
			{
				if( (len == p->len) && (memcmp( p->data, pkt, minim) == 0) )
				{
					ret=1;
				}
			}
			if( dif2 > dif )
			{
				dif=dif2;
				k=i;
			}
		}
		else
		{
			dif=tstamp;
			k=i;
		}		
	}
	//printk("hw_hash: %u, pos: %d\n", hw_hash, pos);
	
	(duptable[k])[pos].tstamp = tstamp;
	(duptable[k])[pos].len = len;
	memcpy( (duptable[k])[pos].data, pkt, minim );
	
	return ret;
}
#endif

/*********************************************************************************
 RX-related functions
*********************************************************************************/
//#define BUF_ALIGN 4
#define CALC_CAPLEN(cap,len) ( (cap==0) ? (len) : (minimo(cap,len)) )
//int paqn=0;
u64 hpcap_rx(HW_RING *rx_ring, u64 limit, char *pkt_buf, u64 bufsize, int offs, u64 *fs, u16 caplen
#ifdef REMOVE_DUPS
	, struct hpcap_dup_info ** duptable
#endif
)
{
	HW_RX_DESCR *rx_desc;

	u16 len=64, capl, fraglen;
	u32 staterr;
	int qidx = rx_ring->next_to_clean;
	int next_qidx = 0;//rx_ring->next_to_clean;
	u64 cnt = 0;
	u8 *src;
	u32 total_rx_packets = 0, total_rx_bytes = 0;
	u64 aux=0;
	int offset=offs;
	u64 filesize = *fs;
	struct timespec tv;
	unsigned char tmp_h[RAW_HLEN];
	#ifdef RX_DEBUG
		int r_idx = rx_ring->reg_idx;
		HW_ADAPTER *adapter = rx_ring->adapter; //different from version 2.0.38
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

	if( likely(pkt_buf) )
	{
		prefetcht0(pkt_buf + (offset + 64 * 0) % bufsize );
		prefetcht0(pkt_buf + (offset + 64 * 1) % bufsize );
	}
	prefetchnta(HW_RX_DESC(rx_ring, qidx + 0));//different from version 2.0.38
	prefetchnta(HW_RX_DESC(rx_ring, qidx + 1));//different from version 2.0.38
	
	#ifdef DO_PREFETCH
		prefetchnta(src + MAX_DESCR_SIZE * 0);
		prefetchnta(src + MAX_DESCR_SIZE * 1);
		prefetchnta(src + MAX_DESCR_SIZE * 2);
		prefetchnta(src + MAX_DESCR_SIZE * 3);
	#endif

	while( cnt < limit )
	{
		len = 0;
		jf = 0;
		next_qidx = qidx;
		#ifdef JUMBO
		do
		{
		#endif
			rx_desc = HW_RX_DESC(rx_ring, next_qidx);//different from version 2.0.38
			staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
			src = packet_buf(rx_ring, next_qidx);

	
			#ifdef DO_PREFETCH
				prefetchnta(src + MAX_DESCR_SIZE * 4);
				//if (len > 64)
				//	prefetchnta(src + MAX_DESCR_SIZE * 4 + 64);
			#endif

			prefetchnta(rx_desc + 2);
			if( likely(pkt_buf) )
				prefetcht0(pkt_buf + offset + 64 * 2);

			next_qidx = (next_qidx + 1) % rx_ring->count;

			if( unlikely( !(staterr & IXGBE_RXD_STAT_DD) ) )
				goto done;
			if( unlikely( !pkt_buf ) )
				goto ignore;
			
			#ifdef RX_DEBUG
			if( !(staterr & IXGBE_RXD_STAT_EOP) )
			{
				printk( KERN_INFO "[HPCAP] a jumboframe appeared (len: %d)\n", le16_to_cpu( rx_desc->wb.upper.length ));
			}
			u16 hdrinfo = le16_to_cpu(rx_desc->wb.lower.lo_word.hs_rss.hdr_info);
			if( !(staterr & IXGBE_RXD_STAT_EOP) )
			{
				printk( KERN_INFO "[HPCAP] a jumboframe appeared (len: %d)\n", le16_to_cpu( rx_desc->wb.upper.length ));
			}
			#endif
			
			#ifdef REMOVE_DUPS
			if( jf == 0 )
				rss_hash = le32_to_cpu(rx_desc->wb.lower.hi_dword.rss);
			#endif
	
			
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
		
		getnstimeofday(&tv);

		#ifdef REMOVE_DUPS
			if ( duptable && check_duplicate(rss_hash, len, jf_src[0], &tv, duptable) )
			{
				total_dup_packets++;
				goto ignore;
			}
		#endif
		
		capl = CALC_CAPLEN(caplen, len);

		/* PADDING CHECK */
		if( unlikely( (filesize+capl+2*RAW_HLEN) > HPCAP_FILESIZE) )
		{
			//There is need for padding
			padding = 1;
			padlen = HPCAP_FILESIZE - filesize - RAW_HLEN; //padding header not included
		}

		// if there is no room for packet (or packet + padding if needed), finish rx
		if( unlikely( ( (cnt+capl+RAW_HLEN) > limit ) || ( padding && ( (cnt+capl+padlen+2*RAW_HLEN) > limit ) ) ) )
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
			if( (offset + RAW_HLEN) > bufsize )
			{
				aux=bufsize-offset;
				memcpy(pkt_buf+offset, tmp_h, aux);
				memcpy(pkt_buf, &tmp_h[aux], RAW_HLEN-aux);
			}
			else
				memcpy(pkt_buf+offset, tmp_h, RAW_HLEN);
			offset = (offset+RAW_HLEN) % bufsize;
			
			// write the padding into the buffer
			#ifdef BUF_DEBUG
			if( padlen > 0 )
			{
				if( (offset+padlen) > bufsize )
				{
					aux=bufsize-offset;
					memset(pkt_buf+offset, 0, aux);
					memset(pkt_buf, 0, padlen-aux );
				}
				else
					memset(pkt_buf+offset, 0, padlen);
			}
			#endif
			
			filesize = 0;
			offset = (offset+padlen) % bufsize;
			cnt += padlen+RAW_HLEN;
			padding = 0;
		}
		
		// write the packet header into the buffera
		*((u32 *)tmp_h) = tv.tv_sec;
		*((u32 *)&tmp_h[sizeof(u32)]) = tv.tv_nsec;
		*((u16 *)&tmp_h[2*sizeof(u32)]) = capl;
		*((u16 *)&tmp_h[2*sizeof(u32)+sizeof(u16)]) = len;
		if( (offset + RAW_HLEN) > bufsize )
		{
			aux = bufsize-offset;
			memcpy(pkt_buf+offset, tmp_h, aux);
			memcpy(pkt_buf, &tmp_h[aux], RAW_HLEN-aux);
		}
		else
			memcpy(pkt_buf+offset, tmp_h, RAW_HLEN);
		offset = (offset+RAW_HLEN) % bufsize;
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
			fraglen = minimo(capl, MAX_DESCR_SIZE);
			if( (offset+fraglen) > bufsize )
			{
				aux=bufsize-offset;
				memcpy(pkt_buf+offset, src, aux);
				memcpy(pkt_buf, &src[aux], fraglen-aux );
			}
			else
				memcpy(pkt_buf+offset, src, fraglen);
			offset = (offset+fraglen) % bufsize;
		#ifdef JUMBO
			capl -= fraglen;
		}
		#endif
		
		total_rx_bytes += len;
		total_rx_packets++;
ignore:
		rx_desc->read.pkt_addr = rx_desc->read.hdr_addr = cpu_to_le64(packet_dma(rx_ring, qidx));
		qidx = next_qidx;
	}

done:
	#ifdef REMOVE_DUPS
	if( likely( (total_rx_packets>0) || (total_dup_packets>0) || !pkt_buf ) )
	#else
	if( likely( (total_rx_packets>0) || !pkt_buf  ) )
	#endif
	{
		rx_ring->queued = qidx;
		rx_ring->next_to_clean = qidx;
		rx_ring->next_to_use = (qidx == 0) ? (rx_ring->count - 1) : (qidx - 1);
		HW_RELEASE_RX_DESCR(rx_ring, rx_ring->next_to_use);
		
		if( likely( pkt_buf ) )
		{
			rx_ring->stats.packets += total_rx_packets;
			#ifdef REMOVE_DUPS
			rx_ring->stats.bytes += total_dup_packets;//total_rx_bytes;
			#else
			rx_ring->stats.bytes += total_rx_bytes;
			#endif
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
	list->bufferWrOffset = 0;
	list->bufferRdOffset = 0;
	list->first = 1;
}

/*
 NOTE:
	if global == NULL => list is the global listener
*/
void hpcap_push_listener(struct hpcap_listener *list, u64 count, struct hpcap_listener *global, u64 bufsize)
{
	if( avail_bytes(list) < count )
	{
		printk("[PUSH] Error => RD:%llu WR:%llu avail:%llu count:%llu\n", list->bufferRdOffset, list->bufferWrOffset, avail_bytes(list), count);
	}
	if( !global )
	{//then "list" is the global listener
		list->bufferWrOffset = (list->bufferWrOffset + count) % bufsize; //written by producer
	}
	else if( list->pid != 0 )
	{
		if( list->first == 1 )
		{
			list->first = 0;
			list->bufferWrOffset = global->bufferWrOffset;
			list->bufferRdOffset = global->bufferRdOffset;
			return;
		}
		else
		{
			list->bufferWrOffset = (list->bufferWrOffset + count) % bufsize; //written by producer
		}
	}
}

void hpcap_pop_listener(struct hpcap_listener *list, u64 count, u64 bufsize )
{
	if( used_bytes(list) < count )
	{
		printk("[POP] Error => RD:%llu WR:%llu used:%llu count:%llu\n", list->bufferRdOffset, list->bufferWrOffset, used_bytes(list), count);
	}
	list->bufferRdOffset = (list->bufferRdOffset + count) % bufsize; // written by consumer
}

int hpcap_pop_global_listener(struct hpcap_listener *global, struct hpcap_listener *listeners, u64 bufsize)
{
	int i;
	u64 minDist = bufsize+1;
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
	if( (minDist <= bufsize) && (minDist > 0)  )
	{
		//printk("[POP global] %d bytes\n", minDist);
		if( used_bytes(global) < minDist )
		{
			printk("[POPg] Error => RD:%llu WR:%llu used:%llu count:%llu\n", global->bufferRdOffset, global->bufferWrOffset, used_bytes(global), minDist);
		}
		global->bufferRdOffset = (global->bufferRdOffset + minDist) % bufsize;
		//hpcap_pop_listener( global, minDist, bufsize);
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

	avail = used_bytes(list);
	//while( avail == 0 )
	while( ( !list->kill ) && ( avail < desired ) )
	{
		schedule_timeout( ns(100000) );//200us
		avail = used_bytes(list);
	}
	if( list->kill )
		return -1;
	return avail;
}

#define SLEEP_QUANT 200
u64 hpcap_wait_listener_user(struct hpcap_listener *list, u64 *data)
{
	u64 avail=0;
	u64 desired=data[0];
	u64 timeout_ns=data[2];
	int num_loops=(timeout_ns/SLEEP_QUANT);//max_loops, if negative -> infinite loop
	

	//set_current_state(TASK_UNINTERRUPTIBLE);//new

	avail = used_bytes(list);
	while( ( !list->kill ) && (avail < desired) && ( (num_loops>0) || (timeout_ns<0) ) )
	{
		schedule_timeout( ns(SLEEP_QUANT) );
		//ndelay( SLEEP_QUANT );
		avail = used_bytes(list);
		num_loops--;
	}
	if( list->kill )
		return -1;
	data[0] = list->bufferRdOffset;
	data[1] = avail;

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
		printk("[HPCAP] PID:%d- opening char device for hpcap%dq%d (%d listeners)\n",current->pid,pbuf->adapter, pbuf->queue, atomic_read(&pbuf->num_list) );
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
		printk("[HPCAP] closing char device for hpcap%dq%d (%d listeners)\n", pbuf->adapter, pbuf->queue, atomic_read(&pbuf->num_list));
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
	u64 retval = 0;
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
	if( offset + retval > buf->bufSize )
	{
		aux = buf->bufSize-offset;
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

	return ((ssize_t) retval);
}


long hpcap_ioctl(struct file *filp, unsigned int cmd, unsigned long arg2)
{
	u64 arg=arg2;
	int ret=0;
	#if MAX_LISTENERS > 1
		int i=0;
	#endif
	u64 acks;
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
			acks = ((u64 *)arg)[1];
			if( acks > 0)
			{
				hpcap_pop_listener( list, acks, buf->bufSize );
			}
			hpcap_wait_listener_user( list, (u64 *)arg );
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
			hpcap_wait_listener_user( list, (u64 *)arg );
			//printk("User wait: avail=%d, off=%d\n", ( (int *) arg)[1], ( (int *) arg)[0] );
			break;

		case HPCAP_IOC_OFFSETS:
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			((u64 *)arg)[0] = list->bufferRdOffset;
			((u64 *)arg)[1] = list->bufferWrOffset;
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
			( (u64 *) arg )[0] = get_buf_offset( buf->bufferCopia );
			( (u64 *) arg )[1] = buf->bufSize;
			break;
		
		#ifdef REMOVE_DUPS	
		case HPCAP_IOC_DUP:
			if( buf->dupTable )
			{
				copy_to_user( (void *)arg, buf->dupTable[0], sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE*DUP_WINDOW_LEVELS );
			}
			break;
		#endif

		/*case HPCAP_IOC_BUFS:
			#if MAX_LISTENERS > 1
				list = hpcap_get_listener( buf->listeners, current->pid);
			#else
				list = &buf->global;
			#endif
			break;
		*/
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
	HW_RING *rx_ring = arg;
	struct hpcap_buf *buf = rx_ring->buf;
	u64 retval=0;
	u64 avail=0;
	u16 caplen = adapters[buf->adapter]->caplen;
	u8 *rxbuf=NULL;
	#if MAX_LISTENERS > 1
		int i;
	#endif

	//set_current_state(TASK_UNINTERRUPTIBLE);//new
	printk("HPCAP: Hello, I'm kernel thread %sq%d\n", rx_ring->adapter->netdev->name, buf->queue);

    	while( !kthread_should_stop() )
	{
		if( unlikely( atomic_read(&buf->num_list) <= 0 ) )
		{
			rxbuf=NULL;
		}
		else
		{
			rxbuf=buf->bufferCopia;
		}
		
		avail = avail_bytes(&buf->global);
		retval = hpcap_rx(rx_ring, avail, rxbuf, buf->bufSize, buf->global.bufferWrOffset, &buf->bufferFileSize, caplen
		#ifdef REMOVE_DUPS
			, buf->dupTable);
		#else
			);
		#endif
		if( retval > avail )
		{
			printk("Leyendo mas de lo que se puede!!!!! (leidos:%llu, avail=%llu, BUF=%llu, bufcount=%llu)\n", retval, avail, buf->bufSize, used_bytes(&buf->global) );
		}
		if( retval == 0 )
		{
			#if MAX_LISTENERS > 1
				for(i=0;i<MAX_LISTENERS;i++)
				{
					if( ( buf->listeners[i].pid != 0 ) /*&& ( buf->listeners[i].first == 1 )*/ )
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
					if( buf->listeners[i].pid != 0 )
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

int hpcap_stop_poll_threads(HW_ADAPTER *adapter)
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

int hpcap_launch_poll_threads(HW_ADAPTER *adapter)
{
	int i;
	
	for(i=0;i<adapter->num_rx_queues;i++)
	{
		struct hpcap_buf  *bufp=adapter->rx_ring[i]->buf;
		if( !bufp )
		{
			printk("Error raro al lanzar poll para hpcap%dq%d\n", adapter->bd_number, i);
			return 0;
		}
		if( bufp->created == 0 )
		{
			#ifdef BUF_DEBUG
				memset( bufp->bufferCopia, 0, bufp->bufSize);
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

	#ifdef REMOVE_DUPS
		if( bufp->dupTable )
		{
			kfree( bufp->dupTable[0] );
			kfree( bufp->dupTable );
			bufp->dupTable = NULL;
		}
	#endif

	
	return 0;
}

#ifndef DO_BUF_ALLOC
	//char auxBufs[HPCAP_MAX_IFS][HPCAP_MAX_QUEUES][HPCAP_BUF_SIZE];
	//char __attribute__((aligned(0x1000))) auxBufs[HPCAP_BUF_SIZE];//align to 4KB page size
	char auxBufs[PAGE_SIZE+HPCAP_BUF_SIZE];//align to 4KB page size
#endif
int hpcap_buf_init(struct hpcap_buf *bufp, HW_ADAPTER *adapter, int queue,struct cdev *chard, u64 size, u64 bufoffset, int ifnum)
{
	int i;
	u64 offset = PAGE_SIZE-get_buf_offset(auxBufs);
	
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
	#else /* DO_BUF_ALLOC */
		bufp->bufSize = size;
		bufp->bufferCopia = &auxBufs[ offset + bufoffset ];
		printk("[hpcap%dq%d] offset:%llu, size:%llu, total:%lu\n", bufp->adapter, bufp->queue, bufoffset, bufp->bufSize, HPCAP_BUF_SIZE );
	#endif /* DO_BUF_ALLOC */
	if( !(bufp->bufferCopia) )
	{
		printk("Error when allocating bufferCopia-%d.%d [size=%llu]\n", adapter->bd_number, queue, bufp->bufSize );
		return -1;
	}
	printk("Success when allocating bufferCopia-%d.%d [size=%llu]\n", adapter->bd_number, queue, bufp->bufSize );
	printk( KERN_INFO "\tvirt_addr_valid(): %d\n", virt_addr_valid(bufp->bufferCopia) );

	hpcap_rst_listener( &bufp->global );
	bufp->global.bufsz = bufp->bufSize;
	for(i=0;i<MAX_LISTENERS;i++)
	{
		hpcap_rst_listener( &bufp->listeners[i] );
		bufp->listeners[i].bufsz = bufp->bufSize;
	}
	

	#ifdef REMOVE_DUPS
		if( adapter->dup_mode == 0 )
		{
			bufp->dupTable = NULL;
		}
		else
		{
			int i=0;
			struct hpcap_dup_info *aux=NULL;

			aux = (struct hpcap_dup_info *) kzalloc_node( sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE*DUP_WINDOW_LEVELS, GFP_KERNEL, adapter->numa_node );
			bufp->dupTable = (struct hpcap_dup_info **) kzalloc_node( sizeof(struct hpcap_dup_info *)*DUP_WINDOW_LEVELS, GFP_KERNEL, adapter->numa_node);
			if( !aux || !(bufp->dupTable) )
			{
				printk("Error when allocating dupTable for hpcap%dq%d\n", adapter->bd_number, queue);
				if( aux )
					kfree(aux);
				if( bufp->dupTable )
					kfree(bufp->dupTable);
				#ifdef DO_BUF_ALLOC
					kfree( bufp->bufferCopia );
				#endif
				return -1;
			}
			else
				printk("Success allocating %lu Bytes for Dup buffer in hpcap%dq%d\n",  sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE*DUP_WINDOW_LEVELS,adapter->bd_number, queue);

			for(i=0;i<DUP_WINDOW_LEVELS;i++)
			{
				bufp->dupTable[i] = &aux[i*DUP_WINDOW_SIZE];
			}
		}
	#endif /* REMOVE_DUPS */

	return 0;
}


int hpcap_unregister_chardev(HW_ADAPTER *adapter)
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


int hpcap_register_chardev(HW_ADAPTER *adapter, u64 size, u64 offset, int ifnum)
{
	int i,ret=0,major=0;
	dev_t dev = 0;
	struct hpcap_buf *bufp=NULL;

	major = HPCAP_MAJOR+adapter->bd_number;
	printk("<hpcap%d> tiene %d rxqs\n", adapter->bd_number, adapter->num_rx_queues);
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

		hpcap_buf_init(bufp, adapter, i, &bufp->chard, size, offset, ifnum);
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
