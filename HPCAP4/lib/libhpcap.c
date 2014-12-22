#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include <pcap.h>

#include "../include/hpcap.h"

int hpcap_open(struct hpcap_handle *handle, int adapter_idx, int queue_idx)
{
	char devname[100]="";
	memset(handle, 0, sizeof(struct hpcap_handle));

	sprintf(devname,"/dev/hpcap_%d_%d", adapter_idx, queue_idx);
	handle->fd = open(devname, O_RDWR);
	if( handle->fd == -1 )
	{
		printf("Error when opening device %s\n", devname);
		return HPCAP_ERR;
	}
	
	handle->queue_idx = queue_idx;
	handle->adapter_idx = adapter_idx;
	handle->buf = NULL;
	handle->avail = 0;
	handle->rdoff = 0;
	//handle->lastrdoff = 0;
	handle->acks = 0;
	handle->page = NULL;
	handle->bufoff = 0;
	handle->size = 0;

	return HPCAP_OK;
}

void hpcap_close(struct hpcap_handle *handle)
{
	if( handle->fd != -1 )
	{
		close(handle->fd);
		handle->fd = 0;
		handle->queue_idx = 0;
		handle->adapter_idx = 0;
		handle->avail = 0;
		handle->rdoff = 0;
		handle->acks = 0;
		//handle->lastrdoff = 0;
		handle->page = NULL;
		handle->bufoff = 0;
		handle->size = 0;
	}
}

int hpcap_map(struct hpcap_handle *handle)
{
	uint64_t retornos[2];
	int ret=0;
	int size=0, pagesize=0;

	ret = ioctl(handle->fd, HPCAP_IOC_BUFOFF, retornos);
	if( ret >= 0 )
	{
		handle->bufoff = retornos[0];
		handle->bufSize = retornos[1];
	}
	else
		return HPCAP_ERR;
	pagesize = sysconf(_SC_PAGESIZE);
	size = handle->bufSize+handle->bufoff;
	if( ( size % pagesize ) != 0 )
		size = ( (size/pagesize) + 1 ) * pagesize;
	handle->size = size;
	printf("MMAP's - offset: %"PRIu64", size: %"PRIu64" (pagesize: %d)\n", handle->bufoff, handle->bufSize, pagesize);
	handle->page = (u_char *)mmap(NULL, handle->size, PROT_READ , MAP_SHARED|MAP_LOCKED, handle->fd, 0);
	if ((long)handle->page == -1)
		return HPCAP_ERR;

	handle->buf = &(handle->page[ handle->bufoff ]);

	return HPCAP_OK;
}

int hpcap_unmap(struct hpcap_handle *handle)
{
	int ret;
	
	ret = munmap(handle->page, handle->size);
	handle->buf = NULL;
	handle->page = NULL;
	handle->bufoff = 0;
	
	return ret;
}

int hpcap_wait(struct hpcap_handle *handle, uint64_t count)
{
	int ret;
	uint64_t retornos[3];

	retornos[0] = count;
	retornos[2]=0;
	ret = ioctl(handle->fd, HPCAP_IOC_WAIT, retornos);
	if( ( ret >= 0 ) && ( retornos[1] >= count) )
	{
		handle->avail = retornos[1];
		handle->rdoff = retornos[0];
		//handle->lastrdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
		//handle->lastrdoff = 0;
	}
	return ret;
}

int hpcap_ack(struct hpcap_handle *handle)
{
	int ret=0;

	/*if( handle->acks > handle->avail )
	{
		printf("[ACK] acks: %lu, avail: %lu\n", handle->acks, handle->avail);
	}*/
	
	if( handle->acks > 0 )
	{
		ret = ioctl(handle->fd, HPCAP_IOC_POP, handle->acks);
		handle->avail -= handle->acks;
		//handle->rdoff = (handle->lastrdoff + handle->acks) % handle->bufSize;
		//handle->lastrdoff = handle->rdoff;
		handle->acks = 0;
	}
	
	return ret;
}


int hpcap_ack_wait(struct hpcap_handle *handle, uint64_t waitcount)
{
	int ret=0;
	uint64_t retornos[3];
	//u64 avail=handle->avail;

	/*if( handle->acks > handle->avail )
	{
		printf("[ACK-WAIT] acks: %lu, avail: %lu\n", handle->acks, handle->avail);
	}*/
	
	retornos[0] = waitcount;
	retornos[1] = handle->acks;
	retornos[2] = 0;
	ret = ioctl(handle->fd, HPCAP_IOC_POPWAIT, retornos);
	if( ( ret >= 0 ) && ( retornos[1] >= waitcount) )
	{
		handle->avail = retornos[1];
		handle->rdoff = retornos[0];
		//handle->lastrdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
		//handle->lastrdoff = 0;
	}
	/*if( handle->avail != avail )
	{
		printf("[ACK-WAIT2] acks: %lu, pre-avail:%lu, avail:%lu\n", handle->acks, avail, handle->avail);
	}*/
	handle->acks = 0;
	
	return ret;
}
int hpcap_ack_wait_timeout(struct hpcap_handle *handle, uint64_t waitcount, uint64_t timeout_ns)
{
	int ret;
	uint64_t retornos[3];
	//u64 avail=handle->avail;

	retornos[0] = waitcount;
	retornos[1] = handle->acks;
	retornos[2] = timeout_ns;
	ret = ioctl(handle->fd, HPCAP_IOC_POPWAIT, retornos);
	if( ( ret >= 0 ) && ( retornos[1] >= waitcount) )
	{
		handle->rdoff = retornos[0];
		handle->avail = retornos[1];
		//handle->lastrdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
		//handle->lastrdoff = 0;
	}
	
	/*if( handle->avail != avail )
	{
		printf("[ACK-WAIT2] acks: %lu, pre-avail:%lu, avail:%lu\n", handle->acks, avail, handle->avail);
	}*/
	
	handle->acks = 0;
	
	return ret;
}

int hpcap_wroff(struct hpcap_handle *handle)
{
	int ret;
	uint64_t retornos[2];
	
	ret =  ioctl(handle->fd, HPCAP_IOC_OFFSETS, retornos);
	if( ret >= 0 )
		ret = retornos[1];

	return ret;
}
int hpcap_rdoff(struct hpcap_handle *handle)
{
	int ret;
	uint64_t retornos[2];
	
	ret =  ioctl(handle->fd, HPCAP_IOC_OFFSETS, retornos);
	if( ret >= 0 )
		ret = retornos[0];

	return ret;
}

int hpcap_ioc_killwait(struct hpcap_handle *handle)
{
	int ret;
	uint64_t retornos[3];

	ret = ioctl(handle->fd, HPCAP_IOC_KILLWAIT, retornos);

	return ret;
}

#ifdef REMOVE_DUPS
int hpcap_dup_table(struct hpcap_handle *handle)
{
	int ret;
	struct hpcap_dup_info *tabla=NULL;
	int i=0,j=0;

	tabla=(struct hpcap_dup_info *)malloc( sizeof(struct hpcap_dup_info)*DUP_WINDOW_SIZE );

	ret=ioctl(handle->fd, HPCAP_IOC_DUP, tabla);
	if( ret >= 0 )
	{
		for(i=0;i<DUP_WINDOW_SIZE;i++)
		{
			printf("[%04d] %ld , %d , ",i, tabla[i].tstamp, tabla[i].len);
			for(j=0;j<DUP_CHECK_LEN;j++)
			{
				printf("%02x ", tabla[i].data[j]);
			}
			printf("\n");
		}
	}
	else
	{
		printf("Interface hpcap%dq%d does check for duplicated packets.\n", handle->adapter_idx, handle->queue_idx);
	}
	
	return ret;
}
#endif

inline void hpcap_pcap_header(void *header, u32 secs, u32 nsecs, u16 len, u16 caplen)
{
	struct pcap_pkthdr *head = (struct pcap_pkthdr *) header;

	head->ts.tv_sec = secs;
	head->ts.tv_usec = nsecs/1000; //noseconds to useconds
	head->caplen = caplen;
	head->len = len;
}

/*
  hpcap_read_packet
	
	- struct hpcap_handle *hp: handle pointer to read the packet from
	- u_char **pbuffer: when returning its content will point to the buffer where the packet data is (NULL if padding)
	- u_char *auxbuf: pointer to an auxiliar buffer in case the packet is broken into two (circular buffer)
	- void *header: pointer to a header structure
	- ... read_header ...:function pointer to initialise previous header. If NULL no packet header is processed and pbuffer does not point to the packet data but to a buffer conatining RAW header + packet data

  return:
	timestamp (in nanoseconds) of the read packet
*/
inline u64 hpcap_read_packet(struct hpcap_handle *handle, u_char **pbuffer, u_char *auxbuf, void *header, void (* read_header)(void *, u32, u32, u16, u16) )
{
	u64 aux;
	u64 offs = handle->rdoff;
	int acks=0;
	u32 secs, nsecs;
	u16 len,caplen;


        if( unlikely( handle->acks >= handle->avail ) )
        {
                printf("hpcap_read_packet: wrong situation\n");
                *pbuffer=NULL;
                return -1;
        }
        else if( unlikely( handle->avail <  RAW_HLEN ) )
        {
                printf("hpcap_read_packet: wrong situation (not enough avail)\n");
                *pbuffer=NULL;
                return -1;
        }



	/***********************/
	/* Timestamp - seconds */
	/***********************/
	if( unlikely( offs+sizeof(u_int32_t) > handle->bufSize ) )
	{
		aux = handle->bufSize-offs;
		memcpy( &secs, handle->buf + offs, aux);
		memcpy( ((char*)&secs)+aux, handle->buf, sizeof(u_int32_t)-aux);
	}
	else
	{
		memcpy( &secs, handle->buf + offs, sizeof(u_int32_t));
	}
	offs = (offs+sizeof(u_int32_t)) % handle->bufSize;
	acks += sizeof(u_int32_t);

	/***************************/	
	/* Timestamp - nanoseconds */
	/***************************/
	if( unlikely( offs+sizeof(u_int32_t) > handle->bufSize ) )
	{
		aux = handle->bufSize - offs;
		memcpy( &nsecs, handle->buf + offs, aux);
		memcpy( ((char*)&nsecs)+aux, handle->buf, sizeof(u_int32_t)-aux);
	}
	else
	{
		memcpy( &nsecs, handle->buf + offs, sizeof(u_int32_t));
	}
	offs = (offs+sizeof(u_int32_t)) % handle->bufSize;
	acks += sizeof(u_int32_t);

	/**********/
	/* Caplen */
	/**********/
	if( unlikely( offs+sizeof(u_int16_t) > handle->bufSize) )
	{
		aux = handle->bufSize - offs;
		memcpy( &caplen, handle->buf + offs, aux);
		memcpy( ((char*)&caplen)+aux, handle->buf, sizeof(u_int16_t)-aux);
	}
	else
	{
		memcpy( &caplen, handle->buf+offs, sizeof(u_int16_t));
	}
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);


        if( unlikely( handle->avail < (handle->acks+RAW_HLEN+caplen) ) )
        {
                printf("hpcap_read_packet: wrong situation (avail < RAW_HLEN+caplen) (avail=%lu, acks=%lu, caplen=%u)\n", handle->avail, handle->acks, caplen);
                *pbuffer=NULL;
                return 0;
        }


	
	/*****************/
	/* Packet length */
	/*****************/
	if( unlikely( offs+sizeof(u_int16_t) > handle->bufSize) )
	{
		aux = handle->bufSize-offs;
		memcpy( &len, handle->buf + offs, aux);
		memcpy( ((char*)&len)+aux, handle->buf, sizeof(u_int16_t)-aux);
	}
	else
	{
		memcpy( &len, handle->buf + offs, sizeof(u_int16_t));
	}
	offs = (offs+sizeof(u_int16_t)) % handle->bufSize;
	acks += sizeof(u_int16_t);

	/* Padding check */
	if( unlikely( (secs==0) && (nsecs==0) ) )
	{
		*pbuffer = NULL;
	}
	else
	{
		/* Packet data */
		if( !read_header )
		{
			if( unlikely( handle->rdoff+caplen > handle->bufSize ) )
			{
				aux = handle->bufSize - handle->rdoff;
				memcpy( auxbuf, handle->buf + handle->rdoff, aux);
				memcpy( auxbuf+aux, handle->buf, caplen+RAW_HLEN-aux);
				*pbuffer = auxbuf;	
			}
			else
			{
				*pbuffer = (u_char*)handle->buf + handle->rdoff;
			}
			*((u16*)header) = caplen;
		}
		else
		{
			if( unlikely( offs+caplen > handle->bufSize) )
			{
				aux = handle->bufSize-offs;
				memcpy( auxbuf, handle->buf+offs, aux);
				memcpy( auxbuf+aux, handle->buf, caplen-aux);
				*pbuffer = auxbuf;
			}
			else
			{
				*pbuffer = ((u_char*)handle->buf)+offs;
			}
			read_header( header, secs, nsecs, len, caplen);
		}
	}
	offs = (offs+caplen) % handle->bufSize;
	acks += caplen;
	
	handle->rdoff = offs;
	handle->acks += acks;
	
	return (secs*1000000000+nsecs);
}


/*
  hpcap_write_block
	
	- struct hpcap_handle *hp: handle pointer to read data from
	- fd: file descriptor of the output file (nothig will be written if fd==0)
	- max_bytes_to_write: maximum amount of bytes to be written to the output file

  return:
	number of bytes read (-1 on error)
*/
inline uint64_t hpcap_write_block(struct hpcap_handle *handle, int fd, uint64_t max_bytes_to_write)
{
	uint64_t aux=0, ready=minimo(handle->avail,max_bytes_to_write);
	int ret;

	if( likely( ready >= HPCAP_BS ) )
	{
		ready = HPCAP_BS;
	}
	else
	{
		ready = 0;
		goto fin;
	}

	if( likely( fd && (ready>0) ) )
	{
		if( unlikely( (handle->rdoff + ready ) > handle->bufSize ) )
		{
			printf("Entra en el bloque de escritura multiple\n");
			if( handle->rdoff > handle->bufSize )
			{
				printf("Error grave en hpcap_write_block (rdoff=%lu, bufsize=%lu)\n", handle->rdoff, handle->bufSize);
				exit(-1);
			}
			aux = handle->bufSize - handle->rdoff;
			if( write( fd, &handle->buf[ handle->rdoff ], aux) != aux)
			{
				ready=-1;
				printf("Error en escritura 1\n");
				goto fin;
			}
			if( write( fd, handle->buf, ready-aux) !=( ready-aux) )
			{
				ready=-1;
				printf("Error en escritura 2\n");
				goto fin;
			}
		}
		else
		{
			if( write( fd, &handle->buf[ handle->rdoff ], ready) != ready )
			{
				printf("Error en escritura 3\n");
				ready=-1;
				goto fin;
			}
		}
	}
	handle->rdoff = (handle->rdoff+ready) % handle->bufSize;
	handle->acks += ready;
fin:
	return ready;
}
