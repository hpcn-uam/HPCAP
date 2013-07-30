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

#include <sys/mman.h>
#include <sys/ioctl.h>

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
		handle->page = NULL;
		handle->bufoff = 0;
		handle->size = 0;
	}
}

int hpcap_map(struct hpcap_handle *handle)
{
	int retornos[2];
	int ret=0;
	int size, pagesize;

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
	printf("MMAP's - offset: %d, size: %d (pagesize: %d)\n", handle->bufoff, handle->bufSize, pagesize);
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

int hpcap_wait(struct hpcap_handle *handle, int count)
{
	int ret;
	int retornos[2];

	retornos[0] = count;
	ret = ioctl(handle->fd, HPCAP_IOC_WAIT, retornos);
	if( ret >= 0 )
	{
		handle->avail = retornos[1];
		handle->rdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
	}
	return ret;
}

int hpcap_ack(struct hpcap_handle *handle, int count)
{
	int ret;

	ret = ioctl(handle->fd, HPCAP_IOC_POP, count);
	handle->avail -= count;
	handle->rdoff = (handle->rdoff+count) % handle->bufSize;
	return ret;
}


int hpcap_ack_wait(struct hpcap_handle *handle, int ackcount, int waitcount)
{
	int ret;
	int retornos[3];

	retornos[0] = waitcount;
	retornos[1] = ackcount;
	retornos[2] = 0;
	ret = ioctl(handle->fd, HPCAP_IOC_POPWAIT, retornos);
	if( ret >= 0 )
	{
		handle->avail = retornos[1];
		handle->rdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
	}
	return ret;
}
int hpcap_ack_wait_timeout(struct hpcap_handle *handle, int ackcount, int waitcount,int timeout_ns)
{
	int ret;
	int retornos[3];

	retornos[0] = waitcount;
	retornos[1] = ackcount;
	retornos[2] = timeout_ns;
	ret = ioctl(handle->fd, HPCAP_IOC_POPWAIT, retornos);
	if( ret >= 0 )
	{
		handle->avail = retornos[1];
		handle->rdoff = retornos[0];
	}
	else
	{
		handle->avail = 0;
		handle->rdoff = 0;
	}
	return ret;
}

int hpcap_wroff(struct hpcap_handle *handle)
{
	int ret;
	int retorno;
	
	ret =  ioctl(handle->fd, HPCAP_IOC_WROFF, &retorno);
	if( ret >= 0 )
		ret = retorno;

	return ret;
}

int hpcap_ioc_killwait(struct hpcap_handle *handle)
{
	int ret;
	int retornos[3];

	ret = ioctl(handle->fd, HPCAP_IOC_KILLWAIT, retornos);

	return ret;
}
