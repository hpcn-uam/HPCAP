/*****************************************************************
 * Código de captura con PacketShader
 *
 * Creado: 23/02/2012 por Víctor Moreno partiendo del código de Pedro Santiago	
 * 
 * Versión con "defines" que permiten elegir entre:
 *	- escribir o no a ficheros (DO_DUMP)
 *		- escribir en formato RAW (DUMP_RAW)
 *		- escribir en formato PCAP (por defecto)
 *	- redirigir o no tráfico (DO_FORWARD)
 *	- los "defines" se encuentran en ../config.h
 *
 *
 * Revisión del 27/02/2012 por Víctor Moreno:
 *	- la decision de FW se hace en la función "check_fw_condition"
 *		- añadida redirección de tráfico UDP por puerto 5060	
 *
 * Revisión del 28/02/2012 por Víctor Moreno:
 *	- redirige tambien los paquetes IP con offset != 0
 *
 * Revisión del 29/02/2012 por Víctor Moreno:
 *	- redirige los paquetes UDP por el puerto 15070
 *
****************************************************************/


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <sys/wait.h>
#include <numa.h>

#include <sys/time.h>
#include <pcap/pcap.h>
#include <pthread.h>

#include <sys/vfs.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "../../include/ps.h"

#include "../config.h"


#define OFFSET_ETHERTYPE 12
#define OFFSET_IP_HEADER 14
#define OFFSET_OFFSET (OFFSET_IP_HEADER + 6)
#define OFFSET_PROTOCOL (OFFSET_IP_HEADER + 9)
#define OFFSET_UDP_HEADER (OFFSET_IP_HEADER + 20)
#define OFFSET_UDP_SRCPORT (OFFSET_UDP_HEADER + 0)
#define OFFSET_UDP_DSTPORT (OFFSET_UDP_HEADER + 2)

#define MEGA ((1024*1024)*1.0)
#define MAX_NAMES_LENGTH 1000

#ifdef SYNC_MUTEX
	//pthread_mutex_t sem_copy[MAX_CORES], sem_capture[MAX_CORES];
	pthread_mutex_t sem_sync[MAX_CORES];
#endif

struct ps_chunk buf[MAX_CORES][MAX_CHUNKS];
u_int32_t offset_write[MAX_CORES],offset_read[MAX_CORES];

int num_threads, chunk_size;

pthread_t captureThreadId[MAX_CORES]; 
pthread_t copyThreadId[MAX_CORES];

int num_devices;
struct ps_device devices[MAX_DEVICES];

int device_attached, device_send;
struct ps_handle handles[MAX_CORES];

#define THR_UTILIZATION 95.0
char directory[MAX_NAMES_LENGTH]=".";
u_int32_t snaplen=1514;
u_int32_t size=0;
u_int32_t sec_length=0;


int stop,main_stop;

u_int32_t packets_written=0;
FILE *log_f;

/************************************************************************************************
 *
 * FUNCIONES AUXILIARES
 *
************************************************************************************************/

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to monitor> <number of threads/queues> <chunk size> <directory> <file size(in MB)> <file length(in seconds)> <output interface>\n",
			argv0);
	exit(2);
}

void parse_opt(int argc, char **argv)
{
	int j;

	if (argc!=8)
		print_usage(argv[0]);

	
	int ifindex=-1;
	for (j = 0; j < num_devices; j++)
	{
		if (strcmp(argv[1], devices[j].name) != 0)
			continue;

		ifindex = devices[j].ifindex;
		break;
	}

	if (ifindex == -1)
	{
		fprintf(stderr, "RX: Interface %s does not exist!\n", argv[1]);
		exit(4);
	}

	device_attached = ifindex;

	ifindex=-1;
	for (j = 0; j < num_devices; j++)
	{
		if (strcmp(argv[7], devices[j].name) != 0)
			continue;

		ifindex = devices[j].ifindex;
		break;
	}

	if (ifindex == -1)
	{
		fprintf(stderr, "TX: Interface %s does not exist!\n", argv[1]);
		exit(4);
	}

	device_send = ifindex;

	
	num_threads=atoi(argv[2]);
	if(num_threads<=0 || num_threads>MAX_CORES)
	{
		fprintf(stderr, "Num. threads, %s, too large!\n",argv[2]);
	}
	chunk_size=atoi(argv[3]);
	if(chunk_size<=0 || chunk_size>MAX_CHUNK_SIZE)
	{
		fprintf(stderr, "Chunk size %s, too large!\n",argv[2]);
	}
	strcpy( directory, argv[4] );
	size = atoi( argv[5] );
	sec_length =  atoi( argv[6] );
}

struct ps_chunk* buf_copy[MAX_CORES];
u_int64_t filesize_copy[MAX_CORES];

int getUtilization(char* directory_name,u_int64_t* used,u_int64_t *available,int *utilization)
{
/*	char command[1000];
	sprintf(command,"sudo df %s | gawk '{if(match($5,\"([0-9]+)(%%)\",a))print $3,$4,a[1];}'",directory_name);
	FILE* out_utilization=popen(command,"r");
	if(out_utilization==NULL){
		perror("Opening command");
		exit(-1);
	}
	if(fscanf(out_utilization,"%lu %lu %d",used,available,utilization)==3){
		pclose(out_utilization);
		return *utilization;
	}
	pclose(out_utilization);
	return -1;*/
	struct statfs buf;
	statfs(directory_name, &buf);
	*used=buf.f_blocks;
	*available=buf.f_bavail;
	*utilization=100-100*buf.f_bavail/buf.f_blocks;
	return *utilization;

}

char* getDirectory(char* directory_file,char *directory_name){
	char file[1000];
	u_int64_t used,available;
	int utilization;
	u_int8_t found=0;

	FILE* fdir=fopen(directory_file,"r");

	if(fdir==NULL)
	{
		perror(directory);
		exit(-1);
	}
	while(fgets(file, 1000, fdir)&&found==0)
	{
		file[strlen(file)-1]='\0';
		int ret=getUtilization(file,&used,&available,&utilization);
		if(ret>=0 && (double)(used+size)/(available+used)*100<THR_UTILIZATION)
		{
			strcpy(directory_name,file);
			found=1;
		}
	}
	fclose(fdir);
	if(found==1)
		return directory_name;
	else
		return NULL;
}


#ifdef DUMP_RAW
FILE * get_dump_file(u_int64_t my_core)
#else
pcap_dumper_t * get_dump_file(pcap_t *p, u_int64_t my_core)
#endif
{
	struct timeval begin;
	char capture_filename[MAX_NAMES_LENGTH],directory_name[MAX_NAMES_LENGTH];
	
	if( getDirectory(directory,directory_name) == NULL )
	{
		printf("No directory available\n");
		return NULL;
	}
	gettimeofday(&begin,NULL);
	#ifdef DUMP_RAW
		sprintf(capture_filename,"%s/%lu_%lu.raw",directory_name,begin.tv_sec,my_core);
		return fopen(capture_filename,"w");
	#else //PCAP
		sprintf(capture_filename,"%s/%lu_%lu.pcap",directory_name,begin.tv_sec,my_core);
		return pcap_dump_open(p,capture_filename);
	#endif
}
/************************************************************************************************
************************************************************************************************/



/************************************************************************************************
 *
 * FUNCIONES DE ESCRITURA A DISCO
 *
************************************************************************************************/

#ifdef DUMP_RAW
int dump_packet_to_file(FILE ** file, u_int64_t * bytes, u_int32_t * first_packet_sec, u_int32_t * packet_sec, u_int64_t my_core)
#else //PCAP
int dump_packet_to_file(pcap_dumper_t ** file, pcap_t *p, u_int64_t * bytes, u_int32_t * first_packet_sec, u_int32_t * packet_sec, u_int64_t my_core)
#endif
{
	
	if( ( (*bytes)/MEGA > size ) || //cierre de fichero por tamano
		( ( (*packet_sec) - (*first_packet_sec) ) > sec_length ) ) //cierre de fichero por tiempo
	{
		#ifdef DUMP_RAW
			fclose(*file);
			*file = get_dump_file(my_core);
		#else //PCAP
			pcap_dump_close(*file);
			*file = get_dump_file(p,my_core);
		#endif
		if( (*file)==NULL)
		{
			fprintf(stderr,"Destination directory is full or does not exist\n");
			exit(-1);
		}
		*bytes=0;
		*first_packet_sec=-1;
	}
	if ( offset_read[my_core] != offset_write[my_core] )//no hay chunks con datos
	{
		int i=offset_read[my_core];
		int j;
		
		//gettimeofday();
		#ifdef DUMP_RAW
			j=buf[my_core][i].cnt-1;
			#ifdef DO_DUMP
				fwrite(&buf[my_core][i].cnt, 1 ,sizeof(buf[my_core][i].cnt),*file);
				fwrite(buf[my_core][i].info, 1 ,sizeof(struct ps_pkt_info)*buf[my_core][i].cnt, *file);
				fwrite(buf[my_core][i].buf, 1 ,buf[my_core][i].info[j].offset+buf[my_core][i].info[j].len, *file);
			#endif
			//incremento "contadores"
			*bytes += sizeof(struct ps_pkt_info)*ret+chunk.info[ret-1].offset+chunk.info[ret-1].len;
			if( (*first_packet_sec) == -1 )
				*first_packet_sec = buf[my_core][i].info[0].tv.tv_sec;
			*packet_sec = buf[my_core][i].info[0].tv.tv_sec;
		#else //PCAP
			for(j=0;j<buf[my_core][i].cnt;j++)
			{
				struct pcap_pkthdr h;

				h.ts.tv_sec = buf[my_core][i].info[j].tv.tv_sec;
				h.ts.tv_usec = buf[my_core][i].info[j].tv.tv_usec;
				if( ( buf[my_core][i].info[j].len < snaplen ) || ( snaplen==0 ) )
				{
					h.caplen=buf[my_core][i].info[j].len;
				}
				else
				{
					h.caplen=snaplen;
				}
				h.len=buf[my_core][i].info[j].len;
				#ifdef DO_DUMP
					pcap_dump( (u_char*)*file, &h, (u_char *)(buf[my_core][i].buf+buf[my_core][i].info[j].offset) );
				#endif
				//incremento "contadores"
				*bytes += h.caplen;
			}
			*packet_sec = buf[my_core][i].info[0].tv.tv_sec;
			if( (*first_packet_sec) == -1 )
				*first_packet_sec = buf[my_core][i].info[0].tv.tv_sec;
		#endif	
		//gettimeofday();	
		
		offset_read[my_core] = (offset_read[my_core]+1)%MAX_CHUNKS;
		packets_written += buf[my_core][i].cnt;
	}

	return 0;
}


void * copy(void *parameter)
{
	u_int64_t my_core=(u_int64_t)parameter;
	u_int64_t bytes=0;
	#ifdef DUMP_RAW
		FILE * file=NULL;
	#else
		pcap_dumper_t* file=NULL;
		pcap_t *p=NULL;
	#endif
	u_int32_t first_packet_sec=0,packet_sec=0;

	#ifdef DO_MEMLOCK
		mlockall( MCL_CURRENT | MCL_FUTURE );
	#endif

	//fijar en un core
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(CORE_BASE+my_core+num_threads,&mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0) {
		perror("pthread_setaffinity_np");
	}

	
	#ifdef DUMP_RAW
		file=get_dump_file(my_core);
	#else
		p=pcap_open_dead(DLT_EN10MB,snaplen);
		file=get_dump_file(p,my_core);
	#endif
	if( !file )
	{
		fprintf(stderr,"Error open capture file\n");
		exit(-1);
	}
	bytes=0;
	first_packet_sec=-1;
	//en bucle
	while( !stop )
	{
		#ifdef DUMP_RAW
			dump_packet_to_file(&file, &bytes, &first_packet_sec, &packet_sec, my_core);
		#else
			dump_packet_to_file(&file, p, &bytes, &first_packet_sec, &packet_sec, my_core);
		#endif
	}

	#ifdef DUMP_RAW
		fclose(file);
	#else
		pcap_dump_close(file);
	#endif

	return NULL;

}
/************************************************************************************************
************************************************************************************************/



/************************************************************************************************
 *
 * FUNCIONES DE CAPTURA DESDE LA RED
 *
************************************************************************************************/

int ps_alloc_chunk_user(struct ps_chunk *chunk, int size)
{
	memset(chunk, 0, sizeof(*chunk));

	#ifdef DO_MEMALIGN
		chunk->info = (struct ps_pkt_info *)memalign( ALIGN_BLOCKSIZE, sizeof(struct ps_pkt_info) * size );
	#else
		chunk->info = (struct ps_pkt_info *)malloc( sizeof(struct ps_pkt_info) * size );
	#endif
	if (!chunk->info)
		return -1;
	/*#ifdef DO_MEMLOCK
		if( mlock( chunk->info, sizeof(struct ps_pkt_info)*size ) != 0 )
			return -1;
	#endif*/

	#ifdef DO_MEMALIGN
		chunk->buf = (char *)memalign( ALIGN_BLOCKSIZE, MAX_PACKET_SIZE * size );
	#else
		chunk->buf = (char *)malloc( MAX_PACKET_SIZE * size );
	#endif
	if ( !chunk->buf )
		return -1;
	/*#ifdef DO_MEMLOCK
		if( mlock( chunk->buf, sizeof(MAX_PACKET_SIZE*size ) != 0 )
			return -1;
	#endif*/
	return 0;
}

void ps_free_chunk_user(struct ps_chunk *chunk)
{
	/*#ifdef DO_MEMLOCK
		munlock( chunk->buf, sizeof(MAX_PACKET_SIZE*size );
		munlock( chunk->info, sizeof(struct ps_pkt_info)*size );
	#endif*/
	if( chunk->info )
	{
		free(chunk->info);
		chunk->info = NULL;
	}

	if( chunk->buf )
	{
		free(chunk->buf);
		chunk->buf = NULL;
	}
}

#ifdef DO_FORWARD
int nfrags=0;
int check_fw_condition(char * paq)
{
	u_int16_t ethertype_ip=htons(0x0800);
	u_int8_t protocol_tcp = 6;//solo es un byte => no hace falta htonX
	u_int8_t protocol_udp = 17;//solo es un byte => no hace falta htonX
	u_int16_t udp_fwport1 = htons(5060);
	u_int16_t udp_fwport2 = htons(15070);
	u_int16_t ip_offset;

	memcpy(&ip_offset, paq + OFFSET_OFFSET, 2);
	ip_offset = htons( ip_offset );
	ip_offset &= 0x1FFF;
	
	return ( ( memcmp(paq + OFFSET_ETHERTYPE, &ethertype_ip, 2) == 0 ) && //IPv4
			( ( ip_offset > 0 ) || //es un fragmento IP (que no sea el primero)
			( ( memcmp(paq + OFFSET_PROTOCOL, &protocol_udp, 1) == 0 ) && //UDP
				( ( ( memcmp(paq + OFFSET_UDP_SRCPORT, &udp_fwport1, 2) == 0 ) || ( memcmp(paq + OFFSET_UDP_SRCPORT, &udp_fwport2, 2) == 0 ) ) || //sobre puerto 5060 ó 15070 (pto_src)
				( ( memcmp(paq + OFFSET_UDP_DSTPORT, &udp_fwport1, 2) == 0 ) || ( memcmp(paq + OFFSET_UDP_DSTPORT, &udp_fwport2, 2) == 0 ) ) ) ) || //sobre puerto 5060 ó 15070 (pto_dst)
			( memcmp(paq + OFFSET_PROTOCOL, &protocol_tcp, 1) == 0 ) ) ); //TCP
	
}
#endif

void * capture(void *parameter)
{
	u_int64_t my_core=(u_int64_t)parameter;
	struct ps_handle *handle = &handles[my_core];
	struct ps_chunk chunk;
	int nbuf=0,nchunks=0;
	int sig=SIGINT;
	int perdiendo=0;
	#ifdef DO_FORWARD
		struct ps_handle handle_fw;
		struct ps_chunk chunk_fw;
		u_int16_t n_fw=0;
		u_int16_t offset=0;
	#endif
	#ifdef DEBUG
		struct timeval tv;
		u_int64_t previous=0,current=0;
		u_int64_t previous_packets,current_packets;
		u_int64_t previous_bytes,current_bytes=0;
	#endif
	time_t now;
	char *aux=NULL;

	#ifdef DO_MEMLOCK
		mlockall( MCL_CURRENT | MCL_FUTURE );
	#endif

	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(CORE_BASE+my_core,&mask);
	if( pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) < 0 )
	{
		perror("pthread_setaffinity_np");
	}

	assert(ps_init_handle(handle) == 0);

	struct ps_queue queue;
	if( my_core > devices[device_attached].num_rx_queues )
	{
		printf("%u %lu\n",devices[device_attached].num_rx_queues,my_core);
		exit(-1);
	}

	queue.ifindex = device_attached;
	queue.qidx = my_core;

	printf("attaching RX queue xge%d:%d to CPU%lu\n", queue.ifindex, queue.qidx, my_core);
	assert(ps_attach_rx_device(handle, &queue) == 0);

	assert( ps_alloc_chunk(handle, &chunk) == 0 );
	chunk.cnt = chunk_size;
	chunk.recv_blocking = 1;

	int i;
	printf("reservando chunks %lu\n",my_core);
	for(i=0;i<MAX_CHUNKS;i++)
	{
		if( ps_alloc_chunk_user( &(buf[my_core][i]), chunk_size ) != 0 )
		{
			printf("Error reservando chunk i:%u en core:%lu\n",i,my_core);
			exit(-1);
		}
	}
	printf("reservados %lu SIZEOF:%lu\n",my_core,sizeof(buf[my_core][0].cnt));
	nbuf=0;
	nchunks=0;

	#ifdef DO_FORWARD
		assert(ps_init_handle(&handle_fw)==0);
		assert(ps_alloc_chunk(&handle_fw,&chunk_fw)==0);
		chunk_fw.queue.qidx=my_core;
		assert(chunk_fw.info);
		chunk_fw.queue.ifindex=device_send;
	#endif

	//crea hilo para copia
	offset_write[my_core]=0;
	nchunks=0;
	offset_read[my_core]=0;
	/*pthread_attr_t t_attr_copia;
	struct sched_param para_copia;
	pthread_attr_init(&t_attr_copia);
	pthread_attr_setschedpolicy(&t_attr_copia,SCHED_RR);
	para_copia.sched_priority=99;
	pthread_attr_setschedparam(&t_attr_copia,&para_copia);*/
	pthread_create (&copyThreadId[my_core], /*&t_attr_copia*/NULL, copy, (void*)my_core);
	

	#ifdef DEBUG
		gettimeofday(&tv,NULL);
		previous=tv.tv_sec;
		previous_packets = handle->rx_packets[device_attached];
		previous_bytes = handle->rx_bytes[device_attached];
	#endif

	while( !stop )
	{
		if( offset_read[my_core] == ( (nchunks+1) % MAX_CHUNKS ) ) // no hay chunks libres
		{
			#ifdef OVERFLOW_DEBUG
				if(perdiendo==0)
				{
					now = time(NULL);
					aux=ctime(&now);
					aux[ strlen(aux)-1 ] = '\0';
					printf("[%s] perdidas RX\t\ti_read:%d\ti_write:%d\n", aux, offset_read[my_core], nchunks);
					perdiendo=1;
				}
			#endif
			continue;
		}
		#ifdef OVERFLOW_DEBUG
			else if( perdiendo == 1 )
			{
				now = time(NULL);
				aux=ctime(&now);
				aux[ strlen(aux)-1 ] = '\0';
				printf("[%s] Fin perdidas\n", aux);
				perdiendo=0;
			}
		#endif
		int ret = ps_recv_chunk(handle, &chunk);
		if (ret < 0)
		{
			if (errno == EINTR)
				continue;

			if (!chunk.recv_blocking && errno == EWOULDBLOCK)
				break;

			assert(0);
		}
		else
		{
			#ifdef DEBUG
				current=chunk.info[0].tv.tv_sec;
				if(current>previous)
				{
					current_packets=handle->rx_packets[device_attached];
					DEBUG_PRINTF("q%lu:%lupps %luMbps\n",my_core,current_packets-previous_packets,(current_bytes-previous_bytes)*8/1000000);
					previous=current;
					previous_packets=current_packets;
					previous_bytes=current_bytes;		
				}
			#endif

			#ifdef DO_FORWARD
				//reenvio
				n_fw=0;
				offset=0;
				for(i=0;i<ret;i++)
				{
					if( check_fw_condition(chunk.buf+chunk.info[i].offset) )
					{
						memcpy( chunk_fw.info+n_fw, chunk.info+i, sizeof(struct ps_pkt_info) );
						chunk_fw.info[n_fw].offset=offset;
						memcpy( chunk_fw.buf+offset, chunk.buf+chunk.info[i].offset, chunk.info[i].len);
						offset += chunk.info[i].len;
						n_fw++;
					}
				}
				if(n_fw>0)
				{
					chunk_fw.cnt = n_fw;
					ps_send_chunk( &handle_fw, &chunk_fw);
				}
			#endif
			
			//copy chunk
			buf[my_core][nchunks].cnt = ret;
			memcpy( buf[my_core][nchunks].info, chunk.info, ret*sizeof(struct ps_pkt_info) );
			int total_bytes = chunk.info[ret-1].offset+chunk.info[ret-1].len;
			memcpy( buf[my_core][nchunks].buf, chunk.buf, total_bytes );
			#ifdef DEBUG
				current_bytes += total_bytes;
			#endif
			
			//update variables
			offset_write[my_core] = (offset_write[my_core]+1)%MAX_CHUNKS;
			nchunks = offset_write[my_core];
		}
		assert(ret >= 0);
	}

	/*CIERRE ORDENADO*/
	printf("Hilo de CP %ld/%d...",my_core,num_threads);
	pthread_kill(copyThreadId[my_core], sig);
	pthread_join(copyThreadId[my_core], NULL);
	printf("DONE\n");
	#ifdef DO_FORWARD
		ps_free_chunk( &chunk_fw );
		ps_close_handle( &handle_fw );
	#endif
	ps_detach_rx_device( handle, &queue );
	for(i=0;i<MAX_CHUNKS;i++)
	{
		ps_free_chunk_user( &( buf[my_core][i] ) );
	}
	ps_free_chunk( &chunk );
	ps_close_handle( handle );
	return NULL;
}
/************************************************************************************************
************************************************************************************************/



void clean_exit(int signal)
{
	uint64_t i;
	int sig=SIGINT;

	if(stop)
		return;

	stop=1;
	sleep(3);
	/*CIERRE ORDENADO*/
	for(i=0;i<num_threads;i++)
	{
		printf("Hilo RX %ld/%d....", i, num_threads);
		pthread_kill(captureThreadId[i], sig);
		pthread_join(captureThreadId[i], NULL);
		printf("DONE\n");
	}

	if(log_f)
	{
		fprintf(log_f,"%d\n",packets_written);
		fflush(log_f);
		fclose(log_f);
		log_f = NULL;
	}
	main_stop=1;
}


int main(int argc, char **argv)
{
	u_int64_t i;

	stop=0;
	main_stop=0;
	log_f=fopen("packets_written.log","w");

	num_devices = ps_list_devices(devices);
	if (num_devices == -1)
	{
		perror("ps_list_devices");
		exit(1);
	}
	parse_opt(argc, argv);

	/*pthread_attr_t t_attr_captura;
	struct sched_param para_captura;
	pthread_attr_init(&t_attr_captura);
	pthread_attr_setschedpolicy(&t_attr_captura,SCHED_RR);
	para_captura.sched_priority=99;
	pthread_attr_setschedparam(&t_attr_captura,&para_captura);*/


	for (i = 0; i < num_threads; i++)
	{
		#ifdef SYNC_MUTEX
			//pthread_mutex_init(&sem_copy[i],NULL);
			//pthread_mutex_init(&sem_capture[i],NULL);
			pthread_mutex_init(&sem_sync[i],NULL);
			pthread_mutex_init(&sem_sync[i],NULL);
		#endif
		pthread_create (&captureThreadId[i], /*&t_attr_captura*/NULL, capture, (void*)i);
	}

	signal(SIGINT,clean_exit);
	while (!main_stop)
	{
		sleep(1);
	}

	return 0;
}

