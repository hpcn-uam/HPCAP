#define  _BSD_SOURCE
#include <time.h>

#include "IPflow.h"
#include "monitor.h"
#include "aux.h"
#include "../../../include/hpcap.h"
#include "../lib/libmgmon.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <features.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <linux/ip.h>
#include <string.h>
#include <net/ethernet.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <limits.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
//#include <numa.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define IP_SIP 12
#define IP_DIP 16
#define IP_ALEN 4
#define ETH_ALEN 6

#define MTU 1514
#define INFINITO 18446744073709551615ULL
#define MAX_INTERFACES 16

//descomentat para exportar flujos a ficheros
//#define EXPORT_FLOWS_FILE

u_int32_t created_flows=0;
u_int32_t dead_flows=0;


#define MIN(a,b)(((a)<(b))?(a):(b))


int8_t affinity_dump=0;
int8_t affinity_process=0;
int8_t affinity_export=0;
int8_t affinity_main=0;

extern int free_nodes;
extern int free_session;
extern int used_session;
int exported_sessions;
extern int expired_session;
extern int  active_session;
struct passwd *pwd;

pthread_t main_thread;

u_int64_t previous=0, current=0;
u_int64_t previous_capture=0, current_capture=0;
u_int64_t previous_update=0;
u_int16_t previous_week=0, current_week=0;
u_int16_t previous_year=0, current_year=0;


int sock1;
char *map;
struct tpacket_hdr * ps_header_start;
struct tpacket_req req;
struct iovec *ring;


volatile struct sockaddr_ll *ps_sockaddr = NULL;


u_int32_t frame_counter = 0;
u_int32_t frame_counter_kernel = 0;


//fichero de configuracion
char flowsdir[MAX_LINE];
char datadir[MAX_LINE];
char capturedir[MAX_LINE];
char lecturadir[MAX_LINE];
char flowprocesslock[MAX_LINE];
char interfaz[MAX_LINE];
char file_lectura[MAX_LINE];
u_int16_t capture_duration;
u_int16_t capturespace;
char user_web[MAX_LINE];
u_int8_t patrol=0;
u_int8_t filter_inversis=0;
u_int8_t filter_mac_src[ETH_ALEN];
u_int8_t filter_mac_dst[ETH_ALEN];

uint32_t capture_dir_duration;


//captura
char capture_filename[MAX_LINE];
pcap_dumper_t *capture;
pcap_t *pcap_open;

u_int8_t prev_flag_alarm=0,current_flag_alarm=0,next_flag_alarm=0;
u_int64_t alarmID=0;
node_l *capture_list=NULL;
u_int16_t mbytes_capture=0;
extern node_l *nodel_aux;
extern node_l static_node;

//flujos
node_l *flow_table[MAX_FLOWS_TABLE_SIZE]={NULL};
node_l *active_flow_list;
node_l *expired_flow_list;
node_l *flags_expired_flow_list;
u_int32_t expired_flows;
u_int32_t in_expired_list_flows;
u_int32_t active_flows;
extern node_l *aux_session;

//hilos
pthread_t idHiloExport;
pthread_t idHiloCapture;
pthread_t idHiloProcess;
pthread_mutex_t sem_expired_list = PTHREAD_MUTEX_INITIALIZER;

u_int64_t capture_timestamp;

extern u_int64_t last_packet_timestamp;

FILE* flow_file_txt,*flow_file_bin;


u_int64_t pkts_total=0,bytes_total=0,flows_total=0;
extern u_int32_t max_payload;

//PATROL
FILE *patrol_alarm_file;


//HPCAP
struct hpcap_handle hp_dt[MAX_INTERFACES],hp_pt[MAX_INTERFACES];
int stop_dt=0,stop_pt=0,stop_et;
int num_interfaces=0;
uint8_t interfaces[MAX_INTERFACES];
char bonding_name[1000];

void *exportThread(void *parameter)
{
	node_l *n=NULL;

	cpu_set_t mask;   /* process switches to processor 3 now */
	CPU_ZERO(&mask);
	CPU_SET(affinity_export,&mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0) {
		perror("pthread_setaffinity_np");
	}

	struct timeval initwr;
	gettimeofday(&initwr,NULL);

	time_t rawtime;
	struct tm *info;
	time( &rawtime );
	info = localtime( &(initwr.tv_sec) );
	u_int32_t offset_tz=info->tm_gmtoff;

	int flow_sock=0;
        struct sockaddr_in flowAddr;
        int __attribute__((unused)) ret;


	flow_sock = open_multicast_tx_socket( MCAST_FLOW, interfaces[0], 0, &flowAddr);
        if( flow_sock == 0 )
        {
                perror("Create multicast FLOW socket");
        }

	/*int buff_size;
	int len = sizeof(buff_size);
	int size=2129920;
	int ret2;
	ret2=setsockopt(flow_sock,SOL_SOCKET,SO_SNDBUF,(char*)&size,len);
	printf("AAAA:%d\n",ret2);
	printf("%lu %d %d\n",initwr.tv_sec,offset_tz,(int)((initwr.tv_sec+offset_tz)/86400)*86400);*/

	#ifdef EXPORT_FLOWS_FILE
		char filename[MAX_LINE];
		sprintf(filename,"%s/flows%s_%d.txt",flowsdir,bonding_name,(((int)initwr.tv_sec+offset_tz)/86400)*86400-offset_tz);
		flow_file_txt=fopen(filename,"w");
		sprintf(filename,"%s/flows%s_%d.bin",flowsdir,bonding_name,(((int)initwr.tv_sec+offset_tz)/86400)*86400-offset_tz);
		flow_file_bin=fopen(filename,"wb");
		u_int64_t nbin=0;
		int32_t prev_second=0,current_second=last_packet_timestamp/1000000;
	#endif


	exported_sessions=0;


	while(!stop_et){
		pthread_mutex_lock(&sem_expired_list);
		if(expired_flow_list!=NULL){
			//sacar flujo de la lista
			n=list_pop_first_node(&expired_flow_list);
						expired_session--;

			pthread_mutex_unlock(&sem_expired_list);
			//exportar flujo
			node_l *current_node=n;
			IPSession *current_session=NULL;
			current_session=(IPSession*)(current_node->data);
		        current_session->exportation_timestamp=last_packet_timestamp;
			/*{
                                current_session->incoming.lastpacket_timestamp = current_session->lastpacket_timestamp;
                                current_session->incoming.firstpacket_timestamp = current_session->firstpacket_timestamp;
                                current_session->incoming.duration = current_session->lastpacket_timestamp/1000000-current_session->firstpacket_timestamp/1000000+1;
                                current_session->incoming.avg_pack_size = (double)current_session->incoming.nbytes/current_session->incoming.npack;
                                if( current_session->incoming.npack > 1 )
                                {
                                        current_session->incoming.std_pack_size = sqrt( (double)current_session->incoming.nbytes_sqr / (current_session->incoming.npack-1) - current_session->incoming.avg_pack_size*current_session->incoming.avg_pack_size*current_session->incoming.npack/(current_session->incoming.npack-1));
                                }
                                current_session->incoming.avg_int_time = current_session->incoming.sum_int_time / (current_session->incoming.npack-1);
                                if( current_session->incoming.npack <= 2 )
                                {
                                        current_session->incoming.std_int_time = 0;
                                }
                                else
                                {
                                        current_session->incoming.std_int_time = sqrt( current_session->incoming.sum_int_time_sqr / (current_session->incoming.npack-2)-current_session->incoming.avg_int_time*current_session->incoming.avg_int_time*(current_session->incoming.npack-1)/(current_session->incoming.npack-2));
                                }
                        }*/
			#ifdef EXPORT_FLOWS_FILE
			printTupleFileTextAndBin(current_session,flow_file_txt,flow_file_bin,&nbin);
			#endif
			//ret = sendto(flow_sock, (void *)&(current_session->incoming), sizeof(IPFlow), 0, (struct sockaddr *)&flowAddr, sizeof(flowAddr));
			exported_sessions++;
			releaseIPSession(current_session);
			releaseNodel(current_node);
			// Frag. packets
		        if (current_session->incoming.frag_flag)
				removePointer_frag(&(current_session->incoming));
			flows_total++;
		}
		else{//lista vacia;
			pthread_mutex_unlock(&sem_expired_list);
			//sleep(10000);
			usleep(1);
		}
		#ifdef EXPORT_FLOWS_FILE
			current_second=last_packet_timestamp/1000000+offset_tz;
			if(current_second>prev_second)
			{
				if(current_second/86400>prev_second/86400)
				{
					//pasa un día
					fflush(flow_file_txt);
					fflush(flow_file_bin);
					fclose(flow_file_txt);
					fclose(flow_file_bin);
					printf("%d %d %d %d %d %d\n",current_second,prev_second,offset_tz,(current_second/86400)*86400,current_second/86400,prev_second/86400);
					sprintf(filename,"%s/flows%s_%d.txt",flowsdir,bonding_name,(current_second/86400)*86400-offset_tz);
					flow_file_txt=fopen(filename,"w");
					sprintf(filename,"%s/flows%s_%d.bin",flowsdir,bonding_name,(current_second/86400)*86400-offset_tz);
					flow_file_bin=fopen(filename,"wb");
					nbin=0;
				}
				prev_second=current_second;
			}
		#endif
	}
	#ifdef EXPORT_FLOWS_FILE
		flush(flow_file_txt);
		fflush(flow_file_bin);
		fclose(flow_file_txt);
		fclose(flow_file_bin);
	#endif
	return NULL;
}


FILE *log_file;
void capturaSenial (int nSenial)
{
	printf("En captura señal: %u\n",nSenial);
	stop_dt=1;
	stop_pt=1;
	stop_et=1;
	sleep(2);

	if( affinity_export != -1 )
		pthread_join(idHiloExport, NULL);
	if( affinity_dump != -1 )
		pthread_join(idHiloCapture, NULL);
	if( affinity_process != -1 )
		pthread_join(idHiloProcess, NULL);
	
	//if(nSenial==0)
	{
		fclose(flow_file_txt);
		fclose(flow_file_bin);
		printf("fichero flujos cerrado\n");
		fflush(stdout);
		
		last_packet_timestamp=0;
		fclose(log_file);
		printf("redes liberadas\n");
		
		freeIPSessionPool();
		printf("pool sesiones liberado\n");
		freeNodelPool();
		printf("Recursos liberados\nSaliendo...\n");
	}
	return;
}


void reset_flow_table(){
		last_packet_timestamp=INFINITO;
		cleanup_flows();
}

void process_packet(u_int8_t *bp,struct pcap_pkthdr *hcap, mrtg *stat, int mrtg_sock, struct sockaddr_in *mrtgAddr)
{
	last_packet_timestamp=((u_int64_t) ((u_int64_t) (hcap->ts.tv_sec) * 1000000ULL) +(u_int64_t) (hcap->ts.tv_usec));
	char filename[MAX_LINE];
	int __attribute__((unused)) ret;
	u_int8_t num_tags=0;

	current=last_packet_timestamp/1000000;
	current_capture=start_capture_interval(current,capture_duration);

	if(previous==0)
	{//primer paquete
		//contadores de tiempo
		previous=current;//segundo actual
		previous_capture=start_capture_interval(current,capture_duration);//inicio intervalo de captura
		week_number(current,&previous_year,&previous_week);//numero de semana del año
		previous_update=current;//ultima actualizacion de redes

		//creacion directorio semanal de datos y alarmas
		sprintf(filename,"%s/%u-%u",datadir,previous_year,previous_week);
		mkdir(filename,0777);
		ret=chown(filename,pwd->pw_uid,pwd->pw_gid);

		//fichero datos
		sprintf(filename,"%s/%u-%u/%u",datadir,previous_year,previous_week,0);
		log_file=fopen(filename,"a+");
	        ret=chown(filename,pwd->pw_uid,pwd->pw_gid);
		stat->bytes=0;
		stat->packets=0;
		stat->concurrent_flows=0;
		
		active_flow_list=NULL;
		expired_flow_list=NULL;
		flags_expired_flow_list=NULL;
		active_flows=0;
		expired_flows=0;
		memset(flow_table,0,MAX_FLOWS_TABLE_SIZE*sizeof(node_l *));
		aux_session=NULL;
		mbytes_capture=0;
		capture_list=NULL;
	}
				
	if( hcap->caplen > 0 )
	{
		stat->bytes += hcap->caplen;
		stat->packets++;
	}
	
	if( previous < current )
	{//pasa un segundo
		//printf("CREATED:%u DEAD:%u DIFF:%u LOG:%u\n",created_flows,dead_flows,created_flows-dead_flows,networks[0].concurrent_flows_IN);
		//printf("previous:%lu USED_FLOWS:%u EXPIRED_FLOWS=%u ACTIVE_SESSIONS=%u DIFF:%d\n",previous,used_session,expired_session,active_session,used_session-active_session-expired_session);
		stat->concurrent_flows = active_session;
		//escribir log
		fprintf(log_file,"%lu\t%lu\t%lu\t%lu\n",previous, stat->bytes*8, stat->packets, stat->concurrent_flows);
		fflush(log_file);
		stat->timestamp = current;
		ret = sendto(mrtg_sock, (void *)stat, sizeof(mrtg), 0, (struct sockaddr *)mrtgAddr, sizeof(*mrtgAddr));
		stat->bytes=0;
		stat->packets=0;
		stat->concurrent_flows=0;
	
		//limpiar tabla de flujos
		cleanup_flows();
		//reset contadores
		previous=current;
		if( previous_capture < current_capture )
		{//pasan capture_duration segundos
			week_number(current,&current_year,&current_week);//numero de semana del año
			if(previous_year<current_year || previous_week <current_week)
			{//pasa una semana
				sprintf(filename,"%s/%d-%d/",datadir,current_year,current_week);
				mkdir(filename,0777);
				ret=chown(filename,pwd->pw_uid,pwd->pw_gid);
					
				//cerrar y crear fichero datos
				fclose(log_file);
				sprintf(filename,"%s/%u-%u/%u",datadir,current_year,current_week,0);
				log_file=fopen(filename,"w");
				ret=chown(filename,pwd->pw_uid,pwd->pw_gid);
				previous_year=current_year;
				previous_week=current_week;
			}
			//sprintf(capture_filename,"../%s/%lu.pcap",capturedir,current_capture);
			//capture=pcap_dump_open(pcap_open,capture_filename);//fichero de captura
			//chown(capture_filename,pwd->pw_uid,pwd->pw_gid);
			previous_capture=current_capture;
		}

	}
	else
		previous=current;

	bp += 2*ETH_ALEN;
	//saltamos VLAN
	while( (bp[0] == 0x81) && (bp[1] == 0x00) )
	{
		bp += 4;
		num_tags++;
	}
	
	//si el paquete es IP
	if( (bp[0] == 0x08) && (bp[1] == 0x00) )
	{
		bp += 2;
		processFlow(bp,hcap,0,0,num_tags);
	}
}

void get_interfaces()
{
	int j;	
	char *str1,*saveptr1,*token;
	strcpy(bonding_name,"");
	char intf_aux[100];

	for(j=1,str1=interfaz;;j++,str1=NULL){
		token = strtok_r(str1, ",", &saveptr1);
        	if (token == NULL)
			break;
		interfaces[j-1]=atoi(token);
		printf("interfaces[%u]: %u\n", j-1, interfaces[j-1]);
		sprintf(intf_aux,"_%u",interfaces[j-1]);
		strcat(bonding_name,intf_aux);
	}

	printf("bonding_name:%s\n",bonding_name);
	num_interfaces=j-1;
	printf("Num interfaces:%u\n",num_interfaces);
}


void* dumpThread (void *par){

	cpu_set_t mask;   /* process switches to processor 3 now */
	CPU_ZERO(&mask);
	CPU_SET(affinity_dump,&mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0) {
		perror("pthread_setaffinity_np");
	}
        struct timeval initwr;
	int fd;
	char capture_dirname[MAX_LINE];
	uint32_t timestamp_last_dir=0;
 	uint64_t written=0; 
	int __attribute__((unused)) ret;

	int j;
	for(j=0;j<num_interfaces;j++)
	{
		/* Creating HPCAP handle */
		int qindex=0;//SINGLE QUEUE
		int ret = hpcap_open(&hp_dt[j], interfaces[j], qindex);
		if( ret != HPCAP_OK )
		{
		        printf("Error when opening the HPCAP handle hpcap%u j:%u\n",interfaces[j],j);
		        exit(HPCAP_ERR);
		}
		/* Map device's memory */
		ret = hpcap_map(&hp_dt[j]);
		if( ret != HPCAP_OK )
		{
		        printf("Error when opening the mapping HPCAP memory\n");
		        hpcap_close(&hp_dt[j]);
		        exit(HPCAP_ERR);
		}
	}

	if( ( hp_dt[0].bufoff == 0 ) && ( num_interfaces == 1 ) )
		printf("Write performance will be optimal\n");
	else
		printf("Write performance will NOT be optimal\n");
	
	while(!stop_dt){
		gettimeofday(&initwr, NULL);

		printf("Directory checks...\n");
		if(initwr.tv_sec>timestamp_last_dir+capture_dir_duration){
			//new directory
			sprintf(capture_dirname,"%s/%lu",capturedir,initwr.tv_sec);
			mkdir(capture_dirname, 0777);
			ret = chown(capture_dirname,pwd->pw_uid,pwd->pw_gid);
			timestamp_last_dir=initwr.tv_sec;
		}
		sprintf(capture_filename,"%s/%lu%s.raw",capture_dirname,initwr.tv_sec,bonding_name);
		/* Opening output file */
		printf("[%s] %lu\n", capture_filename, written);
		if( hp_dt[0].bufoff == 0 )
			fd = open(capture_filename, O_RDWR|O_TRUNC|O_CREAT|O_DIRECT|O_SYNC, 00666);
		else
			fd = open(capture_filename, O_RDWR|O_TRUNC|O_CREAT, 00666);
		if( fd == -1 )
		{
			printf("Error when opening output file\n");
			return NULL;
		}
		ret = chown(capture_filename,pwd->pw_uid,pwd->pw_gid);

		if(num_interfaces==1)
		{
			written=0;
		        while( !(stop_dt) && ( written < HPCAP_FILESIZE) )
		        {
		                /* acumular para escribir un bloque */
				hpcap_ack_wait_timeout( &hp_dt[0], HPCAP_BS ,5000000000ULL);
				if( hp_dt[0].avail >= HPCAP_BS )
					written += hpcap_write_block( &hp_dt[0], fd, HPCAP_FILESIZE-written);
				if( hp_dt[0].acks > hp_dt[0].avail )
					printf("Se asiente más de la cuenta en DT: acks=%lu, avail=%lu\n", hp_dt[0].acks, hp_dt[0].avail);
		        }
		        hpcap_ack( &hp_dt[0]);
		}
		close(fd);
	}
	printf("exiting DT (before unmap)\n");
	for(j=0;j<num_interfaces;j++){
		hpcap_unmap(hp_dt+j);
		hpcap_close(hp_dt+j);
	}
	printf("exiting DT (after unmap)\n");
	return NULL;
}

void* processThread(void *par)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(affinity_process,&mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0) {
		perror("pthread_setaffinity_np");
	}
 
	struct pcap_pkthdr hcap[MAX_INTERFACES];
	u_char buff_payload[MAX_INTERFACES][MAX_PACKET_SIZE];
	uint64_t tstamp[MAX_INTERFACES];
	u_char* bp[MAX_INTERFACES]={NULL};
	//uint32_t acks[MAX_INTERFACES]={0},avail[MAX_INTERFACES]={0},offset[MAX_INTERFACES]={0};
	
	uint64_t timeout = 5000000000ULL;
	mrtg stat;
	int mrtg_sock=0;
        struct sockaddr_in mrtgAddr;


	mrtg_sock = open_multicast_tx_socket( MCAST_MRTG, interfaces[0], 0, &mrtgAddr);
        if( mrtg_sock == 0 )
        {
                perror("Create multicast sockets");
        }

	int j;
	for(j=0;j<num_interfaces;j++)
	{
		/* Creating HPCAP handle */
		int qindex=0;//SINGLE QUEUE
		int ret = hpcap_open(&hp_pt[j], interfaces[j], qindex);
		if( ret != HPCAP_OK )
		{
		        printf("Error when opening the HPCAP handle hpcap%u j:%u\n",interfaces[j],j);
		        exit(HPCAP_ERR);
		}
		/* Map device's memory */
		ret = hpcap_map(&hp_pt[j]);
		if( ret != HPCAP_OK )
		{
		        printf("Error when opening the mapping HPCAP memory\n");
		        hpcap_close(&hp_pt[j]);
		        exit(HPCAP_ERR);
		}
	}
	while(!stop_pt){
		uint64_t min_ts=INFINITO;
		int min_j=-1;
		for(j=0;j<num_interfaces;j++)
		{
			if( bp[j] == NULL )
			{
				if( hp_pt[j].acks > hp_pt[j].avail )
					printf("Se asiente más de la cuenta en PT: acks=%lu, avail=%lu\n", hp_pt[j].acks, hp_pt[j].avail);
				if( hp_pt[j].acks == hp_pt[j].avail )
				{
					//no hay paquetes a leer
					hpcap_ack_wait_timeout(&hp_pt[j],1,timeout);
				}
				if( hp_pt[j].acks < hp_pt[j].avail )
				{
					tstamp[j] = hpcap_read_packet(&hp_pt[j], &bp[j], buff_payload[j], &hcap[j], hpcap_pcap_header);
				}
			}
			if(bp[j] != NULL)
			{
				if( tstamp[j] < min_ts )
				{
					min_ts = tstamp[j];
					min_j = j;
				}
			}
		}
		if( min_j != -1 )
		{
			process_packet(bp[min_j],&hcap[min_j], &stat, mrtg_sock, &mrtgAddr);
			bp[min_j] = NULL;
		}
		else{
			//no hay paquetes
			//printf("acks:%u avail:%u min_j:%u\n",acks[0],avail[0],min_j);
			struct timeval tv;
			u_char blank[MTU]={0};
			
			gettimeofday(&tv,NULL);
			hcap[0].ts.tv_sec=tv.tv_sec;
			hcap[0].ts.tv_usec=tv.tv_usec;
			hcap[0].caplen=0;
			hcap[0].len=0;
			//force ro process empty packet for timeouts and other stuff
			process_packet(blank,&hcap[0], &stat, mrtg_sock,&mrtgAddr);
		}

	}
	printf("exiting PT (before unmap)\n");
	for(j=0;j<num_interfaces;j++)
	{
		hpcap_ack( &hp_pt[j] );
		hpcap_unmap( &hp_pt[j] );
		hpcap_close( &hp_pt[j] );
	}
	printf("exiting PT (after unmap)\n");
	return NULL;
}


int main (int argc, char *argv[])
{
	char filename[MAX_LINE];
	cpu_set_t mask;
	sigset_t sigmask;
	int sig_caught; 
	int __attribute__((unused)) ret;

        if(read_global_cfg("../global.cfg", datadir,capturedir,lecturadir,flowsdir,interfaz,
		&capture_duration,
		&affinity_dump,&affinity_process,&affinity_export,&affinity_main,
		&capture_dir_duration) ==- 1 )
	{
		printf("error leyendo global.cfg\n");
		return -1;
	}
	get_interfaces();
	
	/* We want the allocated memmory ti be placed on process thread's NUMA node*/
	CPU_ZERO(&mask);
	CPU_SET(affinity_process,&mask);
	main_thread=pthread_self();
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0)
		perror("pthread_setaffinity_np");

        //set perms
        umask(0447);
        //obtain uid and gid of user web
        pwd=getpwnam("naudit");
        if(pwd==NULL)
	{
                printf("El usuario de la web %s no existe en el sistema\n","naudit");
                return -1;
        }

        //set perms to data/capture directories 
        sprintf(filename,"%s",datadir);
        ret = chown(filename,pwd->pw_uid,pwd->pw_gid);
        sprintf(filename,"%s",capturedir);
        ret = chown(filename,pwd->pw_uid,pwd->pw_gid);
	printf("configuracion global leida\n");

	printf("reservando pool de memoria...\n");
	allocIPSessionPool();//pool de nodos
	allocNodelPool();
	printf("pool de memoria reservado\n");


	printf("Affinities: export %d, dump %d, process %d\n", affinity_export, affinity_dump, affinity_process);
	if( affinity_export != -1 )
		pthread_create(&idHiloExport, NULL, exportThread, NULL);
	if( affinity_dump != -1 )
		pthread_create(&idHiloCapture,NULL,dumpThread,NULL);
	if( affinity_process != -1 )
		pthread_create(&idHiloProcess,NULL,processThread,NULL);

	/* Once everything is set, we can set any affinity to the main process */
	CPU_ZERO(&mask);
	CPU_SET(affinity_main,&mask);
	main_thread=pthread_self();
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),&mask) <0)
		perror("pthread_setaffinity_np");
	
	/* Create a mask holding only SIGINT - ^C Interrupt */
	sigemptyset( & sigmask );
	sigaddset( & sigmask, SIGINT );

	/* Set the mask for our main thread to include SIGINT */

	pthread_sigmask( SIG_BLOCK, & sigmask, NULL );
	sigwait (&sigmask, &sig_caught);
	switch (sig_caught)
    	{
		case SIGINT:
			capturaSenial(SIGINT);
		case SIGKILL:
			capturaSenial(SIGKILL);
	}
        return 0;
}


