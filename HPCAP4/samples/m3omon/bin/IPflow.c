#include "IPflow.h"
#include "list.h"
#include "monitor.h"
#define TCP_PROTO 6

#define hashsize(n) ((u_int32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define us2s(x) (double)(x)/1000000


#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))


//#define NO_FLAG_EXPIRATION

extern u_int32_t dead_flows;
extern u_int32_t created_flows;

//PRUEBAS PAYLOAD
u_char padding[MAX_PAYLOAD];

u_int32_t used_session;
u_int32_t free_session;
u_int32_t active_session;
u_int32_t expired_session;

int num_flags;

IPSession *aux_session=NULL;

extern pthread_t main_thread;

#if 0
extern net *networks;
extern u_int16_t n_networks;
#endif

u_int32_t capturado;
extern node_l *flow_table[MAX_FLOWS_TABLE_SIZE];
extern node_l *active_flow_list;
extern node_l *expired_flow_list;
extern node_l *flags_expired_flow_list;
extern u_int32_t expired_flows;
extern u_int32_t active_flows;
extern u_int32_t in_expired_list_flows;
extern pthread_mutex_t sem_expired_list;

u_int32_t max_payload=MAX_PAYLOAD;
u_int64_t max_pack=10;

u_int64_t last_packet_timestamp=0;

u_int64_t expiration_flow_time=EXPIRATION_FLOW_TIME;
u_int64_t expiration_flag_time=0;
fp_export_session export;

u_int64_t total_sessions;
u_int64_t expirados_al_insertar;

int contador = 0;
u_int64_t packts_ACK_descartados;


node_l static_node;

node_l *ip_session_pool_free=NULL;
node_l *ip_session_pool_used=NULL;

//#########################################################
// Frag. packets
node_l *frag_table[MAX_FRAG_PACKETS_TABLE_SIZE]; // Table for frag packets
// Flag for fragment packets
u_int8_t frag_packets_flag;

int packt_frag_dep=0;
pthread_mutex_t sem_frag = PTHREAD_MUTEX_INITIALIZER;
//#########################################################
//#########################################################
node_l *nodel_aux;

u_int32_t ip_length;
u_int32_t tcp_length;
u_int64_t lll=0;

IPSession *ips;


pthread_mutex_t sem_pool_session = PTHREAD_MUTEX_INITIALIZER;

void allocIPSessionPool(void)
{

	int i=0;
	node_l *n=NULL;
	ips=calloc(MAX_POOL_FLOW,sizeof(IPSession));
	assert(ips!=NULL);
	bzero(ips,MAX_POOL_FLOW*sizeof(IPSession));
	for(i=0;i<MAX_POOL_FLOW;i++)
	{
		n=list_alloc_node(ips+i);
		list_prepend_node(&ip_session_pool_free,n);
	}
	used_session=0;
	free_session=MAX_POOL_FLOW;

}

IPSession * getIPSession(void)
{
	//printf("getIPSession!\n");
	pthread_mutex_lock(&sem_pool_session);

	node_l *n=list_pop_first_node(&ip_session_pool_free);

	if(ip_session_pool_free==NULL)
	{	fprintf(stderr,"pool Flujos vacío\n");
		pthread_kill(main_thread,SIGINT);
	}
	list_append_node(&ip_session_pool_used,n);


	used_session++;
	free_session--;

	pthread_mutex_unlock(&sem_pool_session);


	return  (n->data);

}

void releaseIPSession(IPSession * f)
{

	//printf("releaseIPSession!\n");
	pthread_mutex_lock(&sem_pool_session);

	node_l *n=list_pop_first_node(&ip_session_pool_used);
	n->data=(void*)f;
	list_append_node(&ip_session_pool_free,n);

	used_session--;
	free_session++;

	pthread_mutex_unlock(&sem_pool_session);
}

void freeIPSessionPool(void)
{
	node_l *n=NULL;
	while(ip_session_pool_free!=NULL)
	{
		n=list_pop_first_node(&ip_session_pool_free);
		free(n);
	}

	while(ip_session_pool_used!=NULL)
	{
		n=list_pop_first_node(&ip_session_pool_used);
		free(n);
	}
	free(ips);
}

inline char* itoa(int value, char* result, int base) {
	// check that the base if valid
	if (base < 2 || base > 36) { *result = '\0'; return result; }

	char* ptr = result, *ptr1 = result, tmp_char;
	int tmp_value;

	do {
		tmp_value = value;
		value /= base;
		*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
	} while ( value );

	// Apply negative sign
	if (tmp_value < 0) *ptr++ = '-';
	*ptr-- = '\0';
	while(ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr--= *ptr1;
		*ptr1++ = tmp_char;
	}
	return result;
}


void printTupleFilePayloadText (IPSession *session, FILE* f)
{
	u_char *l,*l2,*l3,*l4;
	l = (u_char*)(&(session->incoming.source_ip));
	l2 = (u_char*)(&(session->incoming.destination_ip));
	l3 = (u_char*)(&(session->incoming.source_mac));
	l4 = (u_char*)(&(session->incoming.destination_mac));
	u_int64_t duration=session->lastpacket_timestamp/1000000-session->firstpacket_timestamp/1000000+1;
	double avg_int_time=0,std_int_time=0,avg_pack_size=0,std_pack_size=0;
	avg_pack_size=(double)session->incoming.nbytes/session->incoming.npack;
	if(session->incoming.npack>1)
		std_pack_size=sqrt((double)session->incoming.nbytes_sqr/(session->incoming.npack-1)-avg_pack_size*avg_pack_size*session->incoming.npack/(session->incoming.npack-1));
	if(session->incoming.npack==2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=0;
	}
	if(session->incoming.npack>2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=sqrt(session->incoming.sum_int_time_sqr/(session->incoming.npack-2)-avg_int_time*avg_int_time*(session->incoming.npack-1)/(session->incoming.npack-2));
	}
//printf("%lu %lu.%06lu %u\n",session->incoming.rtt_syn,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.npack);
	int i,j=0;
	char client_payload[MAX_PAYLOAD*4+1];

	for(i=0;i<MAX_PAYLOAD;i++){
		if(i>=session->incoming.offset)
			break;
		if(session->incoming.payload[i]>31 && session->incoming.payload[i]<=126){
			client_payload[j]=session->incoming.payload[i];
			j++;
		}
		else{
			sprintf(client_payload+j,"\\x%.2X",session->incoming.payload[i]);
			//client_payload[j]='\\';
			//client_payload[j+1]='x';
			//itoa(session->incoming.payload[i],client_payload+j+2,16);
			j+=4;
		}
	}
	client_payload[j]=0;


/*	int j=0;
	client_payload[0]=0;
	for(i=0;i<MAX_PAYLOAD;i++){
		if(i>=session->incoming.offset)
			break;
		sprintf(client_payload+j,"\\X%.2X",session->incoming.payload[i]);
		j+=4;
	}
	client_payload[j]=0;
*/
	fprintf(f,"%u.%u.%u.%u ,%u.%u.%u.%u , %02X:%02X:%02X:%02X:%02X:%02X ,%02X:%02X:%02X:%02X:%02X:%02X ,p%u,%u,%u,%u,%lu,%lu.%06lu,%lu.%06lu,%lu,%f,%f,%u,%u,%f,%f,%f,%f,%f,%f,%lu.%06lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%s\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,(double)session->incoming.npack/duration,(double)session->incoming.nbytes/duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.size[0],session->incoming.size[1],session->incoming.size[2],session->incoming.size[3],session->incoming.size[4],session->incoming.size[5],session->incoming.size[6],session->incoming.size[7],session->incoming.size[8],session->incoming.size[9],session->incoming.timestamp[0]/1000000,session->incoming.timestamp[0]%1000000,session->incoming.timestamp[1]/1000000,session->incoming.timestamp[1]%1000000,session->incoming.timestamp[2]/1000000,session->incoming.timestamp[2]%1000000,session->incoming.timestamp[3]/1000000,session->incoming.timestamp[3]%1000000,session->incoming.timestamp[4]/1000000,session->incoming.timestamp[4]%1000000,session->incoming.timestamp[5]/1000000,session->incoming.timestamp[5]%1000000,session->incoming.timestamp[6]/1000000,session->incoming.timestamp[6]%1000000,session->incoming.timestamp[7]/1000000,session->incoming.timestamp[7]%1000000,session->incoming.timestamp[8]/1000000,session->incoming.timestamp[8]%1000000,session->incoming.timestamp[9]/1000000,session->incoming.timestamp[9]%1000000,client_payload);
//fprintf(f,"%u.%u.%u.%u ,%u.%u.%u.%u , %02X:%02X:%02X:%02X:%02X:%02X ,%02X:%02X:%02X:%02X:%02X:%02X ,p%u,%u,%u,%u,%lu,%lu.%06lu,%lu.%06lu,%lu,%f,%f,%u,%u,%f,%f,%f,%f,%f,%f,%lu.%06lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,(double)session->incoming.npack/duration,(double)session->incoming.nbytes/duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.size[0],session->incoming.size[1],session->incoming.size[2],session->incoming.size[3],session->incoming.size[4],session->incoming.size[5],session->incoming.size[6],session->incoming.size[7],session->incoming.size[8],session->incoming.size[9],session->incoming.timestamp[0]/1000000,session->incoming.timestamp[0]%1000000,session->incoming.timestamp[1]/1000000,session->incoming.timestamp[1]%1000000,session->incoming.timestamp[2]/1000000,session->incoming.timestamp[2]%1000000,session->incoming.timestamp[3]/1000000,session->incoming.timestamp[3]%1000000,session->incoming.timestamp[4]/1000000,session->incoming.timestamp[4]%1000000,session->incoming.timestamp[5]/1000000,session->incoming.timestamp[5]%1000000,session->incoming.timestamp[6]/1000000,session->incoming.timestamp[6]%1000000,session->incoming.timestamp[7]/1000000,session->incoming.timestamp[7]%1000000,session->incoming.timestamp[8]/1000000,session->incoming.timestamp[8]%1000000,session->incoming.timestamp[9]/1000000,session->incoming.timestamp[9]%1000000);
	//fflush(f);

}

void printTupleFileTextAndBin (IPSession *session,FILE* f_txt,FILE *f_bin,u_int64_t *offset_bin)
{
	u_char *l,*l2,*l3,*l4;
	l = (u_char*)(&(session->incoming.source_ip));
	l2 = (u_char*)(&(session->incoming.destination_ip));
	l3 = (u_char*)(&(session->incoming.source_mac));
	l4 = (u_char*)(&(session->incoming.destination_mac));
	u_int64_t duration=session->lastpacket_timestamp/1000000-session->firstpacket_timestamp/1000000+1;
	double avg_int_time=0,std_int_time=0,avg_pack_size=0,std_pack_size=0;
	avg_pack_size=(double)session->incoming.nbytes/session->incoming.npack;
	if(session->incoming.npack>1)
		std_pack_size=sqrt((double)session->incoming.nbytes_sqr/(session->incoming.npack-1)-avg_pack_size*avg_pack_size*session->incoming.npack/(session->incoming.npack-1));
	if(session->incoming.npack==2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=0;
	}
	if(session->incoming.npack>2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=sqrt(session->incoming.sum_int_time_sqr/(session->incoming.npack-2)-avg_int_time*avg_int_time*(session->incoming.npack-1)/(session->incoming.npack-2));
	}

	fprintf(f_txt,"%u.%u.%u.%u %u.%u.%u.%u %02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X p%u %u %u %u %lu %lu.%06lu %lu.%06lu %lu %u %u %f %f %f %f %f %f %lu.%06lu %u %u %u %u %u %u %u %u %u %u %lu\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.nwindow_zero,session->incoming.offset,*offset_bin);
	if(session->incoming.offset>0){
//	fprintf(f_txt,"%u.%u.%u.%u %u.%u.%u.%u %02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X p%u %u %u %u %lu %lu.%06lu %lu.%06lu %lu %f %f %u %u %f %f %f %f %f %f %lu.%06lu %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %lu.%06lu %u %lu\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,(double)session->incoming.npack/duration,(double)session->incoming.nbytes/duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.size[0],session->incoming.size[1],session->incoming.size[2],session->incoming.size[3],session->incoming.size[4],session->incoming.size[5],session->incoming.size[6],session->incoming.size[7],session->incoming.size[8],session->incoming.size[9],session->incoming.timestamp[0]/1000000,session->incoming.timestamp[0]%1000000,session->incoming.timestamp[1]/1000000,session->incoming.timestamp[1]%1000000,session->incoming.timestamp[2]/1000000,session->incoming.timestamp[2]%1000000,session->incoming.timestamp[3]/1000000,session->incoming.timestamp[3]%1000000,session->incoming.timestamp[4]/1000000,session->incoming.timestamp[4]%1000000,session->incoming.timestamp[5]/1000000,session->incoming.timestamp[5]%1000000,session->incoming.timestamp[6]/1000000,session->incoming.timestamp[6]%1000000,session->incoming.timestamp[7]/1000000,session->incoming.timestamp[7]%1000000,session->incoming.timestamp[8]/1000000,session->incoming.timestamp[8]%1000000,session->incoming.timestamp[9]/1000000,session->incoming.timestamp[9]%1000000,session->incoming.offset,*offset_bin);
		fwrite(session->incoming.payload,1,session->incoming.offset,f_bin);
		*offset_bin+=session->incoming.offset;
	}
	
}

void printTupleFilePayloadBin (IPSession *session, FILE* f)
{
	u_char *l,*l2,*l3,*l4;
	l = (u_char*)(&(session->incoming.source_ip));
	l2 = (u_char*)(&(session->incoming.destination_ip));
	l3 = (u_char*)(&(session->incoming.source_mac));
	l4 = (u_char*)(&(session->incoming.destination_mac));
	u_int64_t duration=session->lastpacket_timestamp/1000000-session->firstpacket_timestamp/1000000+1;
	double avg_int_time=0,std_int_time=0,avg_pack_size=0,std_pack_size=0;
	avg_pack_size=(double)session->incoming.nbytes/session->incoming.npack;
	if(session->incoming.npack>1)
		std_pack_size=sqrt((double)session->incoming.nbytes_sqr/(session->incoming.npack-1)-avg_pack_size*avg_pack_size*session->incoming.npack/(session->incoming.npack-1));
	if(session->incoming.npack==2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=0;
	}
	if(session->incoming.npack>2){
		avg_int_time=session->incoming.sum_int_time/(session->incoming.npack-1);
		std_int_time=sqrt(session->incoming.sum_int_time_sqr/(session->incoming.npack-2)-avg_int_time*avg_int_time*(session->incoming.npack-1)/(session->incoming.npack-2));
	}
//printf("%lu %lu.%06lu %u\n",session->incoming.rtt_syn,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.npack);
/*	int i,j=0;
	char client_payload[MAX_PAYLOAD*4+1];

	for(i=0;i<MAX_PAYLOAD;i++){
		if(i>=session->incoming.offset)
			break;
		if(session->incoming.payload[i]>31 && session->incoming.payload[i]<=126){
			client_payload[j]=session->incoming.payload[i];
			j++;
		}
		else{
			sprintf(client_payload+j,"\\x%.2X",session->incoming.payload[i]);
			//client_payload[j]='\\';
			//client_payload[j+1]='x';
			//itoa(session->incoming.payload[i],client_payload+j+2,16);
			j+=4;
		}
	}
	client_payload[j]=0;
*/

/*	int j=0;
	client_payload[0]=0;
	for(i=0;i<MAX_PAYLOAD;i++){
		if(i>=session->incoming.offset)
			break;
		sprintf(client_payload+j,"\\X%.2X",session->incoming.payload[i]);
		j+=4;
	}
	client_payload[j]=0;
*/
	fprintf(f,"%u.%u.%u.%u ,%u.%u.%u.%u , %02X:%02X:%02X:%02X:%02X:%02X ,%02X:%02X:%02X:%02X:%02X:%02X ,p%u,%u,%u,%u,%lu,%lu.%06lu,%lu.%06lu,%lu,%f,%f,%u,%u,%f,%f,%f,%f,%f,%f,%lu.%06lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%u\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,(double)session->incoming.npack/duration,(double)session->incoming.nbytes/duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.size[0],session->incoming.size[1],session->incoming.size[2],session->incoming.size[3],session->incoming.size[4],session->incoming.size[5],session->incoming.size[6],session->incoming.size[7],session->incoming.size[8],session->incoming.size[9],session->incoming.timestamp[0]/1000000,session->incoming.timestamp[0]%1000000,session->incoming.timestamp[1]/1000000,session->incoming.timestamp[1]%1000000,session->incoming.timestamp[2]/1000000,session->incoming.timestamp[2]%1000000,session->incoming.timestamp[3]/1000000,session->incoming.timestamp[3]%1000000,session->incoming.timestamp[4]/1000000,session->incoming.timestamp[4]%1000000,session->incoming.timestamp[5]/1000000,session->incoming.timestamp[5]%1000000,session->incoming.timestamp[6]/1000000,session->incoming.timestamp[6]%1000000,session->incoming.timestamp[7]/1000000,session->incoming.timestamp[7]%1000000,session->incoming.timestamp[8]/1000000,session->incoming.timestamp[8]%1000000,session->incoming.timestamp[9]/1000000,session->incoming.timestamp[9]%1000000,session->incoming.offset);
	//char cadena[100000];
	//sprintf(cadena,"%u.%u.%u.%u ,%u.%u.%u.%u , %02X:%02X:%02X:%02X:%02X:%02X ,%02X:%02X:%02X:%02X:%02X:%02X ,p%u,%u,%u,%u,%lu,%lu.%06lu,%lu.%06lu,%lu,%f,%f,%u,%u,%f,%f,%f,%f,%f,%f,%lu.%06lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%lu.%06lu,%u\n", l[3], l[2], l[1], l[0],l2[3], l2[2], l2[1], l2[0], l3[0],l3[1],l3[2],l3[3],l3[4],l3[5],l4[0],l4[1],l4[2],l4[3],l4[4],l4[5],session->incoming.transport_protocol,session->incoming.source_port,session->incoming.destination_port,session->incoming.npack,session->incoming.nbytes,session->firstpacket_timestamp/1000000,session->firstpacket_timestamp%1000000,session->lastpacket_timestamp/1000000,session->lastpacket_timestamp%1000000,duration,(double)session->incoming.npack/duration,(double)session->incoming.nbytes/duration,session->incoming.max_pack_size,session->incoming.min_pack_size,avg_pack_size,std_pack_size,session->incoming.max_int_time,session->incoming.min_int_time,avg_int_time,std_int_time,session->incoming.rtt_syn/1000000,session->incoming.rtt_syn%1000000,session->incoming.num_flags[0],session->incoming.num_flags[1],session->incoming.num_flags[2],session->incoming.num_flags[3],session->incoming.num_flags[4],session->incoming.num_flags[5],session->incoming.num_flags[6],session->incoming.num_flags[7],session->incoming.size[0],session->incoming.size[1],session->incoming.size[2],session->incoming.size[3],session->incoming.size[4],session->incoming.size[5],session->incoming.size[6],session->incoming.size[7],session->incoming.size[8],session->incoming.size[9],session->incoming.timestamp[0]/1000000,session->incoming.timestamp[0]%1000000,session->incoming.timestamp[1]/1000000,session->incoming.timestamp[1]%1000000,session->incoming.timestamp[2]/1000000,session->incoming.timestamp[2]%1000000,session->incoming.timestamp[3]/1000000,session->incoming.timestamp[3]%1000000,session->incoming.timestamp[4]/1000000,session->incoming.timestamp[4]%1000000,session->incoming.timestamp[5]/1000000,session->incoming.timestamp[5]%1000000,session->incoming.timestamp[6]/1000000,session->incoming.timestamp[6]%1000000,session->incoming.timestamp[7]/1000000,session->incoming.timestamp[7]%1000000,session->incoming.timestamp[8]/1000000,session->incoming.timestamp[8]%1000000,session->incoming.timestamp[9]/1000000,session->incoming.timestamp[9]%1000000,session->incoming.offset);
	if(session->incoming.offset>0)
		fwrite(session->incoming.payload,1,session->incoming.offset,f);
	fflush(f);

}



/*******************************************************
*
*  This function compares the tuples of two different IP_flows
*  returns 0 if they are equal and other thing if they are
*  different
*
********************************************************/
int compareTupleFlow(void *a, void *b)
{
	if(	(((IPSession*)a)->incoming.source_ip == ((IPSession*)b)->incoming.source_ip) &&
		(((IPSession*)a)->incoming.destination_ip == ((IPSession*)b)->incoming.destination_ip) &&
		(((IPSession*)a)->incoming.source_port == ((IPSession*)b)->incoming.source_port) &&
		(((IPSession*)a)->incoming.destination_port == ((IPSession*)b)->incoming.destination_port) &&
		(((IPSession*)a)->incoming.transport_protocol == ((IPSession*)b)->incoming.transport_protocol)
	)
	{
		((IPSession*)b)->actual_flow=&(((IPSession*)b)->incoming);
		return 0;
	}
	
	return 1;
}

int compareTupleFlowList(void *a, void *b)
{
	IPSession *aa=((node_l*)a)->data;
	IPSession *bb=((node_l*)b)->data;

	if( 	(((IPSession*)aa)->incoming.source_ip == ((IPSession*)bb)->incoming.source_ip) &&
		(((IPSession*)aa)->incoming.destination_ip == ((IPSession*)bb)->incoming.destination_ip) &&
		(((IPSession*)aa)->incoming.source_port == ((IPSession*)bb)->incoming.source_port) &&
		(((IPSession*)aa)->incoming.destination_port == ((IPSession*)bb)->incoming.destination_port) &&
		(((IPSession*)aa)->incoming.transport_protocol == ((IPSession*)bb)->incoming.transport_protocol) 
	)
	{
		((IPSession*)bb)->actual_flow=&(((IPSession*)bb)->incoming);
		return 0;
	}
	
	return 1;
}


int compareTupleSession(void *a, void *b)
{

	if(	(((IPSession*)a)->incoming.source_ip == ((IPSession*)b)->incoming.source_ip) &&
		(((IPSession*)a)->incoming.destination_ip == ((IPSession*)b)->incoming.destination_ip) &&
		(((IPSession*)a)->incoming.source_port == ((IPSession*)b)->incoming.source_port) &&
		(((IPSession*)a)->incoming.destination_port == ((IPSession*)b)->incoming.destination_port) &&
		(((IPSession*)a)->incoming.transport_protocol == ((IPSession*)b)->incoming.transport_protocol)
	)
	{	
	  	((IPSession*)b)->actual_flow=&(((IPSession*)b)->incoming);
	  	return 0;
  	}
	else if(   	(((IPSession*)a)->incoming.source_ip == ((IPSession*)b)->outgoing.source_ip) &&
			(((IPSession*)a)->incoming.destination_ip == ((IPSession*)b)->outgoing.destination_ip) &&
			(((IPSession*)a)->incoming.source_port == ((IPSession*)b)->outgoing.source_port) &&
			(((IPSession*)a)->incoming.destination_port == ((IPSession*)b)->outgoing.destination_port) &&
			(((IPSession*)a)->incoming.transport_protocol == ((IPSession*)b)->outgoing.transport_protocol)
	)
	{
		  ((IPSession*)b)->actual_flow=&(((IPSession*)b)->outgoing);
  	  	  return 0;
	}

	return 1;

}

IPSession *insertFlowTable(IPSession *aux_session,IPFlow *new_flow,int index)
{

	node_l *new_active_node = NULL;
	node_l *naux = NULL;

	node_l *list=flow_table[index];

	new_flow->previous_timestamp=last_packet_timestamp;
	/*If flow is not in the list, insert it*/
	new_flow->previous_seq_number=new_flow->current_seq_number+new_flow->dataLen;

	new_flow->size[0] = new_flow->nbytes;
	new_flow->packet_offset[0] = new_flow->offset;
	new_flow->timestamp[0] = last_packet_timestamp;
	aux_session->lastpacket_timestamp= last_packet_timestamp;
	aux_session->firstpacket_timestamp= last_packet_timestamp; 
	aux_session->exportation_timestamp= 0;

	new_flow->max_pack_size=new_flow->nbytes;
	new_flow->min_pack_size=new_flow->nbytes;
	new_flow->nbytes_sqr=new_flow->nbytes*new_flow->nbytes;

	new_flow->max_int_time=0;
	new_flow->min_int_time=0;
	new_flow->sum_int_time=0;
	new_flow->sum_int_time_sqr=0;

	int i;
	for(i=0;i<8;i++){
		if((new_flow->flags>>i)%2==1)
			new_flow->num_flags[i]=1;
		else
			new_flow->num_flags[i]=0;
	}


	new_flow->rtt_syn_done=0;
	if(((new_flow->flags>>1)%2)==1){//SYN
		new_flow->rtt_syn=last_packet_timestamp;
	}
	else{
		new_flow->rtt_syn=0;
		new_flow->rtt_syn_done=1;
	}
	u_int8_t*aux=new_flow->payload_ptr;

	if(aux)
	{
		if (max_payload > new_flow->dataLen)
		{
			  //printf("new_flow->offset:%u,new_flow->dataLen:%u,%lu.%06lu,%u,%u,%u\n",new_flow->offset,new_flow->dataLen,last_packet_timestamp/1000000,last_packet_timestamp%1000000,new_flow->source_port,new_flow->destination_port,new_flow->transport_protocol);
			memcpy (new_flow->payload, aux, new_flow->dataLen * sizeof (u_int8_t));
			new_flow->offset=new_flow->dataLen;
		}
		else
		{
			memcpy (new_flow->payload, aux, max_payload * sizeof (u_int8_t));
			new_flow->offset=max_payload;
		}
	}
	new_flow->npack_payload=1;

	
	aux_session->actual_flow=&(aux_session->incoming);	

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Frag. packets
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	if (frag_packets_flag)
	{
		aux_session->actual_flow->frag_flag=1;
		aux_session->actual_flow->ip_id=new_flow->ip_id;
		insertPointer_frag(aux_session->actual_flow);
		frag_packets_flag=0;
	}

	else aux_session->actual_flow->frag_flag=0;

	if(getNodel()==-1)
		pthread_kill(main_thread,SIGINT);

	naux=nodel_aux;
	naux->data=(aux_session);
	list_prepend_node(&list,naux);
	flow_table[index]=list;  //asignamos por si ha cambiado la cabeza

	if(getNodel()==-1)
		pthread_kill(main_thread,SIGINT);

	new_active_node=nodel_aux;
	new_active_node->data=naux;
	list_prepend_node(&active_flow_list,new_active_node);
	aux_session->active_node=new_active_node;

#ifdef NO_FLAGS_EXPIRATION

#else
	if((aux_session->actual_flow->flag_FIN)>1)
	{
		//node_l *n=list_search(&flags_expired_flow_list,aux_session->active_node,compareTupleFlowList);
//		if(n==NULL)
		if(aux_session->actual_flow->expired_by_flags==0)
		{	
			//list_unlink(&(flow_table[index]),(aux_session->active_node)->data);//sacamos de la tabla hash
			//releaseNodel((aux_session->active_node)->data);
			list_unlink(&active_flow_list,aux_session->active_node);//sacamos de la lista de activos
			//(aux_session->active_node)->data=aux_session;//apuntamos directamente a la estructura
			list_append_node(&flags_expired_flow_list,aux_session->active_node);//insertamos en la lista de expirados por banderas
			//expired_session++;//vj
			//active_session--;//vj
			//num_expired++;//vj
			aux_session->actual_flow->expired_by_flags=1;
			num_flags++;
			//printf("%p\n",(aux_session->active_node)->data);
		        //int k;
		        //for(k=0;k<n_networks;k++){
	                	//actualizamos contadores entrada
	                //	if((aux_session->network_membership_IN>>networks[k].netID)%2==1)
        		//                networks[k].concurrent_flows_IN--;
        	        	//actualizamos contadores salida
		        //        else if((aux_session->network_membership_OUT>>networks[k].netID)%2==1)
        	        //	        networks[k].concurrent_flows_OUT--;
	        	//}
		}

	}
#endif

	return NULL;
}

inline void updateFlowTable(IPSession *current_session,IPFlow *new_flow,node_l* current_node,u_int32_t index){

	int num_packets = current_session->actual_flow->npack;
	if(new_flow->nbytes>current_session->actual_flow->max_pack_size)
		current_session->actual_flow->max_pack_size=new_flow->nbytes;
	if(new_flow->nbytes<current_session->actual_flow->min_pack_size)
		current_session->actual_flow->min_pack_size=new_flow->nbytes;
	current_session->actual_flow->nbytes_sqr+=new_flow->nbytes*new_flow->nbytes;
	if(current_session->actual_flow->rtt_syn_done==0){
		current_session->actual_flow->rtt_syn=last_packet_timestamp-current_session->actual_flow->rtt_syn;
		current_session->actual_flow->rtt_syn_done=1;
	}

	if(current_session->actual_flow->npack==1){
	//if(current_session->actual_flow->max_int_time==0){//2nd packet
		current_session->actual_flow->max_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		current_session->actual_flow->min_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		current_session->actual_flow->sum_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		current_session->actual_flow->sum_int_time_sqr=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp)*us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
	}
	else{//remaining packets
		if(current_session->actual_flow->max_int_time<us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp))
			current_session->actual_flow->max_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		if(current_session->actual_flow->min_int_time>us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp))
			current_session->actual_flow->min_int_time=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		current_session->actual_flow->sum_int_time+=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
		current_session->actual_flow->sum_int_time_sqr+=us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp)*us2s(last_packet_timestamp-current_session->actual_flow->previous_timestamp);
	}	


	current_session->actual_flow->previous_timestamp=last_packet_timestamp;

	int i;
	for(i=0;i<8;i++){
		if((new_flow->flags>>i)%2==1)
			current_session->actual_flow->num_flags[i]++;
	}
	
	current_session->actual_flow->nwindow_zero+=new_flow->nwindow_zero;


	u_int16_t copySize=0;
	if(current_session->actual_flow->flag_FIN==0)
		(current_session->actual_flow->flag_FIN)+=(new_flow->flag_FIN);


	(current_session->actual_flow->nbytes) += new_flow->nbytes;
	
	current_session->actual_flow->previous_seq_number=new_flow->current_seq_number+new_flow->dataLen;


	if(new_flow->dataLen+current_session->actual_flow->offset<max_payload)
		copySize=new_flow->dataLen;
	else if((int)(max_payload-current_session->actual_flow->offset)>=0)
		copySize=max_payload-current_session->actual_flow->offset;
	else
		copySize=0;
	//printf("dataLen:%u offset:%u max_payload:%u copySize=%u\n",new_flow->dataLen,current_session->actual_flow->offset,max_payload,copySize);

	if (num_packets < max_pack)
	{
		(current_session->actual_flow->timestamp)[num_packets] =(last_packet_timestamp);
		(current_session->actual_flow->size)[num_packets] = (new_flow->nbytes);
		(current_session->actual_flow->packet_offset)[num_packets] =(copySize);
	}
	//Do not copy more than the max_payload 
	if (copySize > 0)
	{
		current_session->actual_flow->npack_payload++;
		u_int8_t*aux=new_flow->payload_ptr;

		if(aux)
		{	
//			if((current_session->actual_flow->offset)+copySize>MAX_PAYLOAD)
				//printf("1 %p, copySize=%u offset=%u max_payload:%u\n",current_session->actual_flow,copySize,(current_session->actual_flow)->offset,max_payload);
			memcpy (current_session->actual_flow->payload + (current_session->actual_flow->offset),aux, copySize);
			//printf("2 current_session:%p actual_flow:%p, copySize=%u offset=%u\n",current_session,current_session->actual_flow,copySize,(current_session->actual_flow)->offset);
			(current_session->actual_flow)->offset += copySize;
		}
	}

	current_session->lastpacket_timestamp = last_packet_timestamp;
	(current_session->actual_flow->npack)++;

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Frag. packets
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	if (frag_packets_flag)
	{

		if (current_session->actual_flow->frag_flag==0)
		{
			current_session->actual_flow->frag_flag=1;
			current_session->actual_flow->ip_id=new_flow->ip_id;
			insertPointer_frag(current_session->actual_flow);
		}

		else if (current_session->actual_flow->ip_id!=new_flow->ip_id)
		{
			removePointer_frag(current_session->actual_flow);
			current_session->actual_flow->ip_id=new_flow->ip_id;
			insertPointer_frag(current_session->actual_flow);
		}

		frag_packets_flag=0;
	}

	if((current_session->actual_flow->flag_FIN)>1)
	{

		#ifdef NO_FLAGS_EXPIRATION

		#else


		//node_l *n=list_search(&flags_expired_flow_list,current_session->active_node,compareTupleFlowList);
		//if(n==NULL)
		if(current_session->actual_flow->expired_by_flags==0)
		{	
			//list_unlink(&(flow_table[index]),(current_session->active_node)->data);//sacamos de la tabla hash
			//releaseNodel((current_session->active_node)->data);		
			list_unlink(&active_flow_list,current_session->active_node);//sacamos de la lista de activos
			//(current_session->active_node)->data=current_session;//apuntamos directamente a la estructura
			list_append_node(&flags_expired_flow_list,current_session->active_node);//insertamos en la lista de expirados por banderas
			//expired_session++;//vj
			//active_session--;//vj
			//num_expired++;//vj
			current_session->actual_flow->expired_by_flags=1;
			//printf("%p\n",(current_session->active_node)->data);
			num_flags++;
		        //int k;
		        //for(k=0;k<n_networks;k++){
	                	//actualizamos contadores entrada
	                //	if((current_session->network_membership_IN>>networks[k].netID)%2==1)
        		//                networks[k].concurrent_flows_IN--;
        	        	//actualizamos contadores salida
		        //        else if((current_session->network_membership_OUT>>networks[k].netID)%2==1)
        	        //	        networks[k].concurrent_flows_OUT--;
	        	//}
		}
		#endif
	}
	else
	{

		list_unlink(&active_flow_list,current_session->active_node);
		list_prepend_node(&active_flow_list,current_session->active_node);
	}
}


/*******************************************************
*
* This function inserts/updates a session in the GLOBAL
* flows table. 
*
********************************************************/
inline IPSession *insertFlow (IPSession * aux_session)
{
	IPFlow *new_flow=&(aux_session->incoming);
	u_int32_t index = getIndex (new_flow);


	node_l *list=flow_table[index];


	list_alloc_node_no_malloc(aux_session);

	node_l *current_node=list_search(&list,&static_node,compareTupleFlow);

	if(current_node==NULL)
	{
		created_flows++;
		#if 0
		int k;
		for(k=0;k<n_networks;k++){
			//actualizamos contadores entrada
			if((aux_session->network_membership_IN>>networks[k].netID)%2==1)
				networks[k].concurrent_flows_IN++;
			//actualizamos contadores salida
			else if((aux_session->network_membership_OUT>>networks[k].netID)%2==1)
				networks[k].concurrent_flows_OUT++;
		}
		#endif
		active_session++;
		return insertFlowTable(aux_session,new_flow,index);
		
	}
	else /*If session exists */
	{
		IPSession *current_session=(IPSession*)(current_node->data);
		/*If flow has expired*/
		if ((last_packet_timestamp - (current_session->lastpacket_timestamp)) > expiration_flow_time)
		{
			created_flows++;
			#if 0
			int k;
			for(k=0;k<n_networks;k++){
				//actualizamos contadores entrada
				if((aux_session->network_membership_IN>>networks[k].netID)%2==1)
					networks[k].concurrent_flows_IN++;
				//actualizamos contadores salida
				else if((aux_session->network_membership_OUT>>networks[k].netID)%2==1)
					networks[k].concurrent_flows_OUT++;
			}
			#endif
			active_session++;
			return insertFlowTable(aux_session,new_flow,index);
		}
		else
		{
			updateFlowTable(current_session,new_flow,current_node,index);
			return aux_session;
		}
	}
	return aux_session;
}

/*******************************************************
*
*  This function calculates the index in the FLOWS table
*  from the source ip or the destination ip. 
*
********************************************************/
u_int32_t getIndex(IPFlow * flow)
{


	return (flow->source_ip + flow->destination_ip + flow->source_port + flow->destination_port + flow->transport_protocol)%MAX_FLOWS_TABLE_SIZE;
	//return hashlittle((const void*)flow,13,0xDEADBEEF)&hashmask(24);

}

/*******************************************************
*
*  This function clean up the list of active flows 
*  (exporting and removing expired flows)
*
*
********************************************************/
void cleanup_flows ()
{
	
	node_l *n=NULL,*n_flags=NULL;
	node_l *current_node_session_table=NULL;
	IPSession *current_session=NULL;
	int num_expired=0;
	u_int64_t aux = 0;
	u_int32_t index=0;


	n_flags=list_get_last_node(&flags_expired_flow_list);
	n=list_get_last_node(&active_flow_list);

	//printf("USED:%d FREE:%d ACTIVE:%d IN_EXPIRED_LIST:%d EXPIRED:%d ACTIVE+EXPIRED:%d CONCURRENT:%d\n",used_session,free_session,active_flows,in_expired_list_flows,expired_flows,active_flows+in_expired_list_flows,networks[0].concurrent_flows_IN);

	while(n != NULL) 
	{

		current_node_session_table=(node_l*)n->data;
		current_session=(IPSession*)current_node_session_table->data;
		//printf("num_expired:%u %p\n",num_expired,current_session);
		aux =(last_packet_timestamp - ((current_session)->lastpacket_timestamp));
//		printf("last_packet_timestamp:%lu current_session->lastpacket_timestamp:%lu aux:%lu expiration_flow_time:%lu\n",last_packet_timestamp/1000000,current_session->lastpacket_timestamp/1000000,aux/1000000,expiration_flow_time/1000000);

		if ((aux > expiration_flow_time))//ha expirado
		{
			//sacamos de la tabla hash
                        index=getIndex(&(current_session->incoming));
                        list_unlink(&(flow_table[index]),current_node_session_table);
			n->data=current_node_session_table->data; //apuntamos directamente a la estructura para poder borrarla
			releaseNodel(current_node_session_table);
			dead_flows++;
			#if 0
 		        int k;
		        for(k=0;k<n_networks;k++){
	                	//actualizamos contadores entrada
	                	if((current_session->network_membership_IN>>networks[k].netID)%2==1)
        		                networks[k].concurrent_flows_IN--;
        	        	//actualizamos contadores salida
		                else if((current_session->network_membership_OUT>>networks[k].netID)%2==1)
        	        	        networks[k].concurrent_flows_OUT--;
	        	}
			#endif
			node_l* naux=n;
			//avanzamos en la lista de activos
			n = list_get_prev_node(&active_flow_list, n);
			//sacamos de la lista de activos para insertarlo al final de la de expirados por banderas
			list_unlink(&active_flow_list,naux);
			list_append_node(&flags_expired_flow_list,naux);
			num_expired++;
			active_session--;
			//expired_session++; jAVI
		}
		else{
			//printf("last_packet_timestamp:%lu current_session->lastpacket_timestamp:%lu aux:%lu expiration_flow_time:%lu\n",last_packet_timestamp/1000000,current_session->lastpacket_timestamp/1000000,aux/1000000,expiration_flow_time/1000000);
			break;
		}

	}

/*	while(n!=NULL){
		current_node_session_table=(node_l*)n->data;
		current_session=(IPSession*)current_node_session_table->data;
		//printf("num_expired:%u %p\n",num_expired,current_session);
		aux =(last_packet_timestamp - ((current_session)->lastpacket_timestamp));
		if(aux/1000000==15){
			printf("aux:%lu aux_n:%u\n",aux/1000000,aux_n/1000000);
			break;
		}
		n=list_get_prev_node(&active_flow_list,n);
	}
*/

	int nf=0;
	n=n_flags;
	while(n != NULL) 
	{
		current_node_session_table=(node_l*)n->data;
		current_session=(IPSession*)current_node_session_table->data;
		//sacamos de la tabla hash
                index=getIndex(&(current_session->incoming));
                list_unlink(&(flow_table[index]),current_node_session_table);
		n->data=current_node_session_table->data; //apuntamos directamente a la estructura para poder borrarla
		releaseNodel(current_node_session_table);
		dead_flows++;
		#if 0
	        int k;
	        for(k=0;k<n_networks;k++){
	               	//actualizamos contadores entrada
	               	if((current_session->network_membership_IN>>networks[k].netID)%2==1)
       		                networks[k].concurrent_flows_IN--;
       	        	//actualizamos contadores salida
	                else if((current_session->network_membership_OUT>>networks[k].netID)%2==1)
       	        	        networks[k].concurrent_flows_OUT--;
        	}
		#endif
		//avanzamos en la lista de activos
		n = list_get_prev_node(&flags_expired_flow_list, n);
		num_expired++;
		active_session--;
		//expired_session++; JAVI
		num_flags--;
		nf++;
	}



//printf("%lu %u %u %u\n",last_packet_timestamp/1000000,num_expired+nf,networks[0].concurrent_flows_IN,nf);

/*	if(num_expired>0){//ha expirado algún flujo por tiempo
		//printf("expirando por tiempo:%u concurrent:%u\n",num_expired,networks[0].concurrent_flows_IN);
		node_l *last_expired_time=list_get_last_node(&active_flow_list);
		node_l *first_expired_time;
		if(n!=NULL){//quedan flujos activos
			first_expired_time=n->next;
			first_expired_time->prev=last_expired_time;
			last_expired_time->next=first_expired_time;
			//saca de la lista de activos la parte de expirados
			node_l *first_active=list_get_first_node(&active_flow_list);
			n->next=first_active;
			first_active->prev=n;
		}		
		else{//todos los flujos han expirado
			//printf("todos los flujos EXPIRADOS\n");
			first_expired_time=active_flow_list;
			active_flow_list=NULL;
		}
		//inserta los expirados por tiempo al final de la lista de expirados por banderas
		node_l *last_expired_flags=list_get_last_node(&flags_expired_flow_list);
		node_l* first_expired_flags=list_get_first_node(&flags_expired_flow_list);
		if(first_expired_flags!=NULL){//hay elementos en la lista de expirados por banderas
			first_expired_flags->prev=last_expired_time;
			last_expired_flags->next=first_expired_time;
			first_expired_time->prev=last_expired_flags;
			last_expired_time->next=first_expired_flags;
		}
		else{//lista de expirados por banderas vacia
			//printf("lista expirados por banderas, vacía\n");
			flags_expired_flow_list=first_expired_time;
		}
	}
	else{
		//printf("no hay flujos para expirar por tiempo\n");
	}*/
	//insertar los expirados por tiempo y banderas al final de la lista de expirados (a exportar)
	if(flags_expired_flow_list!=NULL){
		pthread_mutex_lock(&sem_expired_list);
		expired_session+=num_expired;
		node_l* first_expired=list_get_first_node(&expired_flow_list);
		node_l* last_expired=list_get_last_node(&expired_flow_list);
		node_l *last_expired_flags=list_get_last_node(&flags_expired_flow_list);
		node_l *first_expired_flags=list_get_first_node(&flags_expired_flow_list);
		if(first_expired!=NULL){//hay elementos en la lista de expirados
			first_expired->prev=last_expired_flags;
			last_expired->next=first_expired_flags;
			first_expired_flags->prev=last_expired;
			last_expired_flags->next=first_expired;
		}
		else{//lista de expirados vacia
			expired_flow_list=first_expired_flags;
		}
		pthread_mutex_unlock(&sem_expired_list);
	}
	flags_expired_flow_list=NULL;
}

/*******************************************************
*
*  This function returns a pointer to the flow containing a given frag packet 
*
********************************************************/
IPFlow * getPointer_frag(u_int32_t ip_src,u_int32_t ip_dst,u_int8_t proto,u_int16_t ip_id)
{
	node_l * node_found;
	node_l static_node;
	IPFlow static_flow;

	static_flow.source_ip=ip_src;
	static_flow.destination_ip=ip_dst;
	static_flow.ip_id=ip_id;
	static_node.data=&(static_flow);

	pthread_mutex_lock(&sem_frag);
	node_found=list_search(&(frag_table[ip_id]),&(static_node),compFragPackets);
	pthread_mutex_unlock(&sem_frag);

	if (node_found!=NULL) return ((IPFlow *)(node_found->data));

	return NULL;

}

/*******************************************************
*
*  This function inserts a pointer in the list of flows containing frag packets 
*
********************************************************/
void insertPointer_frag(IPFlow *  flow)
{
	node_l * node_flow;

	if(getNodel()==-1)
		pthread_kill(main_thread,SIGINT);
	node_flow=nodel_aux;
	node_flow->data=flow;
	pthread_mutex_lock(&sem_frag);
	list_append_node(&(frag_table[flow->ip_id]),node_flow);
	pthread_mutex_unlock(&sem_frag);
}


/*******************************************************
*
*  This function remove a pointer from the list of flows containing frag packets 
*
********************************************************/
void removePointer_frag(IPFlow * flow)
{
	node_l * node_found;
	node_l static_node;

	static_node.data=flow;

	pthread_mutex_lock(&sem_frag);
	node_found=list_search(&(frag_table[flow->ip_id]),&(static_node),compFragPackets);

	if (node_found!=NULL)
	{
		list_unlink(&(frag_table[flow->ip_id]),node_found);
		releaseNodel(node_found);
	}
	pthread_mutex_unlock(&sem_frag);

}

/*******************************************************
*
*  This function compares a frag packet and a flow  
*
********************************************************/
int compFragPackets(void * a, void * b)
{
	if ((((IPFlow *)a)->source_ip==((IPFlow *)b)->source_ip) && (((IPFlow *)a)->destination_ip==((IPFlow *)b)->destination_ip) && (((IPFlow *)a)->ip_id==((IPFlow *)b)->ip_id)) return 0;

	return 1;
}

void processFlow(u_int8_t *bp,struct pcap_pkthdr *h,u_int64_t network_membership_IN,u_int64_t network_membership_OUT,u_int8_t num_tags){

	u_int16_t ipLen = 0;
	u_int16_t dataLen = 0;
	u_int16_t tcpHLen = 0;
	u_int16_t ipHLen = 0;
	char FIN=0;
	u_int8_t flag_frag=0;


	if (((*((u_int16_t *)(bp+6))) & 0xff1f)!=0)
	{
		u_int16_t ip_id=ntohs(*((u_int16_t *)(bp+4)));
		u_int8_t proto=ntohl(*((u_int8_t *)(bp+9)));
		u_int32_t ip_src=ntohl(*((u_int32_t *)(bp+12))), ip_dst=ntohl(*((u_int32_t *)(bp+16)));

		IPFlow * aux_frag=getPointer_frag(ip_src,ip_dst,proto,ip_id);

		if (aux_frag!=NULL)//es un fragmento de un paquete ya contabilizado
		{
			// Copy data from aux_frag
			if(aux_session==NULL)
				aux_session=getIPSession();
//			bzero(aux_session,sizeof(IPSession));
			bzero(aux_session,sizeof(IPSession)-2*sizeof(IPFlow));
			bzero(&(aux_session->incoming),sizeof(IPFlow)-MAX_PAYLOAD+1);

			IPFlow *aux=&(aux_session->incoming);
			aux->source_mac=aux_frag->source_mac;
			aux->destination_mac=aux_frag->destination_mac;
			aux->source_ip=aux_frag->source_ip;
			aux->destination_ip=aux_frag->destination_ip;

			aux->current_seq_number=aux_frag->current_seq_number;

			aux->npack=1;
			aux->nbytes=h->len;
			aux->source_port = aux_frag->source_port;
			aux->destination_port = aux_frag->destination_port;
			aux->transport_protocol=aux_frag->transport_protocol;

			aux->flags=0;
			aux->flag_FIN = 0;
			aux->flag_ACK_nulo = 0;

			aux->ip_id=ip_id;

			aux_session->firstpacket_timestamp =last_packet_timestamp;
			aux_session->lastpacket_timestamp = last_packet_timestamp;
			(aux_session->incoming).payload_ptr=bp+20;
			(aux_session->incoming).dataLen=0;
			(aux_session->incoming).offset=0;
			aux->frag_flag=1;

			flag_frag=1;
			frag_packets_flag=1;

			aux_session->network_membership_IN=network_membership_IN;
			aux_session->network_membership_OUT=network_membership_OUT;
	
			aux_session=insertFlow(aux_session);
		}

		else flag_frag=2;

	}

	// Ahora, comprobar si es el primer fragmento
	else if (((*((u_int16_t *)(bp+6))) & 0x0020)!=0)
	{
		frag_packets_flag=1;

	}
	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

	if (flag_frag==0)
	{
		if(aux_session==NULL)
			aux_session=getIPSession();
//		bzero(aux_session,sizeof(IPSession));
		bzero(aux_session,sizeof(IPSession)-2*sizeof(IPFlow));
		bzero(&(aux_session->incoming),sizeof(IPFlow)-MAX_PAYLOAD+1);


		IPFlow *aux=&aux_session->incoming;

		memcpy(&(aux->destination_mac),bp-ETH_HLEN-4*num_tags,ETH_ALEN);
		memcpy(&(aux->source_mac),bp-ETH_HLEN+ETH_ALEN-4*num_tags,ETH_ALEN);

		aux->source_ip=ntohl(*((u_int32_t*)(bp+IP_SIP)));
		aux->destination_ip=ntohl(*((u_int32_t*)(bp+IP_DIP)));

		ipHLen = (bp[0] & 0x0F) * IP_ALEN;

		ipLen= bp[3];
		((u_int8_t*)(&ipLen))[1]=bp[2];
		aux->npack=1;
		aux->nbytes=h->len;
		aux->ip_id=ntohs(*((u_int16_t *)(bp+4)));

		aux_session->network_membership_IN=network_membership_IN;
		aux_session->network_membership_OUT=network_membership_OUT;

		if (bp[IP_PROTO] == TCP_PROTO) {
			bp += ipHLen;
			//Nos saltamos la cabecera IP
			aux->source_port=*((u_int16_t*)bp);
			aux->source_port = ntohs (aux->source_port);
			aux->destination_port=*((u_int16_t*)(bp+sizeof(u_int16_t)));
			aux->destination_port = ntohs (aux->destination_port);
		
			aux_session->firstpacket_timestamp =last_packet_timestamp;
			aux_session->lastpacket_timestamp = last_packet_timestamp;
	
		
			aux->transport_protocol=TCP_PROTO;

			aux->flags=(bp+13)[0];
			aux->flag_FIN = 0;
			aux->num_flags[2]=0;

			//Advertisement window zero
			if( bp[14]==0 && bp[15]==0 )
				aux->nwindow_zero=1;
			else
				aux->nwindow_zero=0;

			FIN=(bp + 13)[0];
			FIN=FIN & 0x05; //Capturing FIN and RESET flags
			if(FIN%2==1)
				aux->flag_FIN = 2; //1 for sessions
			else if(FIN>1)
				aux->flag_FIN = 2;

			FIN=(bp + 13)[0];
			if((FIN&0x04)==0x04)//RST
				aux->num_flags[2]=1;

			
	

			tcpHLen = (((bp[12] >> 4) & 0x0F) * 4);

			dataLen = ipLen - ipHLen - tcpHLen;
			if(dataLen>9200)//Malformed packets
				dataLen=0;
//PRUEBAS PAYLOAD
//			aux_session->incoming.dataLen=dataLen;
			(aux_session->incoming).dataLen=MIN(dataLen,MAX(h->caplen-ETH_HLEN-4*num_tags-ipHLen-tcpHLen,0));
			(aux_session->incoming).offset=(aux_session->incoming).dataLen;
			if((aux_session->incoming).dataLen>0)
//PRUEBAS PAYLOAD
//				(aux_session->incoming).payload_ptr=padding;
				(aux_session->incoming).payload_ptr=bp+tcpHLen;
			else
				(aux_session->incoming).payload_ptr=NULL;
			aux_session=insertFlow (aux_session);

		}
		else if (bp[IP_PROTO] == UDP_PROTO) {
	
			bp += ipHLen;
			aux->source_port=*((u_int16_t*)bp);
			aux->source_port = ntohs (aux->source_port);
			aux->destination_port=*((u_int16_t*)(bp+sizeof(u_int16_t)));
			aux->destination_port = ntohs (aux->destination_port);
			aux_session->firstpacket_timestamp =last_packet_timestamp;
			aux_session->lastpacket_timestamp = last_packet_timestamp;
			aux->flag_FIN = 0;

			aux->transport_protocol= UDP_PROTO;

			(aux_session->incoming).payload_ptr=bp+8;
			dataLen=ipLen-ipHLen-UDP_HLEN;
//PRUEBAS PAYLOAD
//			aux_session->incoming.dataLen=dataLen;
			(aux_session->incoming).dataLen=MIN(dataLen,MAX(h->caplen-ETH_HLEN-4*num_tags-ipHLen-UDP_HLEN,0));
			(aux_session->incoming).offset=(aux_session->incoming).dataLen;
			if((aux_session->incoming).dataLen>0)
//				(aux_session->incoming).payload_ptr=padding;//PRUEBAS PAYLOAD bp+UDP_HLEN;
				(aux_session->incoming).payload_ptr=bp+UDP_HLEN;
			else
				(aux_session->incoming).payload_ptr=NULL;
//printf("REAL:%u CURRENT:%u h->caplen:%u\n",dataLen,(aux_session->incoming).dataLen,h->caplen);

			aux_session=insertFlow (aux_session);
		
		}
		else if (bp[IP_PROTO] == ICMP_PROTO) {
			bp += ipHLen;

			aux->source_port = 0;
			aux->destination_port=ntohs(*((u_int16_t*)bp));
			aux_session->firstpacket_timestamp =last_packet_timestamp;
			aux_session->lastpacket_timestamp = last_packet_timestamp;
			aux->flag_FIN = 0;

			aux->transport_protocol= ICMP_PROTO;

			dataLen=ipLen-ipHLen-ICMP_HLEN;
//PRUEBAS PAYLOAD
//			aux_session->incoming.dataLen=dataLen;
			(aux_session->incoming).dataLen=MIN(dataLen,MAX(h->caplen-ETH_HLEN-4*num_tags-ipHLen-ICMP_HLEN,0));
			(aux_session->incoming).offset=(aux_session->incoming).dataLen;
			if((aux_session->incoming).dataLen>0)
//				(aux_session->incoming).payload_ptr=padding;//PRUEBAS PAYLOAD bp+ICMP_HLEN;
				(aux_session->incoming).payload_ptr=bp+ICMP_HLEN;
			else
				(aux_session->incoming).payload_ptr=NULL;
//printf("REAL:%u CURRENT:%u h->caplen:%u\n",dataLen,(aux_session->incoming).dataLen,h->caplen);
			aux_session=insertFlow (aux_session);

		}
	}
}
