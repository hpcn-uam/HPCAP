#ifndef MONITOR_H
#define MONITOR_H

#include <pcap.h>
#include "IPflow.h"

#define MAX_LINE 1000
//#define MAX_FLOWS_TABLE_SIZE 1024 //2^10
#define MAX_FLOWS_TABLE_SIZE 16777216 //2^24

#define MAX_NETWORKS 16
typedef struct net{
	u_int16_t netID;
	char description[MAX_LINE];
	u_int32_t ip;
	u_int32_t mask;

	u_int32_t alarmID;

	u_int32_t maxthresh_bytes_IN;
	u_int32_t maxinterval_bytes_IN;
	u_int32_t minthresh_bytes_IN;
	u_int32_t mininterval_bytes_IN;
	u_int32_t maxthresh_packets_IN;
	u_int32_t maxinterval_packets_IN;	
	u_int32_t minthresh_packets_IN;
	u_int32_t mininterval_packets_IN;
	u_int32_t maxthresh_flows_IN;
	u_int32_t maxinterval_flows_IN;	
	u_int32_t minthresh_flows_IN;
	u_int32_t mininterval_flows_IN;		
	u_int32_t maxthresh_bytes_OUT;
	u_int32_t maxinterval_bytes_OUT;
	u_int32_t minthresh_bytes_OUT;
	u_int32_t mininterval_bytes_OUT;
	u_int32_t maxthresh_packets_OUT;
	u_int32_t maxinterval_packets_OUT;
	u_int32_t minthresh_packets_OUT;
	u_int32_t mininterval_packets_OUT;
	u_int32_t maxthresh_flows_OUT;
	u_int32_t maxinterval_flows_OUT;	
	u_int32_t minthresh_flows_OUT;
	u_int32_t mininterval_flows_OUT;		

	u_int64_t bytes_sec_IN;
	u_int64_t packets_sec_IN;
	u_int64_t bytes_sec_OUT;
	u_int64_t packets_sec_OUT;
	u_int32_t concurrent_flows_IN;
	u_int32_t concurrent_flows_OUT;

	u_int32_t beginalarm_max_bytes_IN;
	u_int32_t alarmduration_max_bytes_IN;
	u_int32_t alarmvalue_max_bytes_IN;
	u_int32_t beginalarm_min_bytes_IN;
	u_int32_t alarmduration_min_bytes_IN;
	u_int32_t alarmvalue_min_bytes_IN;
	u_int32_t beginalarm_max_packets_IN;
	u_int32_t alarmduration_max_packets_IN;
	u_int32_t alarmvalue_max_packets_IN;
	u_int32_t beginalarm_min_packets_IN;
	u_int32_t alarmduration_min_packets_IN;
	u_int32_t alarmvalue_min_packets_IN;
	u_int32_t beginalarm_max_flows_IN;
	u_int32_t alarmduration_max_flows_IN;
	u_int32_t alarmvalue_max_flows_IN;
	u_int32_t beginalarm_min_flows_IN;
	u_int32_t alarmduration_min_flows_IN;
	u_int32_t alarmvalue_min_flows_IN;
	u_int32_t beginalarm_max_bytes_OUT;
	u_int32_t alarmduration_max_bytes_OUT;
	u_int32_t alarmvalue_max_bytes_OUT;
	u_int32_t beginalarm_min_bytes_OUT;
	u_int32_t alarmduration_min_bytes_OUT;
	u_int32_t alarmvalue_min_bytes_OUT;
	u_int32_t beginalarm_max_packets_OUT;
	u_int32_t alarmduration_max_packets_OUT;
	u_int32_t alarmvalue_max_packets_OUT;
	u_int32_t beginalarm_min_packets_OUT;
	u_int32_t alarmduration_min_packets_OUT;
	u_int32_t alarmvalue_min_packets_OUT;
	u_int32_t beginalarm_max_flows_OUT;
	u_int32_t alarmduration_max_flows_OUT;
	u_int32_t alarmvalue_max_flows_OUT;
	u_int32_t beginalarm_min_flows_OUT;
	u_int32_t alarmduration_min_flows_OUT;
	u_int32_t alarmvalue_min_flows_OUT;

//	node_l *flow_table[MAX_FLOWS_TABLE_SIZE];
//	node_l *active_flow_list;
//	node_l *flags_expired_flow_list;
//	node_l *long_flow_list;

	u_int32_t threshold_duration;
	u_int32_t threshold_rst;
	
	FILE *log_file;
	FILE *alarm_file;
	FILE *alarmsflows_file;
//	FILE *flow_file;
	
} net;

typedef struct capture_{
	u_int64_t timestamp_ini;
	u_int32_t mbytes_file;
} capture_t;


void capturaSenial (int nSenial);
#endif
