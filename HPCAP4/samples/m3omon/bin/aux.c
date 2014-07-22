#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ether.h>

#include "monitor.h"
#include "aux.h"
extern FILE* patrol_alarm_file;
extern uint8_t patrol;

extern char capture_filename[MAX_LINE];



int read_global_cfg(char *filename, char *datadir,char *capturedir,char *lecturadir,char *flowsdir,char *interfaz,
	uint16_t *capture_duration, 
	int8_t *affinity_dump,int8_t *affinity_process,int8_t *affinity_export,int8_t *affinity_main,
	uint32_t *capture_dir_duration)
{
	FILE *file;
	char line[MAX_LINE],left[MAX_LINE],right[MAX_LINE];

	if(!(file=fopen(filename,"r"))){
		return -1;
	}
	while(fgets(line,MAX_LINE,file)){
		if(sscanf(line,"%[^\t\n=]=%s",left,right)==2){
			if(strcmp(left,"datadir")==0)
				strcpy(datadir,right);
			else if(strcmp(left,"capturedir")==0)
				strcpy(capturedir,right);
			else if(strcmp(left,"lecturadir")==0)
				strcpy(lecturadir,right);
			else if(strcmp(left,"flowsdir")==0)
				strcpy(flowsdir,right);
			else if(strcmp(left,"intf")==0)
				strcpy(interfaz,right);
			else if(strcmp(left,"capture_duration")==0)
				sscanf(line,"%[^\t\n=]=%hu",left,capture_duration);
			else if(strcmp(left,"affinity_dump")==0)
				sscanf(line,"%[^\t\n=]=%hhd",left,affinity_dump);
			else if(strcmp(left,"affinity_process")==0)
				sscanf(line,"%[^\t\n=]=%hhd",left,affinity_process);
			else if(strcmp(left,"affinity_export")==0)
				sscanf(line,"%[^\t\n=]=%hhd",left,affinity_export);
			else if(strcmp(left,"affinity_main")==0)
				sscanf(line,"%[^\t\n=]=%hhd",left,affinity_main);
			else if(strcmp(left,"capture_dir_duration")==0)
				sscanf(line,"%[^\t\n=]=%u",left,capture_dir_duration);
		}
	}
	fclose(file);

	return 0;

}

inline time_t start_capture_interval(time_t timestamp,int capture_duration)
{
	if (capture_duration>60) //orden minutos
		return timestamp-timestamp%60-(((timestamp/60)%60)%(capture_duration/60))*60;
	else //orden segundos
		return timestamp-(timestamp%60)%capture_duration;
}


void day_second_number(time_t timestamp,uint16_t *day,uint16_t *second){
	struct tm *struct_timestamp;
		char date[100];
		uint16_t h,m,s;
		struct_timestamp=gmtime(&timestamp);
		strftime(date,100,"%u %H:%M:%s",struct_timestamp);
		sscanf(date,"%hu %hu:%hu:%hu",day,&h,&m,&s);
		*second=(h*60*60)+(m*60)+s;
}



void week_number(time_t timestamp,uint16_t *year,uint16_t *week){
	struct tm *struct_timestamp;
	char date[100];

	struct_timestamp=gmtime(&timestamp);
	strftime(date,100,"%V-%G",struct_timestamp);
	sscanf(date,"%hu-%hu",week,year);
}

