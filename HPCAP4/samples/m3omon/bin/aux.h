#ifndef AUX_H

#define AUX_H


#define VALUE_UINT16(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a == 65535 ? _b : _a; })

#define VALUE_UINT8(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a == 255 ? _b : _a; })


#define MAGNITUDE_BYTES 0
#define MAGNITUDE_PACKETS 1
#define MAGNITUDE_FLOWS 2


#define DIRECTION_IN 0
#define DIRECTION_OUT 1
#define ALARM_TYPE_MAX 0
#define ALARM_TYPE_MIN 1
#include <time.h>
#include <inttypes.h>
   #include <sys/types.h>
       #include <unistd.h>


void day_second_number(time_t timestamp,uint16_t *day,uint16_t *second);

void week_number(time_t timestamp,uint16_t *year,uint16_t *week);

inline time_t start_capture_interval(time_t timestamp,int capture_duration);

int read_global_cfg(char *filename, char *datadir,char *capturedir,char *lecturadir,char *flowsdir,char *interfaz,
        uint16_t *capture_duration,
	int8_t *affinity_dump,int8_t *affinity_process,int8_t *affinity_export,int8_t *affinity_main,
        uint32_t *capture_dir_duration);

#endif
