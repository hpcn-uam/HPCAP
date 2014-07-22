#!/bin/bash

###############################
#
# This script will check the used
# directories by reading the params.cfg
# file, and free space if needed.
#
###############################

function nivel_ocupacion()
{
        oc=$(df -h | grep $1 | awk '{print $5}')
        oc=${oc%\%}
        echo $oc
}

umbralDisparo=90
umbralParada=70

#basedir="/home/naudit/HPCAP4"
#discos=$(cat "${basedir}/params.cfg" | grep -v "#" | grep dir | awk -v FS="=" '{if($1!="basedir") print $2;}' | sort | uniq )
discos="/disco01"
subdir="detectpro/capture"
for disco in $discos
do
	ocupacion=$(nivel_ocupacion $disco)
	echo "Ocupacion del disco \"${disco}\": ${ocupacion}%"
	if [ $ocupacion -ge $umbralDisparo ]
	then
	        while [ $ocupacion -ge $umbralParada ]
	        do
        	        #se borra el direcorio mas antiguo
	                dirAntiguo=$( ls -rt1 ${disco}/${subdir} | head -n 1)
	                echo "Se va a borrar $dirAntiguo"
	
	                rm -r ${disco}/${subdir}/${dirAntiguo}
	
	                ocupacion=$(nivel_ocupacion $disco)
	                echo "Ocupacion del disco: ${ocupacion}%"
	        done
	fi
done
