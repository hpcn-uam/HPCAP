#!/bin/bash

source scripts/lib.bash

basedir="$(read_value_param basedir)/data"
first=$2
iface=$1
cpus=$3
vf=$4

if [ $# -ne 4 ]
then
	echo "Uso: ./monitor2 <ifaz>  <first> <cpus> <¿vf-aware?>"
	exit 0
fi

monitordir="$(read_value_param basedir)/data"

auxfile="${monitordir}/aux_${iface}.dat"
n=$(ifconfig -a | grep $iface | wc -l)
if [ $n -eq 0 ]
then
	newD=0
	newR=0
	newRB=0
	newDB=0
	fecha=$(date +%s)
else
	ethtool -S $iface  > $auxfile
	fecha=$(date +%s)
	dir=$(date +%Y-%V)

	newR=$(cat $auxfile | grep "rx_packets:" | awk '{print $2}' )
	if [ $vf -eq 0 ]
	then
		newD=$(cat $auxfile | grep "rx_missed_errors:" | awk '{print $2}' )
	fi
	newRB=$(cat $auxfile | grep "rx_bytes:" | awk '{print $2}' )
	bTot=$(cat $auxfile | grep "rx_bytes_nic:" | awk '{print $2}' )
	newDB=$(( $bTot - $newRB ))

	rm $auxfile
fi

if [ $first -eq 0 ]
then
	lastR=$(cat "${monitordir}/${iface}_lastR.dat")
	lastRB=$(cat "${monitordir}/${iface}_lastRB.dat")
	lastDB=$(cat "${monitordir}/${iface}_lastDB.dat")
	lastFecha=$(cat "${monitordir}/${iface}_lastFecha.dat")
	
	if [ $vf -eq 0 ]
	then
		lastD=$(cat "${monitordir}/${iface}_lastD.dat")
		lost=$(( $newD - $lastD ))
	else
		lost=0
	fi
	interval=$(( $fecha - $lastFecha ))
	rx=$(( $newR - $lastR ))
	bytesRx=$(( $newRB - $lastRB ))
	bitsRx=$(( 8 * $bytesRx ))
	#mbps=$(( 8 * $(( $newB - $lastB )) / 1000000 ))
	#ocupacion=$(df -h /disco_capturas/ | grep /dev/ | awk '{printf("%s/%s=%s", $3, $2, $5);}')
	
	#Estimacion de los bytes perdidos a partir de bytes recibidos, paquetes recibidos y paquetes perdidos
	if [ $rx -eq 0 ]
	then
		bytesLost=0 #para evitar error de division por cero
	else
		bytesLost=$(( $(( $bytesRx / $rx )) * $lost ))
	fi
	
	mkdir -p ${basedir}/${dir}
	file=$iface

	echo $fecha $(( $bitsRx / $interval )) $(( $rx / $interval )) $(( $bytesLost / $interval )) $(( $lost / $interval )) >> ${basedir}/${dir}/$file
fi

if [ $cpus -eq 1 ]
then
	$(read_value_param basedir)/scripts/monitorCPUs.bash
fi

echo $newD > "${monitordir}/${iface}_lastD.dat"
echo $newR > "${monitordir}/${iface}_lastR.dat"
echo $newRB > "${monitordir}/${iface}_lastRB.dat"
echo $newDB > "${monitordir}/${iface}_lastDB.dat"
echo $fecha > "${monitordir}/${iface}_lastFecha.dat"


