#!/bin/bash

source scripts/lib.bash

if [ $# -ne 3 ]
then
	echo "Uso: ./monitor <ifaz> <cpus> <vf-aware?>"
	exit 0
fi

interval=$(read_value_param monitor_interval)
iface=$1
cpus=$2
vf=$3

dir="$(read_value_param basedir)/data"
dirbase=$(read_value_param basedir)
echo 0 > "${dir}/${iface}_lastD.dat"
echo 0 > "${dir}/${iface}_lastR.dat"
echo 0 > "${dir}/${iface}_lastRB.dat"
echo 0 > "${dir}/${iface}_lastDB.dat"
echo $(date +%s) > "${dir}/${iface}_lastFecha.dat"
if ! [ -f "${dir}/${iface}_alarm.dat" ]
then
	echo 0 > "${dir}/${iface}_alarm.dat"
fi

${dirbase}/scripts/monitor2.bash $iface 1 $cpus $vf
while [ 1 ]
do
	sleep $interval
	${dirbase}/scripts/monitor2.bash $iface 0 $cpus $vf
done
