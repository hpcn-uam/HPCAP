#!/bin/bash

source scripts/lib.bash

dir=$(read_value_param basedir)
driver=$(read_value_param version)

if [ $# -ne 4 ] && [ $# -ne 5 ]
then
	echo "Usage: $0 <iface> <ip addr> <netmask> <core> [<speed, default 10000>]"
	exit 0
elif [ $# -eq 5 ]
then
	vel=$5
else
	vel=10000
fi

iface=$1
ip=$2
netmask=$3
core=$4

ifconfig $iface $ip netmask $netmask up
sleep 2
cat /proc/interrupts | grep $iface | awk '{split($1,irq,":");print irq[1];}' |
	while read irq
	do
		num=$(printf "%x\n"  $(( 1 << $core )) )
		echo $num > /proc/irq/${irq}/smp_affinity
	done
negocia_iface $iface $vel
