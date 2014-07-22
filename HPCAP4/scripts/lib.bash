#!/bin/bash

#######################
# AUX FUNCTIONS USED BY OHTER SCRIPTS
#######################

function negocia_iface()
{
	ethtool -s $1 speed $2 duplex full autoneg on
	ethtool -A $1 autoneg off rx off tx off
	ethtool -K $1 tso off gso off gro off lro off #ufo off
}
function check_iface_link()
{
	aux=$( ethtool $1 | grep "Link detected" | awk '{print $3}' )
	if [ $aux = "yes" ]
	then
		echo "     -> Interface ${1}: link successfully configured"
	else
		echo "     -> Error while negociating $1 link"
	fi
}
function remove_module()
{
	exists=$( lsmod | awk '{print $1}' | grep $1 | wc -l )
	if [ $exists = 1 ]
	then
		echo "     -> Deleting kernel module $1"
		rmmod $1 &> /dev/null
	fi
}
paramfile="params.cfg"
function read_value_param()
{
	grep -v "#" $paramfile | grep "${1}=" | awk -v FS="[;,=]" '{print $2}'
}

function check_and_mount()
{
	aux=$(df -h | grep $1 | wc -l)
	if [ $aux = 0 ]
	then
		echo "     -> Mounting $2 on /$1"
		mount /dev/$2 /$1
	else
		echo "     -> /$1 already mounted"
	fi
	nr_req=$(read_value_param nr_req)
	echo "echo $nr_req > /sys/block/${2}/queue/nr_requests"
	echo $nr_req > /sys/block/${2}/queue/nr_requests
}
function repeat()
{
	aux=""
	for i in $(seq 1 $1)
	do
		if [ $i != 1 ]
		then
			aux="${aux},$2"
		else
			aux="$2"
		fi
	done
	echo $aux
}
function fill()
{
	num=$2
	ret=""
	arg=$1
	for i in $(seq 0 $(( $num - 1 )) )
	do
		leido=$(read_value_param "${arg}${i}")
		if [ $i != 0 ]
		then
			ret="${ret},$leido"
		else
			ret="$leido"
		fi
	done
	echo $ret
}
function fill_cores()
{
	num=$1
	ret=""
	for i in $(seq 0 $(( $num - 1 )) )
	do
		leido=$(read_value_param "core${i}")
		leido=$(set_core $leido)		
		if [ $i != 0 ]
		then
			ret="${ret},$leido"
		else
			ret="$leido"
		fi
	done
	echo $ret
}
function fill_nodes()
{
	num=$1
	ret=""
	for i in $(seq 0 $(( $num - 1 )) )
	do
		leido=$(read_value_param "core${i}")
		leido=$(set_core $leido)		
		if [ $i != 0 ]
		then
			ret="${ret},$(nodo_del_core $leido)"
		else
			ret="$(nodo_del_core $leido)"
		fi
	done
	echo $ret
}
function nodo_del_core()
{
	i=0
	numactl --hardware | grep cpus | awk -v FS="cpus: " '{print $2}' |
		while read linea
		do
			for j in $linea
			do
				if [ $1 == $j ]
				then
					#echo "el core $1 es del nodo $i"
					echo "$i"
				fi
			done
			i=$(( $i + 1 ))
		done
}
function set_core()
{
	monitor_core=$1
	if [ $monitor_core -eq -1 ]
	then
		num_cores=$( cat /proc/cpuinfo | grep processor | wc -l )
		monitor_core=$(( $num_cores -1 ))
	fi
	echo $monitor_core
}
function set_irq_affinity()
{
	cat /proc/interrupts | grep $iface | awk '{split($1,irq,":");print irq[1];}' |
		while read irq
		do
			num=$(printf "%x\n"  $(( 1 << $core )) )
			echo $num > /proc/irq/${irq}/smp_affinity
		done
}
