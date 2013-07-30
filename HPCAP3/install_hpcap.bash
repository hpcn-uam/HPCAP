#!/bin/bash

source scripts/lib.bash

#######################
# PARAMS
#######################

dir=$(read_value_param basedir)
driver=$(read_value_param version)
nrxq=$(read_value_param nrxq)
ntxq=$(read_value_param ntxq)
rxmode=$(read_value_param rxmode)
ifs=$(read_value_param ifs)
nif=$(read_value_param nif)
itr=956
dev="hpcap"
major=$(cat ${dir}/${driver}/include/hpcap.h | grep "HPCAP_MAJOR" | awk '{print $3}')
copylaunch=$(read_value_param copylaunch)

# Affinity-related params
num_nodes=$( numactl --hardware | grep cpus | wc -l )
num_cores=$( cat /proc/cpuinfo | grep processor | wc -l )
cores_per_node=$(( $num_cores / $num_nodes ))
echo "$cores_per_node cores por nodo"
core_base=$(read_value_param core_base)




#######################
# CLEANING
#######################

#close conflicting applications
echo "[ Killing apps ... ]"
killall -s SIGINT apcap_forward
killall irqbalance
killall copy.bash
killall dd
killall -s SIGINT hpcapdd
killall monitor.bash
sleep 5

#remove driver
echo "[ Removing modules ... ]"
remove_module "ixgbe"
remove_module "ps_ixgbe"
remove_module "hpcap"


#######################
# MOUNT RAID
#######################
# This must be made by the user
#echo "[ Mounting RAID disks ... ]"
#check_and_mount disco_capturas_0 sdb
#check_and_mount disco_capturas_1 sdc


#######################
# INSTALLING
#######################
echo "[ Installing driver ... ]"
args=""
args+="RXQ=$(repeat $nif ${nrxq}) "
args+="TXQ=$(repeat $nif ${ntxq}) "
args+="InterruptThrottleRate=$(repeat $nif ${itr}) "
args+="Node=$(fill_nodes nodes $nif) "
args+="Core=$(fill core $nif) "
args+="Caplen=$(fill caplen $nif) "
args+="Mode=$(fill mode $nif) "
#args+="Dup=$(fill dup $nif) "
cmd="insmod hpcap.ko $args"
#compile driver (if needed)
cd  ${dir}/${driver}/driver
if [ -f hpcap.ko ]
then
	echo "     -> No need to recompile"
else
	make clean
	make
fi

echo "     -> CMD = \"$cmd\""
$cmd

#######################
# CREATING DEVICES AND SETTINGS
#######################
cd ${dir}
j=0
for iface in $ifs
do
	echo "[ Setting up $iface ... ]"
	j=$(echo $iface | awk -v FS="hpcap" '{print $2}')
	for i in $(seq 0 $(( $nrxq -1 )) )
	do
		disp="${dev}_${j}_$i"
		rm -f /dev/${disp}
		mknod /dev/${disp} c $(( $major + $j )) $i
		chmod 666 /dev/${disp}
	done
	ifconfig ${iface} up promisc
	vel=$(read_value_param "vel${j}")
        echo "negocia_iface ${iface} $vel"
	negocia_iface ${iface} $vel
	sleep 1
	check_iface_link ${iface}
done
echo ""
echo "[ New char devices can found at /dev/ directory: ]"
ls -l /dev | grep $dev
echo ""


#######################
# COMPILE LIB
######################
echo "[ Compiling HPCAP lib ... ]"
cd ${dir}/${driver}/lib
if [ -f libhpcap.a ]
then
	echo "     -> No need to compile hpcap-lib"
else
	make
	echo "     -> Compiling hpcap-lib..."
fi

######################
# LAUNCH MONITORING (if enabled)
######################
echo "[ Launching monitoring script... ]"
cd $dir
first=1
for iface in $ifs
do
	echo "     -> ${dir}/scripts/monitor.bash $iface $first"
	${dir}/scripts/monitor.bash $iface $first &
	first=0
done


#######################
# LAUNCH DD COPY (if enabled)
#####################
if [ $copylaunch = 1 ]
then
	cd $dir
	echo "[ Launching dd threads ... ]"
	for iface in $ifs
	do
		i=$(echo $iface | awk -v FS="hpcap" '{print $2}')
		for k in $(seq 0 $(( $nrxq - 1 )) )
		do
			echo "     -> ${dir}/scripts/copy.bash $i $k"
			${dir}/scripts/copy.bash $i $k &
		done
	done
else
	echo "[ Not launching dd threads ]"
fi

exit 0
