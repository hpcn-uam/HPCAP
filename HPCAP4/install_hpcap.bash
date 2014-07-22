#!/bin/bash

source scripts/lib.bash

#######################
# PARAMS
#######################

dir=$(read_value_param basedir)
version=$(read_value_param version)

#######################
# CLEANING
#######################

#close conflicting applications
echo "[ Killing apps ... ]"
killall irqbalance
killall -s SIGINT hpcapdd
killall monitor.bash
sleep 5

#remove driver
echo "[ Removing modules ... ]"
remove_module "ixgbe"
remove_module "ps_ixgbe"
remove_module "hpcap"


#######################
# INSTALLING
#######################
itr=956
nif=$(read_value_param nif)
nrxq=$(read_value_param nrxq)
ntxq=$(read_value_param ntxq)
echo "[ Installing driver ... ]"
args=""
args+="RXQ=$(repeat $nif ${nrxq}) "
args+="TXQ=$(repeat $nif ${ntxq}) "
args+="VMDQ=$(repeat $nif 0) "
args+="InterruptThrottleRate=$(repeat $nif ${itr}) "
args+="Node=$(fill_nodes $nif) "
args+="Core=$(fill_cores $nif) "
args+="Caplen=$(fill caplen $nif) "
args+="Mode=$(fill mode $nif) "
args+="Dup=$(fill dup $nif) "
cmd="insmod hpcap.ko $args"
#compile driver (if needed)
cd  ${dir}/driver/${version}/driver
if [ -f hpcap.ko ]
then
	echo "     -> No need to recompile"
else
	make clean
	make
	make clear
fi

echo "     -> CMD = \"$cmd\""
$cmd
if [ $? -ne 0 ]
then
	echo "Error when installing the driver module."
	exit 1
fi

#######################
# CREATING DEVICES AND SETTINGS
#######################
cd ${dir}
j=0
dev="hpcap"
major=$(cat ${dir}/include/hpcap.h | grep "HPCAP_MAJOR" | awk '{print $3}')
ifs=$(read_value_param ifs)
for iface in $ifs
do
	echo "[ Setting up $iface ... ]"
	ifconfig $iface down
	sleep 1
	j=$(echo $iface | awk -v FS="hpcap|xgb" '{print $2}')
	modo=$(read_value_param "mode${j}")
	if [ $modo -eq 1 ]
	then
		core=$(read_value_param "core${j}")
		core=$(set_core $core)
	elif [ $modo -eq 2 ]
	then
		core=$(set_core -1)
		for i in $(seq 0 $(( $nrxq -1 )) )
		do
			disp="${dev}_${j}_$i"
			rm -f /dev/${disp}
			mknod /dev/${disp} c $(( $major + $j )) $i
			chmod 666 /dev/${disp}
		done
	fi
	ifconfig ${iface} up promisc
	set_irq_affinity $iface $core
	vel=$(read_value_param "vel${j}")
	negocia_iface ${iface} $vel
	#sleep 2
	#check_iface_link ${iface}
	if [ $modo -eq 1 ]
	then
		echo ifconfig ${iface} $(read_value_param "ip${j}") netmask $(read_value_param "mask${j}")
		ifconfig ${iface} $(read_value_param "ip${j}") netmask $(read_value_param "mask${j}")
	fi
done
echo ""
echo "[ New char devices can found at /dev/ directory: ]"
ls -l /dev | grep $dev
echo ""


#######################
# COMPILE LIB
######################
echo "[ Compiling HPCAP lib ... ]"
cd ${dir}/lib
if [ -f libhpcap.a ]
then
	echo "     -> No need to compile hpcap-lib"
else
	make
	echo "     -> Compiling hpcap-lib..."
fi

######################
# LAUNCH MONITORING SCRIPT (if enabled)
######################
cd $dir
first=1
monitor_core=$(read_value_param monitor_core)
monitor_core=$(set_core $monitor_core)
echo "[ Launching monitoring scripts (on core $monitor_core)... ]"
for iface in $ifs
do
	j=$(echo $iface | awk -v FS="hpcap|xgb" '{print $2}')
	modo=$(read_value_param "mode${j}")
	if [ $modo -eq 2 ]
	then
		#hpcap mode
		echo "     -> ${dir}/scripts/monitor.bash $iface $first"
		taskset -c ${monitor_core} ${dir}/scripts/monitor.bash $iface $first &
		first=0
	fi
done


exit 0
