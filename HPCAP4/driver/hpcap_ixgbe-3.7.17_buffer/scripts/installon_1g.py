#!/usr/bin/env python

import sys
import os
import subprocess
import time

ITR = 956	# interrupt throttling rate

def execute(cmd):
	try:
		proc = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
		return proc.communicate()[0]
	except:
		pass
		return None
	
def get_num_interfaces():
	output_82598 = execute('lspci | grep 82598').strip()
	num_82598 = len(output_82598.split('\n'))
	if output_82598 == '':
		num_82598 = 0

	output_82599 = execute('lspci | grep 82599').strip()
	num_82599 = len(output_82599.split('\n'))
	if output_82599 == '':
		num_82599 = 0

	output_82599_cable = execute('lspci | grep "Intel Corporation Device 151c"').strip()
	num_82599_cable = len(output_82599_cable.split('\n'))
	if output_82599_cable == '':
		num_82599_cable = 0
	

	return num_82598 + num_82599 + num_82599_cable

def get_num_cpus():
	output = execute('cat /proc/cpuinfo | grep processor')
	return len(output.strip().split('\n'))
	
if os.getuid() != 0:
	print 'You must be root!'
	sys.exit(1)

if len(sys.argv) < 3:
	print 'usage: %s <# of RX queues> <# of TX queues>' % sys.argv[0]
	sys.exit(1)

num_rx_queues = int(sys.argv[1])
num_tx_queues = int(sys.argv[2])
postfix = '1'

assert 0 <= num_rx_queues <= 16

num_ifs = get_num_interfaces()
num_cpus = get_num_cpus()

execute('killall irqbalance')
execute('rmmod ps_ixgbe &> /dev/null')
execute('insmod ../driver/ps_ixgbe.ko RXQ=%s TXQ=%s InterruptThrottleRate=%s' % 
		(','.join([str(num_rx_queues)] * num_ifs),
		 ','.join([str(num_tx_queues)] * num_ifs),
		 ','.join([str(ITR)] * num_ifs))
	)

time.sleep(3)

for i in range(num_ifs):
	ifname = 'xge%d' % i
	print 'setting %s...' % ifname,
	execute('ethtool -s %s speed 1000 autoneg on duplex full' % (ifname))
#	execute('ethtool -K %s ntuple on' % (ifname))
#	execute('ethtool -U %s flow-type tcp4 action 0' % (ifname))
	execute('ifconfig %s 10.0.%d.%s netmask 255.255.255.0' % (ifname, i, postfix))

	print 'OK'
	print execute('./affinity.py %s' % ifname).strip()

execute('rm -f /dev/packet_shader')
execute('mknod /dev/packet_shader c 1010 0')
execute('chmod 666 /dev/packet_shader')
