#!/bin/bash

#a_loop_variable=$(pos_get_variable a_loop_variable --from-loop)
ifnode2=$(pos_get_variable a/global/ifnode2 --from-global)
ethnode1=$(pos_get_variable a/global/ethnode1 --from-global)
ethnode2=$(pos_get_variable a/global/ethnode2 --from-global)
pcap=$(pos_get_variable a/global/pcap --from-global)
portremap=$(pos_get_variable a/global/portremap --from-global) 

pos_sync
echo "measuring on node2..."
ifconfig "$ifnode2" up
pos_sync
sleep 1
tcprewrite --infile="$pcap" --outfile=ba-doering/code/pcaps/pcap_experiment.pcap --portmap="$portremap" --enet-dmac="$ethnode1" --enet-smac="$ethnode2"
timeout 80s tcpreplay --intf1="$ifnode2" ba-doering/code/pcaps/pcap_experiment.pcap &
echo "wait for tcpreplay to finish"
wait
pos_sync
echo "...done measuring on node2"
