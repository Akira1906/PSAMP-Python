#!/bin/bash

#a_loop_variable=$(pos_get_variable a_loop_variable --from-loop)
ifnode1=$(pos_get_variable a/global/ifnode1 --from-global)
counter=$(pos_get_variable a/global/experimentcounter --from-global)

pos_sync
echo "measuring on node1..."
cd ba-doering/prototype/code
ifconfig "$ifnode1" up
pos_sync
echo "starting PSAMP Collector"
python3 psamp_collector.py &
echo "starting PSAMP Device"
python3 psamp_device.py -n "$ifnode1" &
echo "waiting for packet selection process to finish"
wait
git add *

#git commit -m "measurement data (${counter})"
git commit -m"measurement data"
git push

#counter=$((counter+1))
#pos_set_variable a/global/experimentcounter $counter --as-global
pos_sync
echo "...done measuring on node1"

