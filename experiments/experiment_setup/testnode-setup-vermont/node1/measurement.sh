#!/bin/bash

ifnode1=$(pos_get_variable a/global/ifnode1 --from-global)
counter=$(pos_get_variable a/global/experimentcounter --from-global)

pos_sync
echo "measuring on node1..."
cd ba-doering/prototye/code
ifconfig "$ifnode1" up
pos_sync
echo "starting psamp_collector.py"
python3 psamp_collector.py --vermont &
echo "starting vermont psamp_device.py"
cd ..
cd ..
timeout 70s vermont/vermont -q -f ba-doering/prototype/experiments/experiments_setup/testnode-setup-vermont/vermont-config.xml &
echo "waiting for packet selection process to finish"
wait
cd ba-doering
git add *
git commit -m"measurement data"
git push

pos_sync
echo "...done measuring on node1"

