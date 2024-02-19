#!/bin/bash

# Sample experiment demonstrating global, local, and loop variables
# in queuing mode.

if test "$#" -ne 2; then
	echo "Usage: experiment.sh node1 node2"
	exit
fi

set -x
set -e

NODE1=$1
NODE2=$2

#free experiment nodes
pos allocations free --keep-calendar-event $NODE1
pos allocations free --keep-calendar-event $NODE2
# allocate experiment nodes
pos allocations allocate $NODE1 $NODE2

# load global variables (the allocation is referred to by any node within it)
pos allocations set_variables $NODE1 --as-global ./global-variables.yml

# load local variables
pos allocations set_variables $NODE1 ./node1/node1.yml
pos allocations set_variables $NODE2 ./node2/node2.yml

# load loop variables
#pos allocations set_variables $NODE1 --as-loop ./loop-variables.yml

# configure nodes
pos nodes image $NODE1 debian-bullseye
pos nodes image $NODE2 debian-bullseye

# reset/reboot nodes
pos nodes reset $NODE1 --non-blocking
pos nodes reset $NODE2 --blocking

# setup nodes
pos commands launch --infile node1/setup.sh --queued --name setup $NODE1
pos commands launch --infile node2/setup.sh --queued --name setup $NODE2
# execute experiment on nodes
pos commands launch --infile node1/measurement.sh --queued --name measurement $NODE1
# as all nodes sync at start and end of measurement scripts, launching the
# loop for the last node in blocking mode accurately displays the current
# progress
pos commands launch --infile node2/measurement.sh --blocking --name measurement $NODE2

# free nodes
pos allocations free --keep-calendar-event $NODE1
pos allocations free --keep-calendar-event $NODE2
