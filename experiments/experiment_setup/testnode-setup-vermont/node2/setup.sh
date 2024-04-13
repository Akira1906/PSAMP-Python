#!/bin/bash

hn=$(pos_get_variable hostname)
accesstoken=$(pos_get_variable a/global/accesstoken --from-global)

echo "Setting up node2..."
echo "hostname is $hn according to pos"
apt-get -qq update
apt-get install -qq --yes --force-yes tcpreplay
apt-get install -qq --yes --force-yes net-tools
apt-get install -qq --yes --force-yes coreutils
git clone https://gitlab.lrz.de:$accesstoken@gitlab.lrz.de/netintum/teaching/tumi8-theses/ba-doering.git &
wait
echo "...done setting up node2"
