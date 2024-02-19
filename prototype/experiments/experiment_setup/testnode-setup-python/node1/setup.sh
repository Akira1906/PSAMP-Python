#!/bin/bash

hn=$(pos_get_variable hostname)
accesstoken=$(pos_get_variable a/global/accesstoken --from-global)

echo "Setting up node1..."
echo "hostname is $hn according to pos"
apt-get -qq update
apt-get -qq --yes --force-yes install net-tools
apt-get -qq --yes --force-yes install python3-pip

pip3 install scapy
pip3 install matplotlib
git clone https://gitlab.lrz.de:$accesstoken@gitlab.lrz.de/netintum/teaching/tumi8-theses/ba-doering.git &
wait

echo "...done setting up node1"
