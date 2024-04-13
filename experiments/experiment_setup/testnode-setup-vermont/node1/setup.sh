#!/bin/bash

hn=$(pos_get_variable hostname)
accesstoken=$(pos_get_variable a/global/accesstoken --from-global)

echo "Setting up node1..."
echo "hostname is $hn according to pos"
apt-get -qq update
apt-get -qq --yes --force-yes install net-tools
apt-get -qq --yes --force-yes install python3-pip

apt-get -qq --yes --force-yes install cmake libboost-filesystem-dev libboost-regex-dev libboost-test-dev libboost-thread-dev libxml2-dev libpcap-dev libsctp-dev cmake-curses-gui libpq-dev libgsl-dev libczmq-dev
git clone https://github.com/tumi8/vermont.git
cd vermont
cmake -Wno-error -Wno-deprecated -Wno-dev .
make install
cd ..

pip3 install scapy
pip3 install matplotlib

git clone https://gitlab.lrz.de:$accesstoken@gitlab.lrz.de/netintum/teaching/tumi8-theses/ba-doering.git &
wait

echo "...done setting up node1"
