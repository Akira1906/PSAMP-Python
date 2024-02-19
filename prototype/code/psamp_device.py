import json
import struct
from warnings import *
from scapy.all import *
from scapy.layers.l2 import Ether
from psamp_config_state import *
from psamp_packet_crafter import *
import binascii
import threading
import time
import socket
import select
import queue
import argparse


# ---------------------------------------------------------------------------------------
# THE SELECTION PROCESS
# ---------------------------------------------------------------------------------------

""" 
        Applies the selection on one network packet and returns the resulting metadata of all the selectionSequences
        Args:
            network_packet              : The network packet to select on
            config                      : the psamp configuration

        Returns:
            metadata ([{}]) : List of dictionaries, each dictionary represents the metadata resulting from a postive selection outcome
"""


def packet_selection(network_packet, config):
    metadata = []
    selection_processes = config.selectionProcesses

    for curr_selection_process in selection_processes:
        selection_result = False
        selection_process_metadata = {}

        for curr_selection in curr_selection_process.selectors:
            selection_result = False
            curr_selection.packetsObserved += 1

            if (curr_selection.method == "selectAll"):
                selection_result, selection_process_metadata = apply_select_all()
            elif (curr_selection.method == "filterMatch"):
                selection_result, selection_process_metadata = apply_property_matching(
                    network_packet, curr_selection)
            elif (curr_selection.method == "filterHash"):
                selection_result, selection_process_metadata = apply_hash_based_selection(
                    network_packet, curr_selection)

            # if packet doesn't match one filter, skip the filters in queue
            if not selection_result:
                curr_selection.packetsDropped += 1
                break

        # metadata: should at least contain selectionSequenceId and the result
        # if a packet is not selected by a process it wont be added to the list
        if selection_result:
            metadata += [{"selectionSequenceId": curr_selection_process.get_selectionSequenceId()}]
            metadata[-1].update(selection_process_metadata)

    return metadata


""" 
        Applies property matching on one network packet and returns the result and possible metadata
        Args:
            network_packet              : The network packet to select on
            curr_selection              : The PSAMP configuration of the selection that should be applied

        Returns:
            result (Bool)   : Positive if the packet matches the criteria
            metadata ({})   : Dictionary that represents the resulting metadata of the matching
"""


def apply_property_matching(network_packet: scapy.packet.Packet, curr_selection):
    ieId = curr_selection.ieId
    ieName = curr_selection.ieName
    value = curr_selection.value
    result = False

    if ieId == "7":  # sourceTransportPort
        if network_packet.haslayer("TCP"):
            result = network_packet.getlayer("TCP").sport == int(value)
        elif network_packet.haslayer("UDP"):
            result = network_packet.getlayer("UDP").sport == int(value)
        else:
            warn("Warn: Only TCP/UDP transport protocols supported in selection")

    elif ieId == "8":  # sourceIPv4Address
        if network_packet.haslayer("IP"):
            result = network_packet.getlayer('IP').src == value
        else:
            warn("No IP Layer detected")

    elif ieId == "11":  # destinationTransportPort
        if network_packet.haslayer("TCP"):
            result = network_packet.getlayer("TCP").dport == int(value)
        elif network_packet.haslayer("UDP"):
            result = network_packet.getlayer("UDP").dport == int(value)
        else:
            warn("Warn: Only TCP/UDP transport protocols supported in selection")

    elif ieId == "12":  # destinationIPv4Address
        if network_packet.haslayer("IP"):
            result = network_packet.getlayer('IP').dst == value
        else:
            warn("No IP Layer detected")


    elif ieId == "180":  # udpSourcePort
        if network_packet.haslayer("UDP"):
            result = network_packet.getlayer("UDP").sport == int(value)

    elif ieId == "181":  # udpDestinationPort
        if network_packet.haslayer("UDP"):
            result = network_packet.getlayer("UDP").dport == int(value)

    elif ieId == "192":  # ipTTL
        result = network_packet.getlayer('IP').ttl == int(value)
    else:
        print("Error: This IE is not supported by property matching")

    metadata = {}
    return result, metadata


""" 
        Applies hash based selection on one network packet and returns the result and possible metadata
        Based on RFC 5475 section 6.2
        Args:
            network_packet              : The network packet to select on
            curr_selection              : The PSAMP configuration of the selection that should be applied

        Returns:
            result (Bool)   : Positive if the packet matches the criteria
            metadata ({})   : Dictionary that represents the resulting metadata of the hash based selection
"""


def apply_hash_based_selection(network_packet, curr_selection):
    flow_selector_algorithm = curr_selection.hashFunction
    ipPayloadOffset = curr_selection.ipPayloadOffset
    ipPayloadSize = curr_selection.ipPayloadSize
    digestHashValue = 0
    metadata = {}
    result = False
    input = b''

    input += struct.pack("!H", network_packet['IP'].id)
    # calculate flags + frag together because of byte alignment
    flags_frag = 0
    # mandatory inclusion into hash digest (RFC 5475 section 6.2.4.1)
    # reserved flag always 0
    if ("DF" in network_packet['IP'].flags):
        flags_frag += 16384  # set flag
        # print("DF!!!")
    if ("MF" in network_packet['IP'].flags):
        flags_frag += 8192
        # print("MF!!!")

    flags_frag += network_packet['IP'].frag

    input += struct.pack("!H", flags_frag)
    input += get_field_bytes(network_packet['IP'], "src")
    input += get_field_bytes(network_packet['IP'], "dst")
    input += bytes(network_packet['IP'].payload)[
        ipPayloadOffset:ipPayloadOffset+ipPayloadSize]

    # DEBUG
    # print(network_packet[IP].flags)
    # print(str(binascii.hexlify(struct.pack("!H", flags_frag)), "utf-8"))
    # print(str(binascii.hexlify(bytes(network_packet[IP].payload)), "utf-8"))
    # print(str(binascii.hexlify(bytes(network_packet[IP].payload)[3:5]), "utf-8"))
    # print(binascii.hexlify(input))
    # DEBUG

    metadata["digestHashValue"] = "0x37373737"  # standard value for testing
    if flow_selector_algorithm == "6":
        # BOB
        warn("Warning: selection, unknown hash-function")
        return True, metadata
    elif flow_selector_algorithm == "7":
        # IPSX
        warn("Warning: selection, unknown hash-function")
        return True, metadata
    elif flow_selector_algorithm == "8":
        # CRC
        metadata["digestHashValue"] = binascii.crc32(input)
    else:
        warn("Warning: selection, unknown hash-function")

    for range in curr_selection.selectedRanges:
        # hashSelectedRangeMin
        min = int(curr_selection.selectedRanges[range].min)
        # hashSelectedRangeMax
        max = int(curr_selection.selectedRanges[range].max)
        if digestHashValue >= min and digestHashValue <= max:
            result = True

    # if desired add hash value to metadata
    if curr_selection.digestOutput:
        return result, metadata
    else:
        return result, {}


""" 
        Function that resembles the select all selector

        Returns:
            result (Bool)   : Always positive by definition
            metadata ({})   : empty metadata dictionary
"""


def apply_select_all():
    metadata = {}
    return True, metadata


# ---------------------------------------------------------------------------------------
# INITIALIZATION OF THE PSAMP CONFIG
# ---------------------------------------------------------------------------------------
def load_config(file_name):
    # load config from json file
    config_f = open(file_name)
    config_json = json.loads(config_f.read())
    config_f.close()
    # initiate psamp objects based on json config
    config_state = IPFIX(config_json["ipfix"])
    return config_state


# ---------------------------------------------------------------------------------------
# PARSING OF PACKETS
# ---------------------------------------------------------------------------------------

def listen_interface(config_state, network_interface_name):
    global threads_running

    print("listen to interface: " + network_interface_name + " ...")
    raw_socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    # Pack a sockaddr_ll structure
    ifname = bytes(network_interface_name, 'utf-8')
    ifindex = socket.if_nametoindex(ifname)
    ssl = struct.pack('HBB8s', socket.AF_PACKET, 0, 6, ifname)
    SO_TIMESTAMPNS = 35
    raw_socket.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)

    # create a raw socket on the specified network interface
    raw_socket.bind((network_interface_name, 0))
    # receive incoming Ethernet packets on the socket
    timeout = 10
    debug_packet_counter = 0
    metadata = {}

    while threads_running:
        try:
            r, _, _ = select.select([raw_socket], [], [], timeout)
            if r:
                # print("trying to receive data...")
                # packet, address = raw_socket.recvfrom(4096)

                raw_data, ancdata, flags, address = raw_socket.recvmsg(
                    65535, 1024)
                # print('received ', raw_data, '-',
                #       ancdata, '-', flags, '-', address)
                if (len(ancdata) > 0):
                    # print(len(ancdata),len(ancdata[0]),ancdata[0][0],ancdata[0][1],ancdata[0][2])
                    # print('ancdata[0][2]:',type(ancdata[0][2])," - ",ancdata[0][2], " - ",len(ancdata[0][2]));
                    i = ancdata[0]
                    # print('ancdata: (cmsg_level, cmsg_type, cmsg_data)=(',
                    #   i[0], ",", i[1], ", (", len(i[2]), ") ", i[2], ")")
                    if (i[0] != socket.SOL_SOCKET or i[1] != SO_TIMESTAMPNS):
                        continue
                    tmp = (struct.unpack("iiii", i[2]))
                    # timestamp = tmp[0] + tmp[2]*1e-9
                    # dateTimeNanoSeconds format according to RFC 7011 6.1.10
                    timestamp = (tmp[0], tmp[2])
                    # print("SCM_TIMESTAMPNS,", tmp, ", timestamp=", timestamp)

                # observationTimeNanoseconds ieId325
                # timestamp = time.perf_counter_ns()
                debug_packet_counter += 1

                packet = Ether(raw_data)
                
                metadata = packet_selection(packet, config_state)
                if metadata:
                    shared_queue.put((packet, metadata, timestamp))
                metadata = {}
                # log += metadata+'\n'

            else:
                raise socket.timeout(
                    "listen_interface(): No data received within {} seconds".format(timeout))
        except socket.timeout as e:
            print(e)
            threads_running = False
            print("listen_interface(): total packet_counter: " +
                  str(debug_packet_counter))
            sys.exit(1)
        except KeyboardInterrupt:
            threads_running = False
            break
        except Exception as e:
            print("listen_interface(): An error occurred while processing a packet:", e)
            threads_running = False
            break
    print("listen_interface(): total packet_counter: " + str(debug_packet_counter))
    raw_socket.close()


def parse_pcap(config_state, pcap_filename):
    global threads_running
    print("reading pcap...")
    pcap_p = rdpcap(pcap_filename)
    pcap_p = pcap_p[:1000]  # shorten the pcap for faster debugging
    start_time = pcap_p[0].time
    # old_timestamp = 0
    from datetime import datetime
    ntp_time = (datetime.utcnow() - datetime(1900, 1, 1)).total_seconds()
    timestamp = 0
    metadata = {}
    # timing = time.perf_counter_ns()
    # old_timing = 0
    for packet in pcap_p:
        if not threads_running:
            break
        time.sleep(float(packet.time - start_time))
        start_time = packet.time

        timestamp = int(ntp_time + int(packet.time)
                        ), int((packet.time - int(packet.time))*1e9)

        metadata = packet_selection(packet, config_state)
        print (metadata)
        if metadata:
          #      with queue_lock:
            shared_queue.put((packet, metadata, timestamp))
        metadata = {}
        # old_timing = timing
        # timing = time.perf_counter_ns()
        # print("post queue:"+ str((timing-old_timing)/1000000))
    threads_running = False
    print("parse_pcap: done")


# ---------------------------------------------------------------------------------------
# IPFIX EXPORTING
# ---------------------------------------------------------------------------------------
def exporting_process(config_state, exportingProcessId, destination_name):
    global threads_running
    print("start exporting process...")

    # TODO maintain the transport session object
    # extract exporting information from config
    exportingProcess = {}
    for e in config_state.exportingProcesses:
        if int(e.exportingProcessId) == exportingProcessId:
            exportingProcess = e

    if not exportingProcess:
        warn("exporting_process(): exporting process config not found")
        exit(1)
    for d in exportingProcess.destinations:
        if d.name == destination_name:
            destination = d

    if not destination:
        warn("exporting_process(): destination config not found")
        exit(1)

    report_interpretation_interval = float(
        destination.tcpExporter.customPacketReportInterpretationInterval)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect the socket to the server's address and port
    server_address = (destination.tcpExporter.destinationIPAddress, int(
        destination.tcpExporter.destinationPort))

    # Wait for the server to become available
    timeout_count = 0
    while True:
        try:
            sock.connect(server_address)
            break
        except ConnectionRefusedError:
            print('PSAMP Collector Server not available, waiting...')
            time.sleep(1)
            timeout_count += 1
            if (timeout_count >= 30):
                threads_running = False
                print('Connection unsuccessful')
                exit(1)
        except Exception as e:
            print(e)
            pass

    timeout = 10
    sock.settimeout(timeout)

    print('Connected to {} port {}'.format(*server_address))

    template_sent = False
    init = time.perf_counter()
    current_time = init
    packet = b''
    packet_report = b''
    debug_packet_counter = 0
    debug_packet_report_interpretation_counter = 0
    debug_packet_report_counter = 0
    metadata = {}

    try:
        while threads_running or not shared_queue.empty():
            # try:
            current_time = time.perf_counter()

            # EXPORT TEMPLATE SETS AT THE BEGINNING OF TRANSMISSION
            if not template_sent:
                options_template_sets = []
                # possible TODO send templates in regular intervalls, e.g. every 20 packets
                print("send all templates...")
                for t_key in destination.tcpExporter.templates.keys():
                    options_template_sets.append(build_ipfix_template_set(
                        destination.tcpExporter.templates[t_key]))
                debug_packet_counter += 1
                template_sent = True
                sock.sendall(build_ipfix_message(
                    options_template_sets, destination.sequenceNumber, config_state))

            # EXPORT OF PACKET REPORTS
            # with queue_lock:
            if not shared_queue.empty():
                packet, metadata, timestamp = shared_queue.get()
            if metadata:
                for m in metadata:
                    debug_packet_report_counter += 1
                    m["observationTimeNanoseconds"] = timestamp
                    sets = []
                    for t_key in destination.tcpExporter.templates.keys():
                        if destination.tcpExporter.templates[t_key].setId == "2":
                            packet_report = build_ipfix_data_record(
                                m, destination.tcpExporter.templates[t_key], config_state, packet)
                            sets.append(build_ipfix_set(
                                int(destination.tcpExporter.templates[t_key].templateId), [packet_report]))

                    # EXPORT OF REPORT INTERPRETATION AT THE DEFINED TIME INTERVAL
                    if current_time - init >= report_interpretation_interval:
                        for t_key in destination.tcpExporter.templates.keys():
                            if destination.tcpExporter.templates[t_key].setId == "3":
                                # Use every Options Template
                                for sP in config_state.selectionProcesses:
                                    # Export report interpretations about every selectionProcess
                                    debug_packet_report_interpretation_counter += 1
                                    # send report_interpretation every 0.1 seconds
                                    sets.append(build_report_interpretation(
                                        destination.tcpExporter.templates[t_key], config_state, sP.get_selectionSequenceId()))

                        init = current_time

                    destination.sequenceNumber = (
                        destination.sequenceNumber + 1) % (pow(2, 32))
                    ipfix_message = build_ipfix_message(
                        sets, destination.sequenceNumber, config_state)
                    sock.sendall(ipfix_message)
                    debug_packet_counter += 1
            metadata = {}
            # except Exception as e:
            #    print(e)
            #    break
    finally:
        sock.close()
        print("exporting_process(): packet_counter: " +
              str(debug_packet_counter))
        print("exporting_process(): packet_report_interpretation_counter: " +
              str(debug_packet_report_interpretation_counter))
        print("exporting_process(): packet_report_counter: " +
              str(debug_packet_report_counter))

    # except Exception as e:
    #     print("exporting_process(): Exception: ", e)
    #     threads_running = False
    #     print("exporting_process(): packet_counter: " + str(debug_packet_counter))
    #     break

# legacy
    # def print_exporting_process(config_state):
    # # Report Interpretation: selectionSequenceId
    # selectionSequenceId = 16777217

    # while threads_running:
    #     print("selectionSequenceReportInterpretation")
    #     report_interpretation = build_selection_sequence_report_interpretation(
    #         selectionSequenceId, config_state.templates["selectionSequenceReportInterpretation"], config_state)
    #     print(report_interpretation)
    #     time.sleep(4)
    # threads_running = False

# ---------------------------------------------------------------------------------------
# ARGUMENT HANDLING
# ---------------------------------------------------------------------------------------

parser = argparse.ArgumentParser(description='This script implements a PSAMP Device. It parses network packets either from a pcap-file or from a network interface. Once parsed, the packets are selected according to the configuration and exported to a PSAMP Collector.')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', '--input', type=str, help='input pcap file path')
group.add_argument('-n', '--networkinterface', type=str, help='name of network interface to listen to')
parser.add_argument('-c', '--config', type=str, help='configuration file path')


args = parser.parse_args()

if args.input:
    print(f'Parse pcap at: {args.input}')
if args.networkinterface:
    print(f'Listen to network interface: {args.networkinterface}')
if args.config:
    print(f'Configuration file path: {args.config}')

# ---------------------------------------------------------------------------------------
# INITIALIZATION
# ---------------------------------------------------------------------------------------

# CONFIG
network_parse = False
local_parse = False
if args.config:
    config_state= load_config(args.config)
else:
    config_state = load_config("configs/psamp_device_config.json")

if args.networkinterface:
    network_parse = True
    network_parser = threading.Thread(target=listen_interface, args=[config_state, args.networkinterface])
    network_parser.start()
elif args.input:
    pcap_parser = threading.Thread(target=parse_pcap, args=[
                               config_state, args.input])
    pcap_parser.start()
    local_parse = True

if args.networkinterface:
    network_parse = True

export_destination_name = "NHM-TCP"
threads_running = True

# Definition of the queue used for information transfer between Observation Point and Exporting Process

shared_queue = queue.Queue()


network_exporter = threading.Thread(
    target=exporting_process, args=[config_state, 1, export_destination_name])
network_exporter.start()


# Join Threads
if network_parse:
    network_parser.join()
elif local_parse:
    pcap_parser.join()
network_exporter.join()


# ---------------------------------------------------------------------------------------
# NOTES
# ---------------------------------------------------------------------------------------
#GENERAL TODO implement all the supported IEs with the correct IANA type
# TODO verify the Yang instance for conformity to our yang model before using it

# LIMITATIONS:
# only use IPv4 packets
# only one metering process
# only one observation domain
# only limited number of information elements are supported
# support Python 3.7 + (ordered dictionaries)
# concept for metadata:
# metadata as dictionary, possible values:
# hashDigestOutput
# hash-algorithm
# selectionsequenceid
# all IE names
# remember: selectorIds are always stored as lists in metadata and in scope