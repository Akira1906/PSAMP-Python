# needs to be able to parse data_records, Template Records, and Options Template Records
import select
from psamp_config_state import *
import json
import struct
import socket
import time


# ---------------------------------------------------------------------------------------
# INITIALIZATION
# ---------------------------------------------------------------------------------------
# load information elements dictionary
ie_f = open("data/ipfix-information-elements.csv", 'r')
ie_dict = {}
for dict in csv.DictReader(ie_f):
    ie_dict.update({dict["ElementID"]: dict["Name"]})
    ie_dict.update({dict["Name"]: dict["ElementID"]})
ie_dict.update({"492": "packetData"})
ie_dict.update({"packetData": "492"})


""" 
        Parses a set from an IPFIX message. Returns extracted information as metadata or set state of config_state accordingly.
        Currently supports: IPFIX Data Record Sets, IPFIX Template Sets, IPFIX Options Template Sets
        Based on RFC 7011
        Args:
            set_id (int)            : The set id of the IPFIX set received
            set_length (int)        : The length of the IPFIX set received
            record (bytes)          : The IPFIX Set without the set header
            config_state            : The current state of the PSAMP object of the network function

        Returns:
            metadata ([{}])   : List of dictionaries that represents the resulting metadata of the message parsing
"""


def parse_set(set_id: int, set_length: int, record: bytes, config_state):
    r_ptr = 0  # points to the next byte in the record

    # Data Set for an Options Template
    if set_id > 255:
        template = ""
        for t in config_state.templates:
            if int(config_state.templates[t].templateId) == set_id:
                template = config_state.templates[t]
                break

        if not template:
            warn("Warn: dataRecord could not be matched to template")
            return {}
        metadata = {}
        # TODO unpack more than one datarecord from a set
        for field in template.fields:
            if field.ieLength == "4":
                if field.ieId == "302":  # selectorId
                    if not any("selectorId" in d for d in metadata):
                        metadata["selectorId"] = [
                            struct.unpack("!L", record[r_ptr:r_ptr+4])[0]]
                    else:
                        metadata["selectorId"].append(
                            struct.unpack("!L", record[r_ptr:r_ptr+4])[0])

                elif field.ieId == "319":  # packetsSelected
                    if not "selectorIdTotalPktsSelected" in metadata:
                        metadata["selectorIdTotalPktsSelected"] = []
                    metadata["selectorIdTotalPktsSelected"].append(
                        struct.unpack("!L", record[r_ptr:r_ptr+4])[0])

                else:
                    metadata[field.ieName] = struct.unpack(
                        "!L", record[r_ptr:r_ptr+4])[0]
                r_ptr += 4

            elif field.ieLength == "2":
                metadata[field.ieName] = struct.unpack(
                    "!H", record[r_ptr:r_ptr+2])[0]
                r_ptr += 2

            elif field.ieLength == "8":
                if field.ieId == "325":
                    metadata[field.ieName] = struct.unpack(
                        "!II", record[r_ptr:r_ptr+8])
                else:
                    metadata[field.ieName] = struct.unpack(
                        "!Q", record[r_ptr:r_ptr+8])[0]
                r_ptr += 8
            # TODO support whole packet payload
        if r_ptr < set_length-4:
            return [metadata] + parse_set(set_id, set_length - r_ptr, record[r_ptr:], config_state)
        else:
            return [metadata]

    elif set_id <= 255:

        if set_id == 3:
            # Options Template Set contains a new template to store
            # no support for Enterprise numbers
            template_id, field_count, scope_field_count = struct.unpack(
                "!HHH", record[r_ptr:r_ptr+6])
            r_ptr += 6
            scope_fields = []
            for _ in range(0, scope_field_count):
                ie_id = struct.unpack("!H", record[r_ptr:r_ptr+2])[0]
                set_length = struct.unpack("!H", record[r_ptr+2:r_ptr+4])[0]
                scope_fields.append(
                    Field([], str(ie_id), str(set_length), True))
                r_ptr += 4

            fields = []
            for _ in range(0, field_count-scope_field_count):
                ie_id = struct.unpack("!H", record[r_ptr:r_ptr+2])[0]
                set_length = struct.unpack("!H", record[r_ptr+2:r_ptr+4])[0]
                fields.append(Field([], str(ie_id), str(set_length), False))
                r_ptr += 4

            # add the new options template to the config
            print("add Template" + str(template_id))
            config_state.templates["Template:"+str(template_id)] = Template(
                [], str(set_id), str(template_id), scope_fields + fields)
            return {}

        elif set_id == 2:
            # Template Set contains a new template to store
            # no support for Enterprise numbers
            template_id, field_count = struct.unpack(
                "!HH", record[r_ptr:r_ptr+4])
            r_ptr += 4

            fields = []
            for _ in range(0, field_count):
                ie_id = struct.unpack("!H", record[r_ptr:r_ptr+2])[0]
                set_length = struct.unpack("!H", record[r_ptr+2:r_ptr+4])[0]
                fields.append(Field([], str(ie_id), str(set_length), False))
                r_ptr += 4

            # add the new template to the config
            print("add Template" + str(template_id))
            config_state.templates["Template:"+str(template_id)] = Template(
                [], str(set_id), str(template_id), fields)
            return {}
        else:
            warn("Unkown set_id")
            return {}

""" 
        Parses a IPFIX message.
        Currently supports: IPFIX Data Record Sets, IPFIX Template Sets, IPFIX Options Template Sets
        Based on RFC 7011
        Args:
            TODO set_id (int)            : The set id of the IPFIX set received
            set_length (int)        : The length of the IPFIX set received
            record (bytes)          : The IPFIX Set without the set header
            config_state            : The current state of the PSAMP object of the network function

        Returns:
            metadata_list ([[{}]])   : List of a List of dictionaries that represents the resulting metadata of the message parsing
"""

def parse_message(message: bytes, config_state):
    version_number, length, export_time, sequence_number, observation_domain_id = struct.unpack("!HHIII", message[:16])
    message = message[16:]
    print("packet parsed:"+str(sequence_number))
    metadata_list = [[]]
    while(len(message) > 0):
        set_id, set_length = struct.unpack("!HH", message[:4])
        metadata_list.append(parse_set(set_id, set_length, message[4:set_length], config_state))
        message = message[set_length:]
    
    return metadata_list
# ---------------------------------------------------------------------------------------
# NETWORK HEALTH MONITORING
# ---------------------------------------------------------------------------------------


def init_scope():
    dict = {
        # packet counter
        "pr_last_timestamp": 0,
        "pr_cur_timestamp": time.perf_counter_ns(),
        "f_packet_count": 0,
        "packet_count": 0,
        "datalog": "",
        # packet timestamps
        "timestamp_log": "",
        # packet interarrival time
        "iat_log": "",
        "iat_last_observationTimeNanoseconds": 0,
        "iat_cur_timestamp": time.perf_counter_ns(),
        "iat_last_timestamp": 0,
        # packet loss
        "pl_log": "",
        "pl_init_nanoseconds": 0,
    }
    return dict


def collect_metrics(debug_packet_reports_counter, metadata, log, init_ns, cs):
    # initialize
    # packet counter
    f_pps = 0
    pps = 0
    pr_cur_timestamp = cs["pr_cur_timestamp"]
    pr_last_timestamp = cs["pr_last_timestamp"]
    f_packet_count = cs["f_packet_count"]
    packet_count = cs["packet_count"]
    datalog = cs["datalog"]
    #packet timestamps
    timestamp_log = cs["timestamp_log"]
    # packet interarrival time
    iat_log = cs["iat_log"]
    iat_last_observationTimeNanoseconds = cs["iat_last_observationTimeNanoseconds"]
    iat_cur_timestamp = cs["iat_cur_timestamp"]
    iat_last_timestamp = cs["iat_last_timestamp"]
    # packet loss
    pl_log = cs["pl_log"]
    pl_init_nanoseconds = cs["pl_init_nanoseconds"]

    if "observationTimeNanoseconds" in metadata:
        observationTimeNanoseconds = int(int(str(
            metadata["observationTimeNanoseconds"][0])[-4:]) * 1e9 + metadata["observationTimeNanoseconds"][1])
        # TODO prettier solution to the accuracy problem

    # PACKET RATES: Packet Report Interpretation
    if "selectorIdTotalPktsSelected" in metadata and "selectorIdTotalPktsObserved" in metadata:
        pr_last_timestamp, pr_cur_timestamp = pr_cur_timestamp, time.perf_counter_ns()
        if not f_packet_count == 0:
            # calculate pps
            f_pps = (metadata["selectorIdTotalPktsSelected"][2]-f_packet_count) / \
                (float(pr_cur_timestamp -
                       pr_last_timestamp) / 1e9)

        if not packet_count == 0:
            pps = (metadata["selectorIdTotalPktsObserved"]-packet_count) / \
                (float(pr_cur_timestamp -
                       pr_last_timestamp) / 1e9)

        packet_count = metadata["selectorIdTotalPktsObserved"]
        f_packet_count = metadata["selectorIdTotalPktsSelected"][2]

        log += "filtered packets/s: " + str(f_pps) + '\n'
        datalog += "f" + str((pr_cur_timestamp - init_ns) / 1e9) + \
            ": " + str(f_pps) + '\n'

        # print("parsed packets/s: " + str(pps) +
        #      ", filtered packets/s: " + str(f_pps))
        log += "parsed packets/s: " + str(pps) + '\n'
        datalog += "p" + str((pr_cur_timestamp - init_ns) / 1e9) + \
            ": " + str(pps) + '\n'

        # PACKET INTERARRIVAL TIME: Packet Report
    elif "observationTimeNanoseconds" in metadata:
        iat_last_timestamp, iat_cur_timestamp = iat_cur_timestamp, time.perf_counter_ns()
        debug_packet_reports_counter += 1
        # TODO get ieId 160 systemInitTimeMilliseconds as well for relation
        if not iat_last_observationTimeNanoseconds == 0:
            iat_log += "i" + str((iat_cur_timestamp - init_ns) / 1e9) + ": " + str(
                observationTimeNanoseconds - iat_last_observationTimeNanoseconds) + "\n"
            # print("interArrivalTime: " +
            #      str(m["observationTimeNanoseconds"][1]-last_observationTimeNanoseconds))
        iat_last_observationTimeNanoseconds = observationTimeNanoseconds

        # PACKET TIMESTAMPS: 
        timestamp_log += "t" + str(observationTimeNanoseconds) + "\n"

        # PACKET LOSS: Packet Report
        if "fragmentIdentification" in metadata and "observationTimeNanoseconds" in metadata:
            if pl_init_nanoseconds == 0:
                pl_init_nanoseconds = observationTimeNanoseconds
            pl_log += str((observationTimeNanoseconds - pl_init_nanoseconds) /
                          1e9) + ": " + str(metadata["fragmentIdentification"]) + "\n"

    return log, debug_packet_reports_counter, {
        # packet counter
        "pr_last_timestamp": pr_last_timestamp,
        "pr_cur_timestamp": pr_cur_timestamp,
        "f_packet_count": f_packet_count,
        "packet_count": packet_count,
        "datalog": datalog,
        # timestamp
        "timestamp_log" : timestamp_log,
        # packet interarrival time
        "iat_log": iat_log,
        "iat_last_observationTimeNanoseconds": iat_last_observationTimeNanoseconds,
        "iat_cur_timestamp": iat_cur_timestamp,
        "iat_last_timestamp": iat_last_timestamp,
        # packet loss
        "pl_log": pl_log,
        "pl_init_nanoseconds": pl_init_nanoseconds,
    }


# remember IE 319 can occur multiple times in metadata -> always as list
config_state = IPFIX()
# -----------------------------------------------------------
# Settings
test_time = 90
# -----------------------------------------------------------
# parse_message(b'\x00\x03\x00\x1e\x01\x01\x00\x05\x00\x01\x01-\x00\x04\x01>\x00\x04\x01?\x00\x04\x01?\x00\x04\x01?\x00\x04', config_state)
# print(config_state.templates["selectionSequenceStatisticsReportInterpretation"].fields == config_state.templates["template:257"].fields)


 #Open TCP-socket that metering_process clients can connect to
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 3839)
# Debug Option
#sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.bind(server_address)
timeout = 20
sock.settimeout(timeout)

# init variables
log = ""
data = b''

init_ns = time.perf_counter_ns()
init = time.perf_counter()

# DEBUG
debug_packet_report_counter = 0
debug_packet_counter = 0

# Scopes of selectionProcesses
# scope saved as a dictionary of a dictonary {"selectionSequenceId1" : {"variable name" : value, ..}, ...}
scopes = {}
# current scope
cs = {}

# receive the data and digest it in the according selectionSequence scopes
while time.perf_counter() - init < test_time:
    try:
        #Waiting for connection
        sock.listen(1)
        print("Wait for exporting client connection")
        connection, client_address = sock.accept()
        while time.perf_counter()-init < test_time:
            try:

                r, _, _ = select.select([connection], [], [], timeout)
                if r:
                    # 65535 is the max size of IPFIX messages (due to the length field constraints)
                    data += connection.recv(50)
                    # print(len(data))

                    # extract IPFIX messages from data stream using the IPFIX length field
                    while len(data) >= 4:
                        version_number, message_length = struct.unpack("!HH", data[:4])

                        if len(data) < message_length:
                            break
                        else:  # if len(data) >= message_length
                            debug_packet_counter += 1
                            metadata_list = parse_message(data[:message_length], config_state)
                            data = data[message_length:]

                            # print(metadata)
                            log += str(metadata_list) + '\n'
                            for metadata in metadata_list:
                                for m in metadata:

                                    #Network Function starts here
                                    # change scope based on selectionSequenceId

                                    if not m["selectionSequenceId"] in scopes:
                                        scopes[m["selectionSequenceId"]] = init_scope()

                                    cs = scopes[m["selectionSequenceId"]]

                                    # calculate, collect metrics from the metadata
                                    log, debug_packet_report_counter, cs = collect_metrics(
                                        debug_packet_report_counter, m,  log, init_ns, cs)

                                    # save scope state
                                    scopes[m["selectionSequenceId"]] = cs
                else:
                    raise socket.timeout(
                        "Network Function: No data received within {} seconds".format(timeout))

            except (BrokenPipeError, ConnectionResetError):
                    print("connection closed")
                    template_sent = False
                    break
            # except Exception as e:
            #     print("Network Function: Error occured connection closed: ", e)
            #     connection.close()
            #     break

    finally:
        print("Network function: packet_report_counter: " +
            str(debug_packet_report_counter))
        print("Network Function: packets_counter: " +
            str(debug_packet_counter))
        # print("Network Function: detected Selection Processes: " +
        #      (', '.join(scopes.keys())))

        # if (len(datalog) > 0):
        #     visualize_packetrates("nf-data_pr.txt")
        # if (len(iat_log) > 0):
        #     visualize_iat('nf-data_iat.txt')
        # if (len(pl_log) > 0):
        #     visualize_pl("nf-data_pl.txt")

        print('Network Function: closing socket')
        sock.close()

#save data file
with open("experiment/nf-log.txt", "w") as f:
    f.write(log)

for sId in scopes:
    with open("experiment/nf-data_pr-" + str(sId) + ".txt", "w") as f:
        f.write(scopes[sId]["datalog"])
    with open("experiment/nf-data_iat-" + str(sId) + ".txt", "w") as f:
        f.write(scopes[sId]["iat_log"])
    with open("experiment/nf-data_pl-" + str(sId) + ".txt", "w") as f:
        f.write(scopes[sId]["pl_log"])
    with open("experiment/nf-data_timestamp-" + str(sId) + ".txt", "w") as f:
        f.write(scopes[sId]["timestamp_log"])

