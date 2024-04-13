import struct
from warnings import *
from scapy.all import *
from scapy.layers.netflow import NetflowHeaderV10, NetflowTemplateV9, NetflowRecordV9, NetflowDataflowsetV9
import scapy.layers.netflow


# ---------------------------------------------------------------------------------------
# EXTRACT METADATA
# ---------------------------------------------------------------------------------------
""" 
        Helper function to extract metadata from given context.
        Args:
            network_packet              : The network packet as context
            metadata ({})               : The Metadata of the network packet as context
            datafield                   : The datafield that defines which metadata to extract
            config_state                : The global config and state as context
            scope [(s_name, s_value)]   : Defines the scope used for IPFIX Options Template Data Records 

        Returns:
            ipfix_data_record (Bytes)   : The final IPFIX Data Record
"""


def extract_metadata(network_packet, metadata, datafield, config_state, scope=[]):
    field_value = b''

    if datafield.ieLength == "2":
        if datafield.ieName in metadata:
            field_value = struct.pack("!H", int(metadata[datafield.ieName]))
        elif datafield.ieName == "ingressInterface":  # ieId = 10
            if config_state.observationPoints[0].direction == "Ingress":
                field_value = struct.pack(
                    "!H", int(config_state.observationPoints[0].ifIndex))
            else:
                warn("Extract_metadata ieId 10")
        # elif datafield.ieName == "totalLengthIPv4":
        #     field_value = struct.pack("!H", len(network_packet["IP"]))
        elif datafield.ieName == "ethernetTotalLength":
            # Determine ie here from the network packet
            field_value = struct.pack("!H", len(network_packet))
        else:
            field_value = struct.pack("!H", 0)
            warn("Metadata unsupported IE")

    elif datafield.ieLength == "4":

        
        if datafield.ieName == "selectorId":
            field_value = struct.pack("!L", int(metadata["selectorId"].pop(0)))

        elif datafield.ieName == "fragmentIdentification":
            field_value = struct.pack("!L", int(network_packet['IP'].id))

        elif datafield.ieName == "selectorIdTotalPktsSelected":
            # only used in Options Templates, requires selectorId and selectionsequenceid in metadata
            if not ("selectorId" in metadata and "selectionSequenceId" in metadata):
                warn(
                    "extract_metadata: selectorIdTotalPktsSelected needs metadata to work")
            else:
                selectorId = metadata["selectorId"].pop(0)
                selectionSequenceId = metadata["selectionSequenceId"]

            for sP in config_state.selectionProcesses:
                if sP.get_selectionSequenceId() == int(selectionSequenceId):
                    for selector in sP.selectors:
                        if selector.selectorId == selectorId:
                            packetsSelected = selector.packetsObserved - selector.packetsDropped
                            field_value = struct.pack("!L", packetsSelected)
                            break
                    break

            if field_value == b'':
                warn("extract_metadata: selectorIdTotalPktsSelected selectorId not found ")
                field_value = struct.pack("!L", 0)

        elif datafield.ieName == "selectorIdTotalPktsObserved":
            if not ("selectorId" in metadata and "selectionSequenceId" in metadata):
                warn(
                    "extract_metadata: selectorIdTotalPktsObserved needs metadata to work")
            else:
                selectorId = metadata["selectorId"][0]
                selectionSequenceId = metadata["selectionSequenceId"]

            for sP in config_state.selectionProcesses:
                if sP.get_selectionSequenceId() == int(selectionSequenceId):
                    for selector in sP.selectors:
                        if selector.selectorId == selectorId:
                            packetsObserved = selector.packetsObserved
                            field_value = struct.pack("!L", packetsObserved)
                            break
                    break

            if field_value == b'':
                warn("extract_metadata: selectorIdTotalPktsObserved selectorId not found ")
                field_value = struct.pack("!L", 0)

        elif datafield.ieName in metadata:
            field_value = struct.pack("!L", int(metadata[datafield.ieName]))

        else:
            field_value = struct.pack("!L", 0)
            warn("Metadata unsupported IE")

    elif datafield.ieLength == "8":
        if datafield.ieName == "observationTimeNanoseconds":
            # always stored as a tuple of two 32bit uints according to dateTimeNanosecondsformat
            if datafield.ieName in metadata:
                field_value = struct.pack(
                    "!II", metadata[datafield.ieName][0], metadata[datafield.ieName][1])
            else:
                warn("extract_metadata: observationTimeNanoseconds not available")
                field_value = struct.pack("!Q", 0)

        elif datafield.ieName in metadata:
            field_value = struct.pack("!Q", int(metadata[datafield.ieName]))
        else:
            field_value = struct.pack("!Q", 0)
            warn("Metadata unsupported IE")

    elif (datafield.ieLength == "65535" and datafield.ieId == "492"):
        # pack up a variable length field (only packetData supported)
        # RFC 7011 section 7
        if len(bytes(network_packet)) != 0:
            field_value = struct.pack("!B", 255)
            field_value += struct.pack("!H", len(bytes(network_packet)))
            field_value += bytes(network_packet)
        else:
            field_value = struct.pack("!B", 0)
    else:
        warn("Extract metadata, unsupported ieLength")
    return field_value


# ---------------------------------------------------------------------------------------
# BUILD IPFIX COMPLIANT RECORDS
# ---------------------------------------------------------------------------------------


# """
#         LEGACY
#         Builds an IPFIX Template Set in bytes according to the cache configuration
#         RFC 7011 3.4.1
#         Args:
#             set_id (int)        : The Set ID of the IPFIX Template Record Set
#             template_id (int)   : The Template ID of the IPFIX Template  Set
#             cache               : The PSAMP configuration of a Cache object

#         Returns:
#             template_set (Bytes)   : The final IPFIX Template Set
# """


# def build_ipfix_template_set_cache(set_id: int, template_id: int, cache):
#     set_id = struct.pack("!H", set_id)
#     template_id = struct.pack("!H", template_id)
#     set_length = 8
#     field_count = 0
#     cache_layout = cache.cacheLayout
#     datafields_b = b''
#     # TODO fix to suit lists
#     for datafield in cache_layout.keys():
#         datafields_b += build_field_specifier(
#             int(cache_layout[datafield].ieId), int(cache_layout[datafield].ieLength))

#         set_length += 4
#         field_count += 1

#     return set_id + struct.pack("!H", set_length) + template_id + struct.pack("!H", field_count) + datafields_b


""" 
        Builds an IPFIX Template Set in bytes according to the template configuration
        RFC 7011 3.4.1 and 3.4.2
        Args:
            template:       The PSAMP configuration of the template used

        Returns:
            template_set (Bytes)   : The final IPFIX Template Set
"""


def build_ipfix_template_set(template):
    # set_id = 2: template set ; set_id = 3: options template set (RFC7011 3.3.2)
    set_id = struct.pack("!H", int(template.setId))
    template_id = struct.pack("!H", int(template.templateId))
    set_length = 8
    scope_field_count = 0
    field_count = 0
    scope_datafields_b = b''
    datafields_b = b''
    for f in template.fields:
        if f.isScope:
            scope_datafields_b += build_field_specifier(
                int(f.ieId), int(f.ieLength))

            set_length += 4
            scope_field_count += 1
            field_count += 1
        else:
            datafields_b += build_field_specifier(int(f.ieId), int(f.ieLength))

            set_length += 4
            field_count += 1

    if not scope_field_count == 0:
        # IPFIX Options Template Set
        set_length += 2  # for the inclusion of scope_field_count in the header
        return set_id + struct.pack("!H", set_length) + template_id + struct.pack("!H", field_count)\
            + struct.pack("!H", scope_field_count) + \
            scope_datafields_b + datafields_b
    else:
        # IPFIX Template Set
        return set_id + struct.pack("!H", set_length) + template_id + struct.pack("!H", field_count) + datafields_b


""" 
        Builds a single IPFIX Data Record using the network packets content and the metadata resulting from the selection process
        RFC7011 3.4.3
        Args:
            network_packet      : The network packet 
            metadata ({})       : The Metadata of the network packet
            template            : The PSAMP configuration of the template used
            config_state        : The global config and state to extract metadata

        Returns:
            ipfix_data_record (Bytes)   : The final IPFIX Data Record
"""


def build_ipfix_data_record(metadata, template, config_state, network_packet=[]):
    data_record = b''
    template.templateDataRecords += 1
    # IPFIX Template Record
    if template.setId == "2":
        for datafield in template.fields:
            field_value = extract_metadata(
                network_packet, metadata, datafield, config_state)
            data_record += field_value

        return data_record

    # IPFIX Options Template Record
    elif template.setId == "3":
        # first data records are always the scope
        scope = []
        for datafield in template.fields:
            if datafield.isScope:
                field_value = extract_metadata(
                    network_packet, metadata, datafield, config_state)
                # extract scope
                scope_name = datafield.ieName
                scope_value = int.from_bytes(field_value, "big")
                scope.append((scope_name, scope_value))
                data_record += field_value

        # other data records after that
        for datafield in template.fields:
            if not datafield.isScope:
                field_value = extract_metadata(
                    network_packet, metadata, datafield, config_state, scope)
                data_record += field_value

        return data_record
    else:
        warn("Warn: build_ipfix_data_record unknown set id")



# # Define the IPFIX packet header
# ipfix_header = NetflowHeaderV10(length=None, ExportTime=int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()), flowSequence=0, ObservationDomainID=1)

# # Define the IPFIX template
# ipfix_template = NetflowTemplateV9(templateID=256, fieldCount = 2)
# ipfix_template.template_fields += (Field(fieldType=8, fieldLength=4))  # Source IPv4 Address
# ipfix_template.add_field(Field(field_type=12, field_length=2))  # Source TCP Port

# # Define the IPFIX data record
# ipfix_data = NetflowRecordV9(template_id=256)
# ipfix_data.add_field(Field(field_type=8, field_value="192.168.1.1"))  # Source IPv4 Address
# ipfix_data.add_field(Field(field_type=12, field_value=80))  # Source TCP Port

# # Build the IPFIX message
# ipfix_packet = NetFlow(ipfix_header / ipfix_template / ipfix_data)

# # Print the IPFIX packet summary
# print(ipfix_packet.summary())

# """     LEGACY
#         Builds a single IPFIX Data Record using the network packets content and the metadata resulting from the selection process
#         Counters in cache count up if a Data Record of a packet is build.
#         Args:
#             network_packet      : The network packet
#             metadata ({})       : The Metadata of the network packet
#             cache               : The PSAMP configuration of a Cache object

#         Returns:
#             ipfix_data_record (Bytes)   : The final IPFIX Data Record
# """


# def build_ipfix_data_record_cache(network_packet, metadata, cache):
#     data_record = b''

#     for datafield in cache.cacheLayout:
#         curr_datafield = cache.cacheLayout[datafield]
#         field_value = b''

#         if (curr_datafield.ieLength == "2"):
#             if curr_datafield.ieName in metadata:
#                 field_value = struct.pack(
#                     "!H", metadata[curr_datafield.ieName])
#             else:
#                 field_value = struct.pack("!H", 0)

#         elif (curr_datafield.ieLength == "4"):
#             if curr_datafield.ieName in metadata:
#                 field_value = struct.pack(
#                     "!L", metadata[curr_datafield.ieName])
#             elif (curr_datafield.ieName == "ipTotalLength"):
#                 # Determine ie here from the network packet
#                 field_value = struct.pack(
#                     "!L", len(bytes(network_packet['IP'])))
#             else:
#                 field_value = struct.pack("!L", 0)

#         elif (curr_datafield.ieLength == "65535" and curr_datafield.ieId == "492"):
#             # pack up a variable length field (only packetData supported)
#             # RFC 7011 section 7
#             if (len(bytes(network_packet)) != 0):
#                 field_value = struct.pack("!B", 255)
#                 field_value += struct.pack("!H", len(bytes(network_packet)))
#                 field_value += bytes(network_packet)
#             else:
#                 field_value = struct.pack("!B", 0)
#         else:
#             warn("Warn: Building data record, unsupported ieLength")

#         data_record += field_value

#     cache.dataRecords += 1
#     return data_record


""" 
        Builds an IPFIX Data Record Set from any amount of IPFIX Data Records.
        Based on: RFC7011 section 3
        Args:
            template_id (int)       : The template_id the data records are based on 
            data_records ([Bytes])  : The IPFIX Data Records which should be packed in to a set

        Returns:
            ipfix_data_record_set (Bytes)   : The final IPFIX Data Record Set

"""


def build_ipfix_set(template_id: int, data_records: list):
    set_id = struct.pack("!H", template_id)
    set_length = 4  # initial length of the set header
    data_records_b = b''

    for data_record in data_records:
        data_records_b += data_record
        set_length += len(data_record)

    return set_id + struct.pack("!H", set_length) + data_records_b


""" 
        Builds a Field Specifier.
        Helper Function of build_ipfix_template_record_set.
        Based on: RFC7011 section 3.2
        Args:
            ie_id (int)             : The Information Element ID that the Field Specifier refers to
            field_length (int)      : The Field Length of the Information Element ID
            enterprise (bool)       : Is True if it is an Enterprise Information Element 
            enterprise_number (int) : The Enterprise Identification Number of the Enterprise

        Returns:
            field_specifier (Bytes)   : The final Field Specifier
"""


def build_field_specifier(ie_id: int, field_length: int, enterprise: bool = False, enterprise_number: int = 0):
    if enterprise:
        warn("Warn: build_field_specifier, enterprise numbers not supported")
    return struct.pack("!H", ie_id) + struct.pack("!H", field_length)


""" 
        Helper function to get packet fields as bytes.
        Args:
            pkt                     : scapy network packet object
            name                    : name of the datafield to extract

        Returns:
            field_specifier (Bytes)   : The final Field Specifier
"""


def get_field_bytes(pkt, name):
    fld, val = pkt.getfield_and_val(name)
    return fld.i2m(pkt, val)


"""
        Builds a PSAMP Report Interpretation.
        Builds an IPFIX data record based on an IPFIX Options Template Record of a Selection Sequence Report Interpretation.\
        As Report Interpretations typically 
        Based on: RFC 5476 section 6.5.1
        Args:
            selectionSequenceId (int)   : The SelectionSequenceID refered in the report interpretation
            template                    : The PSAMP configuration of the template of the Selection Sequence Report Interpretation
            config_state                : The global PSAMP configuration

        Returns:
            selection_sequence_report_interpretation_data_record (Bytes)   : The IPFIX Data Record of the selection sequence report interpretation
"""


def build_report_interpretation(template, config_state, selectionSequenceId=0,):
    metadata = {"selectionSequenceId": str(
        selectionSequenceId), "selectorId": []}
    # get all selectorIds of the selectors in the selectionProcess refered by selectionSequenceId
    for sP in config_state.selectionProcesses:
        if sP.get_selectionSequenceId() == int(selectionSequenceId):
            for selector in sP.selectors:
                metadata["selectorId"].append(selector.selectorId)
    template_id = template.templateId

    return build_ipfix_set(int(template_id), [build_ipfix_data_record(metadata, template, config_state)])


def build_ipfix_message(sets, sequence_number, config_state):
    print("packet crafted:"+str(sequence_number))
    version_number = struct.pack("!H", 0x000a)
    observation_domain_id = struct.pack(
        "!I", int(config_state.observationPoints[0].observationDomainId))
    length = struct.pack("!H", 16 + sum([len(set) for set in sets]))
    export_time = struct.pack(
        "!I", int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()))

    return version_number + length + export_time + struct.pack("!I", sequence_number) + observation_domain_id + b''.join(sets)
