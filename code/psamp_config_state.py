import csv
import struct
from warnings import *


# ---------------------------------------------------------------------------------------
# INITIALIZATION
# ---------------------------------------------------------------------------------------
# load information elements dictionary
ie_f = open("data/ipfix-information-elements.csv", 'r')
ie_dict = {}
for dict in csv.DictReader(ie_f):
    ie_dict.update({dict["ElementID"]: dict["Name"]})
    ie_dict.update({dict["Name"]: dict["ElementID"]})


# ---------------------------------------------------------------------------------------
# ID HANDLING
# ---------------------------------------------------------------------------------------

# only a single Observation Domain and Observation Point supported
observationDomainId = 0
observationPointId = 0


def set_observationDomainId(newId):
    global observationDomainId

    if observationDomainId != newId and observationDomainId != 0:
        print("Error: Multiple observationDomainIds are used but not supported")
    else:
        observationDomainId = newId


def set_observationPointId(newId):
    global observationPointId

    if observationPointId != newId and observationPointId != 0:
        print("Error: Multiple observationPointIds are used but not supported")
    else:
        observationPointId = newId


def get_observationDomainId():
    global observationDomainId
    return observationDomainId


def get_observationPointId():
    global observationPointId
    return observationPointId


selectionProcessId_counter = 1
# selectionProcessId is given sequentially 1, 2 ..

# selectorId is given sequentially, 1 ,2 .. ieID = 302, unsigned64
selectorId_counter = 1


def get_new_selectionProcessId():
    global selectionProcessId_counter
    selectionProcessId_counter += 1
    return selectionProcessId_counter - 1


def get_new_selectorId():
    global selectorId_counter
    selectorId_counter += 1
    return selectorId_counter - 1


# generate selectionSequenceId in the established scheme
def gen_selectionSequenceId(observationPointId, selectionProcessId: int):
    return int.from_bytes(struct.pack("!B", int(observationPointId)) + struct.pack("!B", 0) + struct.pack("!H", selectionProcessId), "big")

# ---------------------------------------------------------------------------------------
# CLASS DEFINITIONS
# ---------------------------------------------------------------------------------------


class IPFIX:
    def __init__(self, config={}):

        self.observationPoints = []
        if "observationPoint" in config:
            for oP in config["observationPoint"]:
                self.observationPoints.append(ObservationPoint(oP))

        if (len(self.observationPoints) > 1):
            warn("Only a single Observation Point is supported")

        self.selectionProcesses = []
        if "selectionProcess" in config:
            for sP in config["selectionProcess"]:
                self.selectionProcesses.append(SelectionProcess(sP))

        self.caches = []
        if "cache" in config:
            if "cache" in config:
                for c in config["cache"]:
                    self.caches.append(Cache(c))

        self.templates = {}
        if "template" in config:
            for t_key in config["template"].keys():
                self.templates[t_key] = Template(config["template"][t_key])

        self.exportingProcesses = []
        if "exportingProcess" in config:
            for eP in config["exportingProcess"]:
                self.exportingProcesses.append(ExportingProcess(eP))

        self.collectingProcesses = []
        if "collectingProcess" in config:
            for cP in config["collectingProcess"]:
                self.collectingProcesses.append(CollectingProcess(cP))


class ObservationPoint:
    # TODO is not yang compliant, need to add lists
    def __init__(self, config):
        # RW
        if "name" in config:
            self.name = config["name"]
        if "observationPointId" in config:
            self.observationPointId = config["observationPointId"]
            set_observationPointId(config["observationPointId"])
        if "observationDomainId" in config:
            self.observationDomainId = config["observationDomainId"]
            set_observationDomainId(config["observationDomainId"])
        if "ifName" in config:
            self.ifName = config["ifName"]
        if "ifIndex" in config:
            self.ifIndex = config["ifIndex"]
        if "entPhysicalName" in config:
            self.entPhysicalname = config["entPhysicalName"]
        if "entPhysicalIndex" in config:
            self.entPhysicalIndex = config["entPhysicalIndex"]
        if "direction" in config:
            self.direction = config["direction"]


class SelectionProcess:
    def __init__(self, config):
        # RW
        self.selectionProcessId = get_new_selectionProcessId()
        if "name" in config:
            self.name = config["name"]
        if "cache" in config:
            self.cache = config["cache"]
        self.selectors = []
        if "selector" in config:
            for s in config["selector"]:
                self.selectors.append(Selector(s))
        # RO
        self.selectionSequence = SelectionSequence(get_observationDomainId(), gen_selectionSequenceId(
            get_observationDomainId(), self.selectionProcessId))

    def get_selectionSequenceId(self):
        return self.selectionSequence.get_selectionSequenceId()


class SelectionSequence:
    def __init__(self):
        self.observationDomainId = 0
        self.selectionSequenceId = 0

    def __init__(self, observationDomainId, selectionSequenceId):
        self.observationDomainId = observationDomainId
        self.selectionSequenceId = selectionSequenceId

    def get_selectionSequenceId(self):
        return self.selectionSequenceId


class Selector:
    def __init__(self, config):
        self.selectorId = get_new_selectorId()
        # RW
        if "name" in config:
            self.name = config["name"]
        # selectAll
        if "selectAll" in config and config["selectAll"] == True:
            self.method = "selectAll"
            self.selectAll = True
            if ("filterMatch" in config and config["filterMatch"] == True) or ("filterHash" in config and config["filterHash"] == True):
                warn("Warning: init() more than one selector method defined")
        # filterMatch
        if "filterMatch" in config and config["filterMatch"] == True:
            self.method = "filterMatch"
            self.filterMatch = True
            if "ieName" in config:
                self.ieName = config["ieName"]
                self.ieId = ie_dict[config["ieName"]]
            elif "ieId" in config:
                self.ieId = config["ieId"]
                self.ieName = ie_dict[config["ieId"]]
            else:
                warn("Warning: init() filterMatch no IE defined")
            if "ieEnterpriseNumber" in config:
                self.ieEnterpriseNumber = config["ieEnterpriseNumber"]
            if "value" in config:
                self.value = config["value"]
            else:
                warn("Warning: init() filterMatch no value defined")

        # filterHash
        if "filterHash" in config and config["filterHash"] == True:
            self.method = "filterHash"
            self.filterHash = True
            self.selectedRanges = {}
            if "filterHash" in config:
                self.filterHash = config["filterHash"]
            if "hashFunction" in config:
                self.hashFunction = config["hashFunction"]
            if "initializerValue" in config:
                self.initializerValue = config["initializerValue"]
            if "ipPayloadOffset" in config:
                self.ipPayloadOffset = config["ipPayloadOffset"]
            else:
                self.ipPayloadOffset = 0  # Default value, RFC6728 p.24
            if "ipPayloadSize" in config:
                self.ipPayloadSize = config["ipPayloadSize"]
            else:
                self.ipPayloadSize = 8  # Default value, RFC6728, p.24
            if "digestOutput" in config:
                self.digestOutput = config["digestOutput"]
            if "digestOutput" in config:
                self.digestOutput = config["digestOutput"]
            if "outputRangeMin" in config:
                self.outputRangeMin = config["outputRangeMin"]
            if "outputRangeMax" in config:
                self.outputRangeMax = config["outputRangeMax"]
            for r_key in config["selectedRange"]:
                self.selectedRanges[r_key] = SelectedRange(
                    config["selectedRange"][r_key])

        # TODO add other IEs etc.
        if ("selectAll" in config and config["selectAll"] == True) and ("filterMatch" in config and config["filterMatch"] == True):
            warn("Warning: init() more than one selector method defined")
        # RO
        self.packetsObserved = 0
        self.packetsDropped = 0
        # considered out of scope as no discontinuities are expected
        # self.selectorDiscontinuityTime = ""


class SelectedRange:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "min" in config:
            self.min = config["min"]
        if "max" in config:
            self.max = config["max"]


class CollectingProcess:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "tcpCollector" in config:
            self.tcpCollector = TcpCollector(config["tcpCollector"])
        if "udpCollector" in config:
            self.udpCollector = UdpCollector(config["udpCollector"])


class TcpCollector:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "localPort" in config:
            self.localPort = config["localPort"]
        if "localIPAddress" in config:
            self.localIPAddress = config["localIPAddress"]

        self.transportSessions = []

class UdpCollector:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "localPort" in config:
            self.localPort = config["localPort"]
        if "localIPAddress" in config:
            self.localIPAddress = config["localIPAddress"]

        self.transportSessions = []

class transportSession:
    def __init__(self, config):
        if "ipfixVersion" in config:
            self.ipfixVersion = config["ipfixVersion"]
        if "sourceAddress" in config:
            self.sourceAddress = config["sourceAddress"]
        if "destinationAddress" in config:
            self.destinationAddress = config["destinationAddress"]
        if "destinationPort" in config:
            self.destinationPort = config["destinationPort"]
        if "messages" in config:
            self.messages = config["messages"]
        if "ifIndex" in config:
            self.ifIndex = config["ifIndex"]
        elif "ifName" in config:
            self.ifName = config["ifName"]
        if "sendBufferSize" in config:
            self.sendBufferSize = config["sendBufferSize"]
        if "rateLimit" in config:
            self.rateLimit = config["rateLimit"]
        if "transportLayerSecurity" in config:
            warn("Warn: TLS not supported by exporter")

        # CUSTOM
        if "customPacketReportInterpretationInterval" in config:
            self.customPacketReportInterpretationInterval = config[
                "customPacketReportInterpretationInterval"]

        self.templates = {}
        if "template" in config:
            for t_key in config["template"].keys():
                self.templates[t_key] = Template(config["template"][t_key])

        # TODO transportSession RO


class ExportingProcess:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "exportingProcessId" in config:
            self.exportingProcessId = config["exportingProcessId"]
        if "exportMode" in config:
            self.exportMode = config["exportMode"]

        self.destinations = []
        if "destination" in config:
            for d in config["destination"]:
                self.destinations.append(Destination(d))


class Destination:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "tcpExporter" in config:
            self.tcpExporter = TcpExporter(config["tcpExporter"])

        # CUSTOM
        self.sequenceNumber = 0


class TcpExporter:
    def __init__(self, config):
        if "ipfixVersion" in config:
            self.ipfixVersion = config["ipfixVersion"]
        if "destinationPort" in config:
            self.destinationPort = config["destinationPort"]
        if "sourceIPAddress" in config:
            self.sourceIpAddress = config["sourceIPAddress"]
        if "destinationIPAddress" in config:
            self.destinationIPAddress = config["destinationIPAddress"]
        if "ifIndex" in config:
            self.ifIndex = config["ifIndex"]
        elif "ifName" in config:
            self.ifName = config["ifName"]
        if "sendBufferSize" in config:
            self.sendBufferSize = config["sendBufferSize"]
        if "rateLimit" in config:
            self.rateLimit = config["rateLimit"]
        if "transportLayerSecurity" in config:
            warn("Warn: TLS not supported by exporter")

        # CUSTOM
        if "customPacketReportInterpretationInterval" in config:
            self.customPacketReportInterpretationInterval = config[
                "customPacketReportInterpretationInterval"]

        self.templates = {}
        if "template" in config:
            for t_key in config["template"].keys():
                self.templates[t_key] = Template(config["template"][t_key])

        # TODO transportSession RO


class TransportSession:
    def __init__(self, config):
        return


# build after RFC6728 section 4.8
class Template:
    def __init__(self, config, setId=0, templateId=0, fields=[], observationDomainId=0):
        if setId == templateId == 0 and fields == []:

            if "observationDomainId" in config:
                self.observationDomainId = config["observationDomainId"]
            if "templateId" in config:
                self.templateId = config["templateId"]
            if "setId" in config:
                self.setId = config["setId"]

            self.fields = []
            if "field" in config:
                for f in config["field"]:
                    self.fields.append(Field(f))

            # RO
            if "accessTime" in config:
                self.accessTime = config["accessTime"]
            else:
                self.accessTime = 0
            if "templateDataRecords" in config:
                self.templateDataRecords = config["templateDataRecords"]
            else:
                self.templateDataRecords = 0
            if "templateDiscontinuityTime" in config:
                self.templateDiscontinuityTime = config["templateDiscontinuityTime"]
            else:
                self.templateDiscontinuityTime = 0
        else:
            self.setId = setId
            self.templateId = templateId
            self.fields = fields
            self.observationDomainId = observationDomainId
            # RO
            self.accessTime = 0
            self.templateDataRecords = 0
            self.templateDiscontinuityTime = 0


class Field:
    def __init__(self, config, ieId=0, ieLength=0, isScope=False, isFlowKey=False, ieEnterpriseNumber=0):
        if ieId == ieLength == ieEnterpriseNumber == 0 and isScope == False:
            if "ieName" in config:
                self.ieName = config["ieName"]
                self.ieId = ie_dict[config["ieName"]]
            elif "ieId" in config:
                self.ieId = config["ieId"]
                self.ieName = ie_dict[config["ieId"]]
            if "ieLength" in config:
                self.ieLength = config["ieLength"]
            if "ieEnterpriseNumber" in config:
                self.ieEnterpriseNumber = config["ieEnterpriseNumber"]
                warn("Warn: ieEnterpriseNumber currently not supported")
            if "isFlowKey" in config:
                self.isFlowKey = True
            else:
                self.isFlowKey = False

            if "isScope" in config:
                self.isScope = config["isScope"]
            else:
                self.isScope = False

        else:
            self.ieId = ieId
            self.ieName = ie_dict[str(ieId)]
            self.ieLength = ieLength
            self.isScope = isScope
            self.isFlowKey = isFlowKey
            if not ieEnterpriseNumber == 0:
                self.ieEnterpriseNumber = ieEnterpriseNumber


class Cache:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]

        if "immediateCache" in config and config["immediateCache"] == True:
            self.cacheType = "immediateCache"
            self.immediateCache = True
        # TODO change to list
            self.cacheLayout = {}
            for cl in config["cacheLayout"]:
                self.cacheLayout[cl["name"]] = CacheField(cl)

        else:
            warn("Warn: init() Unknown Cache Type")

        # RO
        # self.meteringProcessId (only a single metering process is supported)
        self.dataRecords = 0
        # self.cacheDiscontinuityTime (no discontinuities expected)


class CacheField:
    def __init__(self, config):
        if "name" in config:
            self.name = config["name"]
        if "ieName" in config:
            self.ieName = config["ieName"]
            self.ieId = ie_dict[config["ieName"]]
        elif "ieId" in config:
            self.ieId = config["ieId"]
            self.ieName = ie_dict[config["ieId"]]
        else:
            warn("Warning: init() cacheField no IE defined")
        if "ieLength" in config:
            self.ieLength = config["ieLength"]
        if "ieEnterpriseNumber" in config:
            self.ieEnterpriseNumber = config["ieEnterpriseNumber"]
            warn("Warn: ieEnterpriseNumber currently not supported")
        if "isFlowKey" in config:
            self.isFlowKey = True
        else:
            self.isFlowKey = False
