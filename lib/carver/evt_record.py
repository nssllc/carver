#
# Copyright (C) 2011 Network Security Services, LLC
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation version 3 of the
# License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# evt_record.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Definition of a single record from a Windows Event Log
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
#

import evt_header
import evt_plugin
import binascii
import os
import string
import time

# Fixed record size
FixedSize = 0x38

class EvtRecord:
    """Definition of a single record from a Windows Event Log"""

    EVENTLOG_ERROR_TYPE = "0x0001"
    EVENTLOG_WARNING_TYPE = "0x0002"
    EVENTLOG_INFORMATION_TYPE = "0x0004"
    EVENTLOG_AUDIT_SUCCESS = "0x0008"
    EVENTLOG_AUDIT_FAILURE = "0x0010"

    def __init__(self):
        self._pos = 0        # Position in bytestream of this record
        self._fields = {}
        self._csv_header_printed = False

        # Path of the file from which this record was carved
        self._pathname = ""

        # Size of the record's variable-length data field
        self._var_data_size = 0
    
        # Fields of each EVT record
        self._fields["length"] = ""
        self._fields["reserved"] = evt_header.MagicString
        self._fields["recordNumber"] = ""
        self._fields["timeGenerated"] = ""
        self._fields["timeWritten"] = ""
        self._fields["eventID"] = ""
        self._fields["eventRVA"] = ""
        self._fields["eventType"] = "" 
        self._fields["numStrings"] = ""
        self._fields["eventCategory"] = ""
        self._fields["reservedFlags"] = ""
        self._fields["closingRecordNumber"] = ""
        self._fields["stringOffset"] = ""
        self._fields["sid"] = ""
        self._fields["userSidLength"] = ""
        self._fields["userSidOffset"] = ""
        self._fields["dataLength"] = ""
        self._fields["dataOffset"] = ""
        self._fields["varData"] = ""

    def removeNonAscii(self, k):
        list1 = []
        result = ""
        for char in k:
            if char == "=" or char == "0":
                list1.append("")
            elif ord(char) < 32 or ord(char) > 127:
                list1.append('#')
            else:
                list1.append(char)
            result = ''.join(list1)
        return result

    def parseEventType(self, t):
        """Return a descriptive string for an EVT event type.\
           If the event type is undefined, return it as a string."""
        if t == int(self.EVENTLOG_ERROR_TYPE, 0):
            desc = "Error event"
        elif t == int(self.EVENTLOG_WARNING_TYPE, 0):
            desc = "Warning event"
        elif t == int(self.EVENTLOG_INFORMATION_TYPE, 0):
            desc = "Information event"
        elif t == int(self.EVENTLOG_AUDIT_SUCCESS, 0):
            desc = "Success Audit event"
        elif t == int(self.EVENTLOG_AUDIT_FAILURE, 0):
            desc = "Failure Audit event"
        else:
            desc = str(t)
        return desc

    def setPosition(self, pos):
        """Set the value of this record's position"""
        if pos < 0:
            pos = 0
        _pos = pos

    def getField(self, key):
        """Get the value of a particular field in an EVT log record"""
        if key not in self._fields:
            print "Unknown field " + key
            return
        return self._fields[key]

    def setField(self, key, val):
        """Set the value of a particular field in an EVT log record"""
        if key not in self._fields:
            print "Unknown field " + key
            return
        self._fields[key] = val

    def getPathname(self):
        """Get the path of the file from which this record was carved"""
        return self._pathname

    def setPathname(self, path):
        """Set the path of the file from which this record was carved"""
        self._pathname = path

    def getVarDataSize(self):
        """Get the size (in bytes) of this record's data field"""
        return self._var_data_size

    def setVarDataSize(self, size):
        """Set the size of this record's data field"""
        self._var_data_size = size

    def getRecordFields(self):
        """Return a list of the fields defined in this EVT log record"""
        return keys(self._fields)

    def printRecord(self):
        """Print this record in a human-readable format."""
        # Length of longest field name (FIXME)
        c1 = len("Event RVA Offset:")

        print string.ljust("Length:", c1),
        print self._fields["length"]
        print string.ljust("Reserved:", c1),
        print self._fields["reserved"]
        print string.ljust("Record #:", c1),
        print self._fields["recordNumber"]
        print string.ljust("Time Generated:", c1),
        print time.ctime(self._fields["timeGenerated"])
        print string.ljust("Time Written:", c1),
        print time.ctime(self._fields["timeWritten"])
        print string.ljust("Event ID:", c1),
        print self._fields["eventID"]
        print string.ljust("Event RVA Offset:", c1),
        print self._fields["eventRVA"]

        print string.ljust("Event Type:", c1),
        desc = self.parseEventType(self._fields["eventType"])
        print desc
        #print self._fields["eventType"]

        print string.ljust("# of Strings:", c1),
        print self._fields["numStrings"]
        print string.ljust("Event Category:", c1),
        print self._fields["eventCategory"]
        print string.ljust("Reserved Flags:", c1),
        print self._fields["reservedFlags"]
        print string.ljust("Closing Record #:", c1),
        print self._fields["closingRecordNumber"]
        print string.ljust("String Offset:", c1),
        print self._fields["stringOffset"]
        print string.ljust("SID Length:", c1),
        print self._fields["userSidLength"]
        print string.ljust("SID Offset:", c1),
        print self._fields["userSidOffset"]
        print string.ljust("Data Length:", c1),
        print self._fields["dataLength"]
        print string.ljust("Data Offset:", c1),
        print self._fields["dataOffset"]
        print string.ljust("VarData Size:", c1),
        print self.getVarDataSize()
        print string.ljust("Variable Data:", c1),
        raw = binascii.b2a_qp(self._fields["varData"])
        print self.removeNonAscii(raw)

        # Print the SID, if it was defined
        sid = self.getField("sid")
        if sid != None:
            print string.ljust("SID: ", c1),
            print sid

    def printCsv(self):
        """Print this record in CSV format."""
        print os.path.abspath(self.getPathname()) + ",",
        print str(self.getField("recordNumber")) + ",",
        print time.ctime(self.getField("timeGenerated")) + ",",
        print time.ctime(self.getField("timeWritten")) + ",",
        print str(self.getField("eventCategory")) + ",",
        print str(self.getField("eventID")) + ",",
        # TODO: find out the semantics of these fields
        # SOURCE
        print ",",
        # COMPUTER
        print ",",
        print self.getField("sid") + ",",
        print str(self.getField("numStrings")) + ",",
        #print binascii.hexlify(self.getField("varData")) + ",",
        raw = binascii.b2a_qp(self.getField("varData"))
        print self.removeNonAscii(raw)

    def printCsvHeader(self):
        """Print the CSV preamble."""
        print "SOURCE FILENAME, RECORD NUMBER, TIME GEN, TIME WRITE, "\
            "CATEGORY, EVENTID, SOURCE, COMPUTER, SID, STRINGS, "\
            "RAW DATA (HEX), DECODED DATA"
        self._csv_header_printed = True

