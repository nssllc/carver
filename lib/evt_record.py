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
import string

# Fixed record size
FixedSize = 0x38

class EvtRecord:
    """Definition of a single record from a Windows Event Log"""

    def __init__(self):
        self._pos = 0        # Position in bytestream of this record
        self._fields = {}

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
        self._fields["userSidLength"] = ""
        self._fields["userSidOffset"] = ""
        self._fields["dataLength"] = ""
        self._fields["dataOffset"] = ""
        self._fields["varData"] = ""

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
        print self._fields["timeGenerated"]
        print string.ljust("Time Written:", c1),
        print self._fields["timeWritten"]
        print string.ljust("Event ID:", c1),
        print self._fields["eventID"]
        print string.ljust("Event RVA Offset:", c1),
        print self._fields["eventRVA"]
        print string.ljust("Event Type:", c1),
        print self._fields["eventType"]
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
        print string.ljust("Variable Data:", c1),
        print self._fields["varData"]
        

