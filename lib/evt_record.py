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

# Fixed record size
FixedSize = 0x38

class EvtRecord:
    """Definition of a single record from a Windows Event Log"""
    _pos = 0        # Position in bytestream of this record
    _fields = {}

    # Fields of each EVT record
    _fields["length"] = ""
    _fields["reserved"] = evt_header.MagicString
    _fields["recordNumber"] = ""
    _fields["timeGenerated"] = ""
    _fields["timeWritten"] = ""
    _fields["eventID"] = ""
    _fields["eventRVA"] = ""
    _fields["eventType"] = "" 
    _fields["numStrings"] = ""
    _fields["eventCategory"] = ""
    _fields["reservedFlags"] = ""
    _fields["closingRecordNumber"] = ""
    _fields["stringOffset"] = ""
    _fields["userSidLength"] = ""
    _fields["userSidOffset"] = ""
    _fields["dataLength"] = ""
    _fields["dataOffset"] = ""
    _fields["varData"] = ""

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
        print "Length: %d" % self._fields["length"] 
        print "Reserved: %s" % self._fields["reserved"]
        print "Record Number: %d" % self._fields["recordNumber"]
        print "Time Generated: %s" % \
            self._fields["timeGenerated"]
        print "Time Written: %s" % \
            self._fields["timeWritten"]
        print "Event ID: %d" % self._fields["eventID"]
        print "Event RVA Offset: %d" % self._fields["eventRVA"]
        print "Event Type: %d" % self._fields["eventType"]
        print "Number of Strings: %d" % self._fields["numStrings"]
        print "Event Category: %d" % self._fields["eventCategory"]
        print "Reserved Flags: %d" % self._fields["reservedFlags"]
        print "Closing Record Number: %d" % \
            self._fields["closingRecordNumber"]
        print "String Offset: %d" % self._fields["stringOffset"]
        print "SID Length: %d" % self._fields["userSidLength"]
        print "SID Offset: %d" % self._fields["userSidOffset"]
        print "Data Length: %d" % self._fields["dataLength"]
        print "Data Offset: %d" % self._fields["dataOffset"]
        print "Variable Data: %s" % self._fields["varData"]
        

