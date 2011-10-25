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
# evt_header.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Internal representation of an EVT log header
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026(v=vs.85).aspx
#

# String that occurs in every EVT record ("eLfL")
MagicString = "0x4c664c65"

# Other header constants defined by the EVT standard
magic = {}
magic["headerSize"] = "0x30"
magic["signature"] = MagicString
magic["majorVersion"] = "1"
magic["minorVersion"] = "1"
magic["endHeaderSize"] = "0x30"

class EvtHeader:
    """Internal representation of an EVT log header"""
    def __init__(self):
        self._fields = {}
        self._fields["headerSize"] = magic["headerSize"]
        self._fields["signature"] = magic["signature"]
        self._fields["majorVersion"] = magic["majorVersion"]
        self._fields["minorVersion"] = magic["minorVersion"]
        self._fields["startOffset"] = ""
        self._fields["endOffset"] = ""
        self._fields["currentRecordNum"] = ""
        self._fields["oldestRecordNum"] = ""
        self._fields["maxSize"] = ""
        self._fields["flags"] = ""
        self._fields["retention"] = ""
        self._fields["endHeaderSize"] = magic["endHeaderSize"]

    def getField(self, key):
        if key not in self._fields:
            print "Unknown field " + key
            return
        return self._fields[key]

    def setField(self, key, val):
        if key not in self._fields:
            print "Unknown field " + key
            return
        self._fields[key] = val

    

