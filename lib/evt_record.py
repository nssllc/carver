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

import evt_log
import evt_plugin

class EvtRecord:
"""Definition of a single record from a Windows Event Log"""
    
    # Fields of each EVT record
    _fields["length"] = ""
    _fields["reserved"] = ""
    _fields["recordNumer"] = ""
    _fields["timeGenerated"] = ""
    _fields["timeWritten"] = ""
    _fields["eventID"] = ""
    _fields["eventType"] = "" _fields["numStrings"] = ""
    _fields["eventCategory"] = ""
    _fields["reservedFlags"] = ""
    _fields["closingRecordNumber"] = ""
    _fields["stringOffset"] = ""
    _fields["userSidLength"] = ""
    _fields["userSidOffset"] = ""
    _fields["dataLength"] = ""
    _fields["dataOffset"] = ""

    def getField(self, key):
    """Get the value of a particular field in an EVT log record"""
        if key not in _fields:
            print "Unknown field " + key
            return
        return _fields[key]

    def setField(self, key, val):
    """Set the value of a particular field in an EVT log record"""
        if key not in _fields:
            print "Unknown field " + key
            return
        _fields[key] = val

    def getRecordFields(self):
    """Return a list of the fields defined in this EVT log record"""
        return keys(_fields)
