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
# evt_log.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log file definition 
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309024(v=vs.85).aspx
#

import evt_record
import evt_plugin

# EVT logfile header magic numbers
header_magic["size"] = "0x30"             # Size of header structure
header_magic["signature"] = "0x654c664c"  # Header signature
header_magic["majorVersion"] = "1"        # Major version of event log
header_magic["minorVersion"] = "1"        # Minor version of event log
header_magic["endSize"] = "0x30"          # Ending size of header structure

class EvtLog:
"""Definition of a Windows Event Log"""

    # Event Log header
    _header["size"] = header_magic["size"]
    _header["signature"] = header_magic["signature"]
    _header["majorVersion"] = header_magic["majorVersion"]
    _header["minorVersion"] = header_magic["minorVersion"]
    _header["startOffset"] = ""
    _header["endOffset"] = ""
    _header["currentRecordNum"] = ""
    _header["oldestRecordNum"] = ""
    _header["maxSize"] = ""
    _header["flags"] = []
    _header["retention"] = ""
    _header["endHeaderSize"] = header_magic["endSize"]

    # Records
    _records = []

    # Record iterator
    _recordIter = _records[0]

    def getNumRecords(self):
    """Return the number of records in this log."""
        return 0

    def getRecords(self, base, num):
    """Get a list of all records in the log, starting at base and extending 
       num records. Return a list of EvtRecords."""
        return _record
    
    def getNextRecord(self):
    """Get the next record from this log. Returns an EvtRecord object."""
        return 0

    def setHeaderField(self, key, val):
        if key not in _header:
            print "Unknown EVT header field " + key 
            return
        _header[key] = val

    def getHeaderField(self, key):
        if key not in _header:
            print "Unknown EVT header field " + key
            return
        return _header[key]

    
