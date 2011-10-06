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

from evt_record import *
from evt_plugin import *
from evt_log_header_binary import *
from evt_log_footer_binary import *

# String that occurs in every EVT record ("eLfL")
MagicString = "0x654c664c"

# EVT logfile header magic numbers
header_magic["headerSize"] = "0x30"     # Size of header structure
header_magic["signature"] = MagicString # Header signature ("eLfL")
header_magic["majorVersion"] = "1"      # Major version of event log
header_magic["minorVersion"] = "1"      # Minor version of event log
header_magic["endSize"] = "0x30"        # Ending size of header structure

# EVT logfile footer magic numbers
footer_magic["recordSizeBeginning"] = "0x28"    # Beginning size of EOF record
footer_magic["one"] = "0x11111111"              # "one" identifier
footer_magic["two"] = "0x22222222"              # "two" identifier
footer_magic["three"] = "0x33333333"            # "three" identifier
footer_magic["four"] = "0x44444444"             # "four" identifier
footer_magic["recordSizeEnd"] = "0x28"          # End size of EOF record

class EvtLog:
"""Definition of a Windows Event Log"""
    _header = EvtHeader()   # Event log header
    _footer = EvtFooter()   # Event log footer
    _records = []           # Event log records

    def getNumRecords(self):
    """Return the number of records in this log."""
        return 0

    def getRecords(self, base, num):
    """Get a list of all records in the log, starting at base and extending 
       num records. Return a list of EvtRecords."""
        return _records
    
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

    def addRecord(self, record):
    """Add a record to this EVT log. It is appended to the end of the list."""
        _records.append(record)
        return _records.size()

    def writeEVT(self, logFile):
    """Export this log as a .evt file. Returns number of bytes written."""
        # Build the header
        headerBytes = BinaryHeader(
            _header.getField("headerSize"),
            _header.getField("signature"),
            _header.getField("majorVersion"),
            _header.getField("minorVersion"),
            _header.getField("startOffset"),
            _header.getField("endOffset"),
            _header.getField("currentRecordNum"),
            _header.getField("oldestRecordNum"),
            _header.getField("maxSize"),
            _header.getField("flags"),
            _header.getField("retention"),
            _header.getField("endHeaderSize"))

        # Build the record entries
        binaryRecords = []
        for (r in records):
            recordBytes = BinaryRecord(
                r.getField("length"),
                r.getField("reserved"),
                r.getField("recordNumber"),
                r.getField("timeGenerated"),
                r.getField("timeWritten"),
                r.getField("eventID"),
                r.getField("eventType"),
                r.getField("numStrings"),
                r.getField("eventCategory"),
                r.getField("reservedFlags"),
                r.getField("closingRecordNumber"),
                r.getField("stringOffset"),
                r.getField("userSidLength"),
                r.getField("userSidOffset"),
                r.getField("dataLength"),
                r.getField("dataOffset"))
            binaryRecords.append(r)

        # Build the footer
        footerBytes = BinaryFooter(
            _footer.getField("recordBeginningSize"),
            _footer.getField("one"),
            _footer.getField("two"),
            _footer.getField("three"),
            _footer.getField("four"),
            _footer.getField("beginRecord"),
            _footer.getField("endRecord"),
            _footer.getField("currentRecordNum"),

        # Define a local class to handle the variable number of records
        class BinaryEvtLog(Structure):
            _fields_ = [
                # Header: may need to expand definition of BinaryHeader
                ("header", BinaryHeader),

                # Records: an array of BinaryRecord's 
                ("records", BinaryRecord[]),

                # Footer
                ("footer", BinaryFooter),
            ]

        logBytes = BinaryEvtLog(
            headerBytes,
            binaryRecords,
            footerBytes)
            
        f = open(logFile, "w")
        if (!f)
            print "Unable to write file " + logFile + ": " + strerror
            return -1
        f.write(logBytes)
        f.close()
            
        return logBytes.size()     

    
