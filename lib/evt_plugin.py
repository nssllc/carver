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
# evt_plugin.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log file format definitions
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026(v=vs.85).aspx
#

from bitstring import *
import plugin
import time
import evt_header
import evt_record
from evt_record import *

class EvtPlugin(plugin.Plugin):
    """A carver plugin for reading Windows Event Log Files"""
    _name = "evt"
    #_bs = pass          # ConstBitStream for scanning unalloc space
    _headers = []       # A list of EVT headers found
    _records = []       # A list of the EVT records found

    def searchFile(self, dataFile):
        """Search data for EVT log files. Return a tuple off header lists and
       record lists"""
        #TODO: check return of open()
        _bs = ConstBitStream(filename=dataFile)

        print "Searching for %s." % evt_header.MagicString

        i = 0
        # Find all occurrences of the magic string
        found = _bs.findall(evt_header.MagicString, bytealigned=False)
        for idx in found:
            _bs.pos = idx
            self._records.append(EvtRecord())
            r = self._records[i]
            r.setPosition(_bs.pos)

            # Message length
            readBits = 32
            lenIdx = idx - readBits     # Set stream position to idx of length
            _bs.pos = lenIdx
            recordLength = _bs.read(readBits).uintle
            self._records[i].setField("length", recordLength)
            r.setField("length", recordLength)

            # Calculate size of variable data at end of record 
            varDataSize = evt_record.FixedSize - recordLength 
            # When reading the size in a header
            if varDataSize < 0:
                varDataSize = 0

            # Reset stream position
            _bs.pos = idx

            # Message separator
            readBits = 32
            sep = _bs.read(readBits).uint
            r.setField("reserved", sep)

            # Record number
            readBits = 32
            recordNum = _bs.read(readBits).uintle
            r.setField("recordNumber", recordNum)

            # Date created
            readBits = 32
            created = _bs.read(readBits).uintle
            r.setField("timeGenerated", time.ctime(created))

            # Date written
            readBits = 32
            written = _bs.read(readBits).uintle
            r.setField("timeWritten", time.ctime(written))

            # Event ID
            #readBits = 32
            readBits = 16
            eventID = _bs.read(readBits).uintle
            r.setField("eventID", eventID)
         
            # Event RVA offset
            readBits = 16
            eventRVA = _bs.read(readBits).uintle
            r.setField("eventRVA", eventRVA)

            # Event type
            readBits = 16
            eventType = _bs.read(readBits).uint
            r.setField("eventType", eventType)

            # Num strings
            readBits = 16
            numStrings = _bs.read(readBits).uint
            r.setField("numStrings", numStrings)

            # Category
            readBits = 16
            category = _bs.read(readBits).uint
            r.setField("eventCategory", category)

            # Reserved flags 
            readBits = 16
            flags = _bs.read(readBits).uint
            r.setField("reservedFlags", flags)

            # Closing record number
            readBits = 32
            #readBits = 16
            recordNum = _bs.read(readBits).uint
            r.setField("closingRecordNumber", recordNum)

            # String offset
            readBits = 32
            stringOffset = _bs.read(readBits).uint
            r.setField("stringOffset", stringOffset)

            # User SID length
            readBits = 32
            sidLength = _bs.read(readBits).uint
            r.setField("userSidLength", sidLength)

            # User SID offset
            readBits = 32
            sidOffset = _bs.read(readBits).uint
            r.setField("userSidOffset", sidOffset)

            # Data length
            readBits = 32
            dataLength = _bs.read(readBits).uint
            r.setField("dataLength", dataLength)

            # Data offset
            readBits = 32
            dataOffset = _bs.read(readBits).uint
            r.setField("dataOffset", dataOffset)

            # Variable data
            readBits = varDataSize
            varData = _bs.read(readBits).bytes
            r.setField("varData", varData)

            i += 1
            r.printRecord()
            print
        return (self._headers, self._records)

    def parseLog(self, log):
        """Parse an EVT log file. Return an EvtLog object."""
        return 0

    def exportCSV(self, log, csvFile):
        """Export an EVT log to a CSV file. Returns the number of bytes written."""
        return 0

    def getName(self):
        return _name
