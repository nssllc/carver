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

from bitstring import ConstBitStream
import copy
import plugin
import os
import sys
import evt_header
import evt_record
from evt_record import *

name = "evt"
desc = "Windows XP/2003 Event Log Plugin"
version = "1.0"

class EvtPlugin(plugin.Plugin):
    """A carver plugin for reading Windows Event Log Files"""
    def __init__(self):
        self._headers = []  # List of the headers found
        self._records = []  # List of the records found

    def printPluginHeader(self):
        """Print a banner designating the EVT plugin"""
        print "%s, version %s" % (desc, version)

    def sortByTimeGenerated(self, records, verbose=False, in_place=False):
        """Sort records by time generated.  Performs bubble sort."""
        tmp = records
        if (verbose):
            print "[EVT] Sorting by time generated"

        for i in range(len(tmp)):
            for j in range(len(tmp)):
                ni = tmp[i].getField("timeGenerated")
                nj = tmp[j].getField("timeGenerated")
                if nj > ni:
                    t = tmp[j]
                    tmp[j] = tmp[i]
                    tmp[i] = t
        return tmp

    def sortByRecordNum(self, records, verbose=False, in_place=False):
        """Sort records by record number.  Performs bubble sort."""
        tmp = records    # copy of records for sorting
        if (verbose):
            print "[EVT] Sorting by record number"

        for i in range(len(tmp)):
            for j in range(len(tmp)):
                ni = tmp[i].getField("recordNumber")
                nj = tmp[j].getField("recordNumber")
                if tmp[j] > tmp[i]:
                    t = tmp[j]
                    tmp[j] = tmp[i]
                    tmp[i] = t
        return tmp
                
    def searchFile(self, dataFile, verbose=False):
        """Search data for EVT log files. Return a tuple of \
        header lists and record lists"""
        if (verbose):
            self.printPluginHeader()
            print "[EVT] Searching %s" % os.path.abspath(dataFile)

        _bs = ConstBitStream(filename=dataFile)

        i = 0
        # Find all occurrences of the magic string
        found = _bs.findall(evt_header.MagicString, bytealigned=False)
        for idx in found:
            _bs.pos = idx
            r = EvtRecord()
            r.setPosition(_bs.pos)

            # Message length
            readBits = 32
            lenIdx = idx - readBits     # Set position to idx of length
            _bs.pos = lenIdx
            recordLength = _bs.read(readBits).uintle
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
            r.setField("timeGenerated", created)

            # Date written
            readBits = 32
            written = _bs.read(readBits).uintle
            r.setField("timeWritten", written)

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

            rec = copy.copy(r)
            self._records.append(rec)

        if (verbose):
            print "[EVT] Found %d headers, %d records" % (len(self._headers), \
                len(self._records))
        return (self._headers, self._records)

    def parseLog(self, log):
        """Parse an EVT log file. Return an EvtLog object."""
        return 0

    def exportCSV(self, log, csvFile):
        """Export an EVT log to a CSV file. Returns the number of bytes written."""
        return 0
