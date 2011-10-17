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
# evt_timestamp_plugin.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log timestamp plugin
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026(v=vs.85).aspx
#

import plugin

# EVT logfile header magic numbers
evt_header_magic['size'] = "0x30"             # Size of header structure
evt_header_magic['signature'] = "0x654c664c"  # Header signature
evt_header_magic['majorVersion'] = "1"        # Major version of event log
evt_header_magic['minorVersion'] = "1"        # Minor version of event log
evt_header_magic['endSize'] = "0x30"          # Ending size of header structure

class EvtPlugin(plugin.Plugin):
"""A carver plugin for reading Windows Event Log Files"""
    _name = "evt"

    def searchFile(self, dataFile):
    """Search data for EVT log files. Return a tuple off header lists and
       record lists"""
        try:
            f = open(data, "r")
        except IOError:
            print "Unable to open file " + data + ": " + strerror
            return -1
       
        #TODO: Byte-scan for magic string
        #TODO: Read MAXBUFFERSIZE bytes if file is bigger than MAXBUFFERSIZE
        bufferSize = f.size()
        if (bufferSize < getMaxBufferSize()):
            bufferSize = getMaxBufferSize()
        dataBytes = f.readBytes()
      
        # Offsets in the data file where records were found (reporting purposes)
        headerOffsets = []
        recordOffsets = []

        # Forward decls
        headers = []
        records = []

        #TODO: Find each occurrence of the magic string in the buffer
        match = dataBytes.StrPosition(evt_log.MagicString)
        while (match):
            #TODO: find the start of the EVT record based upon the offset 
            #      of the magic string in the record's header
            
            #TODO: go back (sizeof c_ulong) to get headerSize & start of header
            #TODO: --- OR --- (need to determine if match is header or record!)
            #TODO: go back (sizeof DWORD) to get length & start of record
            idx = match.index() # index in dataBytes of the match
            recordOffsets.append(idx)    # Add index to found offsets

            length = dataBytes[idx]
            idx += sizeof(DWORD)    # increment index by sizeof element just read
            reserved = dataBytes[idx]
            idx += sizeof(DWORD)
            recordNumber = dataBytes[idx]
            idx += sizeof(DWORD)
            timeGenerated = dataBytes[idx]
            idx += sizeof(DWORD)
            dataOffset = dataBytes[idx]
            records.append(BinaryRecord(
                length,
                reserved,
                recordNumber,
                timeGenerated,
                dataOffset))
            
            #TODO: match was part of header rather than record
            idx = match.index() # index in dataBytes of the match
            headerOffsets.append(idx)

            headerSize = dataBytes[idx]
            idx += sizeof(c_ulong)
            signature = dataBytes[idx]
            idx += sizeof(c_ulong)
            majorVersion = dataBytes[idx]
            idx += sizeof(c_ulong)
            minorVersion = dataBytes[idx]
            idx += sizeof(c_ulong)
            endHeaderSize = dataBytes[idx]
            headers.append(BinaryHeader(
                headerSize,
                signature,
                majorVersion,
                minorVersion,
                endHeaderSize))

        #for h in headers:
        #    internalHeaders.append(EvtHeader(h))
        #for r in records:
        #    internalRecords.append(EvtRecord(r))
        #return (internalHeaders, internalRecords)

        #TODO: headers & records contain binary ctypes definitions
        #TODO: convert these to EvtRecord types?
        return (headers, records)

    def parseLog(self, log):
    """Parse an EVT log file. Return an EvtLog object."""
        return 0

    def exportCSV(self, log, csvFile):
    """Export an EVT log to a CSV file. Returns the number of bytes written."""
        return 0

    def getName(self):
        return _name
