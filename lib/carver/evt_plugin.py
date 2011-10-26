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

import bitstring
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
version = "1.2"

class EvtPlugin(plugin.Plugin):
    """A carver plugin for reading Windows Event Log Files"""

    max_buf_bytes = 500 * 1024 * 1024   # size limit on buffers
    ERROR_END_OF_STREAM = -1            # End of bitstream error constant

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

        swapped = True
        while swapped:
            swapped = False
            for i in xrange(len(tmp)-1):
                ni = tmp[i].getField("timeGenerated")
                nj = tmp[i+1].getField("timeGenerated")
                if ni > nj:
                    t = tmp[i+1]
                    tmp[i+1] = tmp[i]
                    tmp[i] = t
                    swapped = True
        return tmp

    def sortByRecordNum(self, records, verbose=False, in_place=False):
        """Sort records by record number.  Performs bubble sort."""
        tmp = records    # copy of records for sorting
        if (verbose):
            print "[EVT] Sorting by record number"

        swapped = True
        while swapped:
            swapped = False
            for i in xrange(len(tmp)-1):
                ni = tmp[i].getField("recordNumber")
                nj = tmp[i+1].getField("recordNumber")
                if ni > nj:
                    t = tmp[i+1]
                    tmp[i+1] = tmp[i]
                    tmp[i] = t
                    swapped = True
        return tmp
                
    def searchFile(self, dataFile, verbose=False):
        """Search data for EVT log files. Return a tuple of \
        header lists and record lists"""
        if (verbose):
            self.printPluginHeader()
            print "[EVT] Searching %s" % os.path.abspath(dataFile)

        file_bytes = os.path.getsize(dataFile)
        if verbose:
            print "[EVT] %s: size = %d bytes" % \
                (os.path.basename(dataFile), file_bytes)
    
        # Split dataFile into manageable chunks if it is too big
        if file_bytes > self.max_buf_bytes:
            pass_bytes = self.max_buf_bytes   # Bytes to read this pass
            if verbose:
                print "[EVT] %s: splitting into chunks of size %d" % \
                    (os.path.basename(dataFile), pass_bytes)
            read_bytes = 0
            while read_bytes < file_bytes:
                # Calculate number of bytes left to read
                pass_bytes = file_bytes - read_bytes
                if pass_bytes > self.max_buf_bytes:
                    pass_bytes = self.max_buf_bytes

                # Read pass_bytes and pass it to carve()
                f = open(dataFile, "r")
                f.seek(read_bytes)  # offset = bytes read so far 
                print "Reading %d bytes from %s.." % (pass_bytes, dataFile)
                rbytes = f.read(pass_bytes)
                _bs = ConstBitStream(bytes=rbytes)
                (headers, records) = self.carve(_bs, dataFile, verbose)

                read_bytes += pass_bytes 
                for h in headers:
                    self._headers.append(h)
                for r in records:
                    self._records.append(r)
        else:
            f = open(dataFile, "r")
            rbytes = f.read(file_bytes)
            _bs = ConstBitStream(bytes=rbytes)
            #_bs = ConstBitStream(filename=dataFile, offset=0,\
            #    length=file_bytes)
            (self._headers, self._records) = \
                self.carve(_bs, dataFile, verbose)

        if verbose:
            print "[EVT] Found %d headers, %d records" % \
                (len(self._headers), len(self._records))
        return (self._headers, self._records)

    def carveField(self, bs, name, data_type, size, verbose):
        if size + bs.pos > bs.len:
            if verbose:
                print "[EVT] Unable to read field %s: "\
                    "end of stream reached" % name
            return self.ERROR_END_OF_STREAM
        data = bs.read(data_type + ":" + str(size))
        return data

    def carve(self, bs, dataFile, verbose=False):
        """Carve EVT records from a bitstream.  Return a tuple of \
        header list and record list."""
        _bs = bs
        records = []
        headers = []

        i = 0
        # Find all occurrences of the magic string
        found = _bs.findall(evt_header.MagicString, bytealigned=False)
        readSoFarBits = 0
        for idx in found:
            _bs.pos = idx
            r = EvtRecord()
            r.setPathname(dataFile)
            r.setPosition(_bs.pos)

            # Read an EVT header field:
            #   The algorithm here is to find the message separator 
            #   and use that as a basis for locating the other fields.
            #   Since we split large input files, "offset" fields are
            #   invalid.  

            # Message length
            fieldBits = 32
            lenIdx = idx - fieldBits     # Set position to idx of length
            _bs.pos = lenIdx
            recordLength = _bs.read(fieldBits).uintle
            r.setField("length", recordLength)
            readSoFarBits += fieldBits

            # Calculate size of variable data at end of record 
            varDataSize = evt_record.FixedSize - recordLength 
            # When reading the size in a header
            if varDataSize < 0: 
                varDataSize = 0

            # Reset stream position
            _bs.pos = idx

            # Message separator
            fieldBits = 32 
            # Check to see if we are reading past end of stream
            data = self.carveField(_bs, "reserved", "uint",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("reserved", data)

            # Record number
            fieldBits = 32 
            data = self.carveField(_bs, "recordNumber", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("recordNumber", data)

            # Date created
            fieldBits = 32 
            data = self.carveField(_bs, "timeGenerated", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("timeGenerated", data)

            # Date written
            fieldBits = 32 
            data = self.carveField(_bs, "timeWritten", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("timeWritten", data)

            # Event ID
            fieldBits = 16 
            data = self.carveField(_bs, "eventID", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("eventID", data)
         
            # Event RVA offset
            fieldBits = 16 
            data = self.carveField(_bs, "eventRVA", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("eventRVA", data)

            # Event type
            fieldBits = 16 
            data = self.carveField(_bs, "eventType", "uintle",\
                    fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("eventType", data)

            # Num strings
            fieldBits = 16 
            data = self.carveField(_bs, "numStrings", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("numStrings", data)

            # Category
            fieldBits = 16 
            data = self.carveField(_bs, "eventCategory", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("eventCategory", data)

            # Reserved flags 
            fieldBits = 16 
            data = self.carveField(_bs, "reservedFlags", "uint",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("reservedFlags", data)

            # Closing record number
            fieldBits = 32 
            data = self.carveField(_bs, "closingRecordNumber", "uint",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("closingRecordNumber", data)

            # String offset
            fieldBits = 32 
            data = self.carveField(_bs, "stringOffset", "uint",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("stringOffset", data)

            # User SID length
            fieldBits = 32
            data = self.carveField(_bs, "userSidLength", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("userSidLength", data)

            # User SID offset
            fieldBits = 32 
            data = self.carveField(_bs, "userSidOffset", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("userSidOffset", data)

            # Data length
            fieldBits = 32 
            data = self.carveField(_bs, "dataLength", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("dataLength", data)

            # Data offset
            fieldBits = 32
            data = self.carveField(_bs, "dataOffset", "uintle",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("dataOffset", data)

            # Variable data
            # FIXME: dont rely on peek() to avoid reading past end of stream
            fieldBits = int(r.getField("length"))
            try:
                data = _bs.peek("bytes" + ":" + str(fieldBits))
            except bitstring.ReadError:
                if verbose:
                    print "[EVT]: Unable to read EVT data field; "\
                        "it would be truncated"
                break
            data = self.carveField(_bs, "varData", "bytes",\
                fieldBits, verbose)
            if data == self.ERROR_END_OF_STREAM:
                break
            r.setField("varData", data)

            # SID
            # FIXME: find out why sidLength is so weird
            #sidLength = r.getField("userSidLength")
            #if sidLength > 0:
            #    sidOffset = r.getField("userSidOffset")
            #    if sidOffset <= _bs.length:
            #        _bs.pos = sidOffset
            #        fieldBits = sidLength
            #        if readSoFarBits + fieldBits >= _bs.len:
            #            fieldBits = _bs.len - _bs.pos
            #            sid = _bs.read(fieldBits).uint
            #            r.setField("sid", sid)
            #            break
            #        sid = _bs.read(fieldBits).uint
            #        r.setField("sid", sid)
            #readSoFarBits += fieldBits
            records.append(r)
        return (headers, records)

    def parseLog(self, log):
        """Parse an EVT log file. Return an EvtLog object."""
        return 0

    def printCsv(self):
        """Print a CSV representation of the records found"""
        self.printCsvHeader()
        for r in self._records:
            r.printCsv()

    def printCsvHeader(self):
        """Print the CSV preamble"""
        print "SOURCE FILENAME, RECORD NUMBER, TIME GEN, "\
            "TIME WRITE, CATEGORY, EVENTID, SOURCE, "\
            "COMPUTER, SID, STRINGS, RAW DATA (HEX), "\
            "DECODED DATA"

    def exportCSV(self, log, csvFile):
        """Export an EVT log to a CSV file. Returns the number of bytes written."""
        return 0
