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
   
    def length(self):
        return _length
    def setLength(self):
        _length = x

    def reserved(self):
        return _reserved
    def setReserved(self, x):
        _reserved = x

    def recordNumber(self):
        return _recordNumber
    def setRecordNumber(self, x):
        _recordNumber = x

    def timeGenerated(self):
        return _timeGenerated
    def setTimeGenerated(self, x):
        _timeGenerated = x

    def timeWritten(self):
        return _timeWritten
    def setTimeWritten(self, x):
        _timeWritten = x

    def eventID(self):
        return _eventID
    def setEventID(self, x):
        _eventID = x

    def eventType(self):
        return _eventType
    def setEventType(self, x):
        _eventType = x

