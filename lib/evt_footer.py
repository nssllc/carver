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
# evt_footer.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Internal representation of an EVT log footer
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026(v=vs.85).aspx
#

magic["recordSizeBeginning"] = "0x28"
magic["one"] = "0x11111111"
magic["two"] = "0x22222222"
magic["three"] = "0x33333333"
magic["four"] = "0x44444444"
magic["recordSizeEnd"] = "0x28"

class EvtFooter:
"""Internal representation of an EVT log footer"""
    _fields["recordSizeBeginning"] = magic["recordSizeBeginning"]
    _fields["one"] = magic["one"]
    _fields["two"] = magic["two"]
    _fields["three"] = magic["three"]
    _fields["four"] = magic["four"]
    _fields["beginRecord"] = ""
    _fields["endRecord"] = ""
    _fields["currentRecordNum"] = ""
    _fields["oldestRecordNum"] = ""
    _fields["recordSizeEnd"] = magic["recordSizeEnd"]

    def getField(self, key):
        if key not in _fields:
            print "Unknown field " + key
            return
        return _fields[key]

    def setField(self, key, val):
        if key not in _fields:
            print "Unknown field " + key
            return
        _fields[key] = val

    _fields["headerSize"] = magic["headerSize"]
    _fields["signature"] = magic["signature"]
    _fields["majorVersion"] = magic["majorVersion"]
    _fields["minorVersion"] = magic["minorVersion"]
    _fields["startOffset"] = ""
    _fields["endOffset"] = ""
    _fields["currentRecordNum"] = ""
    _fields["oldestRecordNum"] = ""
    _fields["maxSize"] = ""
    _fields["flags"] = ""
    _fields["retention"] = ""
    _fields["endHeaderSize" = magic["endHeaderSize"]

    def getField(self, key):
        if key not in fields:
            print "Unknown field " + key
            return
        return _fields[key]

    def setField(self, key, val):
        if key not in fields:
            print "Unknown field " + key
            return
        _fields[key] = val

    

