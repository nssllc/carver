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
# evt_log_record_binary.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log record binary file definition 
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
#

from ctypes import *
import sys
from evt_record import *
from evt_plugin import *

if (sys.platform == "linux2" or sys.platform == "win32"):
    dword_type = c_uint
    word_type = c_ushort
else:
    dword_type = c_int
    word_type = c_short

class BinaryRecord(Structure):
    _fields_ = [
        ("length", dword_type),
        ("reserved", dword_type),
        ("recordNumber", dword_type),
        ("timeGenerated", dword_type),
        ("timeWritten", dword_type),
        ("eventID", dword_type),
        ("eventType", word_type),
        ("numStrings", word_type),
        ("eventCategory", word_type),
        ("reservedFlags", word_type),
        ("closingRecordNum", dword_type),
        ("stringOffset", dword_type),
        ("userSidLength", dword_type),
        ("userSidOffset", dword_type),
        ("dataLength", dword_type),
        ("dataOffset", dword_type)
    ]
