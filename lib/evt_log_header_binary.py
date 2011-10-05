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
# evt_log_header_binary.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log header binary file definition 
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309024(v=vs.85).aspx
#

from ctypes import *
from evt_record import *
from evt_plugin import *

class BinaryHeader(Structure):
    _fields_ = [
        ("headerSize", c_ulong),
        ("signature", c_ulong),
        ("majorVersion", c_ulong),
        ("minorVersion", c_ulong),
        ("startOffset", c_ulong),
        ("endOffset", c_ulong),
        ("currentRecordNum", c_ulong),
        ("oldestRecordNum", c_ulong),
        ("maxSize", c_ulong),
        ("flags", c_ulong),
        ("retention", c_ulong),
        ("endHeaderSize", c_ulong),
    ]
