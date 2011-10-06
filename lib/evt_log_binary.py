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
# evt_log_binary.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
# 
# Windows Event Log binary file definition 
# Specification taken from:
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb309024(v=vs.85).aspx
#

from ctypes import *
from evt_record import *
from evt_plugin import *
from evt_log_header_binary import *
from evt_log_record_binary import *
from evt_log_footer_binary import *

class BinaryLog(Structure):
    _fields_ = [
        # Header
        ("header", BinaryHeader),

        # Records
        ("record1", BinaryRecord),
        ("recordN", BinaryRecord),

        # Footer
        ("footer", BinaryFooter),
    ]
