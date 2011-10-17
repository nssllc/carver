#!/usr/bin/env python
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
# carver.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
#  
# Usage: carver.py [-t <type>] <file>
#

import sys
sys.path.append("../lib")
from plugin import *
from evt_plugin import *
import evt_record

evt = EvtPlugin()
(headers, records) = evt.searchFile("../var/AppEvent.Evt")

for r in records:
    r.printRecord()
    print
