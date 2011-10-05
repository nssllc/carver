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
# GlNU Gen eral Public License for more details.
# 
# carver.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
#  
# Usage: carver.py [-t <type>] <file>
#

from plugin import *
from evt_plugin import *

evtPlugin = EvtPlugin()
(evtHeaders, evtRecords) = evtPlugin.searchFile("unalloc.bin")

print "Found " + evtHeaders.size() " EVT headers."
print "Found " + evtRecords.size() " EVT records."
