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

import plugin

# EVT logfile header magic numbers
evt_header_magic['size'] = "0x30"             # Size of header structure
evt_header_magic['signature'] = "0x654c664c"  # Header signature
evt_header_magic['majorVersion'] = "1"        # Major version of event log
evt_header_magic['minorVersion'] = "1"        # Minor version of event log
evt_header_magic['endSize'] = "0x30"          # Ending size of header structure

class EvtPlugin(plugin.Plugin):
"""A carver plugin for reading Windows Event Log Files"""
    def search(self, data):
    """Search data for EVT log files. Return a list of EvtLog objects.""" 
        return []

    def parseLog(self, log):
    """Parse an EVT log file. Return an EvtLog object."""
        return 0

    def exportCSV(self, log, csvFile):
    """Export an EVT log to a CSV file. Returns the number of bytes written."""
        return 0
