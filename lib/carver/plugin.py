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
# plugin.py
# David Windsor <dwindsor@networksecurityservicesllc.com>
#  
# Base class for data format plugins
#

class Plugin:
    """Base class for data format plugins"""
    def __init__(self):
        self._name = ""     # Short name used to identify this plugin 
        self._maxBufferSize = 1024 * 1024 * 100     # 100 MB limit 

    def search(self, data):
        """Search data for log files.  Return a list EvtLog objects."""
        return []

    def parseLog(self, log):
        """Parse a log file"""
        return 0

    def exportCSV(self, log):
        """Export a log file to a CSV file"""

    def getMaxBufferSize(self):
        return self._maxBufferSize
