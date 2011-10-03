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
# The plugin infrastructure of carver
#

class Plugin:
"""Generic plugin class.  Extend this class for format-specific support."""
    _name = ""
    _versionMajor = 0
    _versionMinor = 0
    _description = ""
    _file

    def __init__(self, name, major, minor, desc):
        _name = name
        _versionMajor = major
        _versionMinor = minor
        _description = desc

    def search(self, data):
    """Search data for log files.  Return a list EvtLog objects."""
        return []

    def parseLog(self, log):
    """Parse a log file"""
        return 0

    def exportCSV(self, log):
    """Export a log file to a CSV file"""


    
