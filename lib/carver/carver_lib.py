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
# Infrastructure for loading plugins
#

# Append the plugin dir to the module search path 
import os
import sys
moduleDir = os.path.dirname(__file__ + "../")
sys.path.append(os.path.abspath(moduleDir + "/"))
sys.path.append(os.path.abspath(moduleDir + "argparse/"))
sys.path.append(os.path.abspath(moduleDir + "bitstring/"))

import argparse
import bitstring
import plugin
import evt_plugin

# Library version
version = "1.0.1"

def __init__():
    pass

def getPlugin(name):
    """Returns a Plugin based on name or None for no matches."""
    if name == evt_plugin.name:
        return evt_plugin.EvtPlugin()
    return None

def getSupportedTypes():
    """Returns a list of supported plugins."""
    return evt_plugin.name

def getVersion():
    """Returns the library version"""
    return version
