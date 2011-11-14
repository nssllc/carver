#!/usr/bin/env python
#
# Test carver's ability to process configuration files.
# This test exercises every carver input plugin.
#
# Usage: config_file_test.py <config file> <data file>
#

import config;
import carver_lib;
import evt_plugin;
import sys;

def verify_results(headers, records, name):
    """Verify the results of this test. Returns True if the test has \
    passed, False otherwise."""
    # Determine which kind of records we have
    if name == evt_plugin.name:
        print "Testing EVT plugin.", 
        if records[0].getField("reserved") != "eLfL":
            print "[FAILED] Unmatched field: reserved"
            return False
    else:
        print "[FAILED] Internal error."
        return False

    if len(records) != 1:
        print "[FAILED] Incorrect number of records found."
        return False

if len(sys.argv) != 3:
    print "Usage: %s <config file> <data file>" % sys.argv[0]
    sys.exit(1)

cfg_path = sys.argv[1]
data_path = sys.argv[2]

cf = config.ConfigFile(cfg_path)

# Get a list of supported plugins
for name in carver_lib.getSupportedTypes():
    plugin = carver_lib.getPlugin(name)
    (headers, records) = plugin.searchFile(data_path, cfg_path, verbose=True)
    passed = verify_results(headers, records, name)
    if passed:
        print "[PASSED]"

