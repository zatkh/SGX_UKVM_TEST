#! /usr/bin/env python

import sys
import os

includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner

vm = vmrunner.vms[0]

tests_ok = 0

def test_ok(line):
    global tests_ok
    tests_ok += 1
    if (tests_ok == 2):
        vm.exit(0, "All tests passed")

def expected_panic(line):
    print "<test.py> VM panicked"
    if (tests_ok == 1):
        return True
    else:
        return False

def test_fail(line):
    print "Test didn't get expected panic output before end of backtrace"
    return False

vm.on_output("Part 1 OK", test_ok)
vm.on_panic(expected_panic, False)
vm.on_output("Uncaught exception expecting panic", test_ok)
vm.on_output("long_mode", test_fail)

vm.cmake().boot(30).clean()
