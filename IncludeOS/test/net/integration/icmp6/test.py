#! /usr/bin/env python

import sys
import os
import subprocess

includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner
from vmrunner.prettify import color

import socket

# Get an auto-created VM from the vmrunner
vm = vmrunner.vms[0]

num_successes = 0

def start_icmp_test(trigger_line):
  global num_successes

  # 1 Ping: Checking output from callback in service.cpp
  print color.INFO("<Test.py>"), "Performing ping6 test"

  output_data = ""
  for x in range(0, 9):
    output_data += vm.readline()

  print output_data

  if "Received packet from gateway" in output_data and \
    "Identifier: 0" in output_data and \
    "Sequence number: 0" in output_data and \
    "Source: fe80:0:0:0:e823:fcff:fef4:83e7" in output_data and \
    "Destination: fe80:0:0:0:e823:fcff:fef4:85bd" in output_data and \
    "Type: ECHO REPLY (129)" in output_data and \
    "Code: DEFAULT (0)" in output_data and \
    "Checksum: " in output_data and \
    "Data: INCLUDEOS12345ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678" in output_data:
    num_successes += 1
    print color.INFO("<Test.py>"), "Ping test succeeded"
  else:
    print color.FAIL("<Test.py>"), "Ping test FAILED"
    vm.exit(1, 666)

  if num_successes == 1:
    vm.exit(0, "<Test.py> All ICMP tests succeeded. Process returned 0 exit status")

vm.on_output("Service IPv4 address: 10.0.0.52, IPv6 address: fe80:0:0:0:e823:fcff:fef4:85bd", start_icmp_test);

# Boot the VM, taking a timeout as parameter
vm.cmake().boot(50).clean()
