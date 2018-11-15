#! /usr/bin/env python

import sys
import os
import subprocess
import subprocess32

thread_timeout = 20
includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner
from vmrunner.prettify import color

# Install build dependencies, ip forwarding
subprocess.call(["bash", "setup.sh"])

# Get an auto-created VM from the vmrunner
vm = vmrunner.vms[0]

counter = 0

def count(trigger_line):
  global counter
  counter += 1

  if counter == 4:
    finish()

def finish():
  vm.exit(0, "DNS resolution test succeeded")

# Add custom event-handler
vm.on_output("Resolved IP address of google.com with DNS server 8.8.8.8", count)
vm.on_output("Resolved IP address of theguardian.com with DNS server 4.2.2.1", count)
vm.on_output("Resolved IP address of github.com with DNS server 8.8.8.8", count)
vm.on_output("some_address_that_doesnt_exist.com couldn't be resolved", count)

# Boot the VM, taking a timeout as parameter
vm.cmake().boot(thread_timeout).clean()
