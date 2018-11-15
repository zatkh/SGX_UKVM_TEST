#! /usr/bin/env python
import sys
import os

includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner
import socket


def transmit_test(grgr):
  print "<Test.py> Performing transmit tests"
  HOST, PORT = "10.0.0.49", 4242
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  data = "Someone there?"
  sock.sendto(data, (HOST, PORT))
  total_bytes = int(sock.recv(1024))

  print "<Test.py> Sent:     {}".format(data)
  print "<Test.py> Incoming: {} bytes".format(total_bytes)

  received = 0
  while (received < total_bytes):
      received += len(sock.recv(1024))

  print "<Test.py> Received: {}".format(received)

  data = "SUCCESS"
  sock.sendto(data, (HOST, PORT))
  print "<Test.py> Sent:     {}".format(data)


# Get an auto-created VM from the vmrunner
vm = vmrunner.vms[0]

# Add custom event-handler
vm.on_output("Ready", transmit_test)

# Boot the VM, taking a timeout as parameter
vm.cmake().boot(20).clean()
