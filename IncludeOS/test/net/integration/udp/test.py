#! /usr/bin/env python

import sys
import os

includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
print 'includeos_src: {0}'.format(includeos_src)
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner
import socket

# Get an auto-created VM from the vmrunner
vm = vmrunner.vms[0]

def UDP_test(trigger_line):
  print "<Test.py> Performing UDP tests"
  HOST, PORT = "10.0.0.55", 4242
  sock = socket.socket
  # SOCK_DGRAM is the socket type to use for UDP sockets
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

  # NOTE: This is necessary for the test to exit after the VM has
  # been shut down due to a VM timeout
  sock.settimeout(20)

  data = "Lucky"
  sock.sendto(data, (HOST, PORT))
  received = sock.recv(1024)

  print "<Test.py> Sent:     {}".format(data)
  print "<Test.py> Received: {}".format(received)
  if received != data: return False

  data = "Luke"
  sock.sendto(data, (HOST, PORT))
  received = sock.recv(1024)

  print "<Test.py> Sent:     {}".format(data)
  print "<Test.py> Received: {}".format(received)
  if received != data: return False

  data = "x" * 1472
  sock.sendto(data, (HOST, PORT))
  received = sock.recv(1500)
  if received != data:
      print "<Test.py> Did not receive long string: {}".format(received)
      return False

  data = "x" * 9216 # 9216 is apparently default max for MacOS
  sock.sendto(data, (HOST, PORT))
  received = bytearray()
  while (len(received) < len(data)):
        received.extend(sock.recv(len(data)))
        print "RECEIVED: ", len(received)
  if received != data:
      print "<Test.py> Did not receive mega string (64k)"
      return False

  vmrunner.vms[0].exit(0, "Test completed without errors")

# Add custom event-handler
vm.on_output("UDP test service", UDP_test)

# Boot the VM, taking a timeout as parameter
vm.cmake().boot(30).clean()
