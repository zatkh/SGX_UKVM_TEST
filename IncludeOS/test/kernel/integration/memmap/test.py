#! /usr/bin/env python

import sys
import os

includeos_src = os.environ.get('INCLUDEOS_SRC',
                               os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))).split('/test')[0])
sys.path.insert(0,includeos_src)

from vmrunner import vmrunner


def test2():
  print "Booting VM 2 - lots of memory"
  vm = vmrunner.vm(config = "vm2.json")
  vm.boot(20, image_name = "build/test_memmap")

vm = vmrunner.vm(config = "vm1.json")
vm.on_exit_success(test2)
print "Booting VM 1 - default amount of memory"
vm.cmake().boot(20).clean()
