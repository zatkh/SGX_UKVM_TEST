# Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
#
# This file is part of Solo5, a unikernel base layer.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

export TOP=$(abspath .)
$(TOP)/Makeconf:
	./configure.sh
include Makefile.common

.PHONY: all
all: ukvm 
.DEFAULT_GOAL := all
.NOTPARALLEL: ukvm 


.PHONY: ukvm
ukvm:
ifeq ($(BUILD_UKVM), yes)
	$(MAKE) -C kernel ukvm
	$(MAKE) -C tests ukvm
endif


.PHONY: clean
clean:
	$(MAKE) -C kernel clean
ifeq ($(BUILD_UKVM), yes)
endif
	$(MAKE) -C tests clean
	$(RM) solo5-kernel-ukvm.pc
	$(RM) -r include-host/
	$(RM) Makeconf

PREFIX?=/nonexistent # Fail if not run from OPAM
OPAM_BINDIR=$(PREFIX)/bin
OPAM_UKVM_LIBDIR=$(PREFIX)/lib/solo5-kernel-ukvm
OPAM_UKVM_INCDIR=$(PREFIX)/include/solo5-kernel-ukvm/include


# We want the MD CFLAGS and LDFLAGS in the .pc file, where they can be
# picked up by the Mirage tool / other downstream consumers.
%.pc: %.pc.in
	sed <$< > $@ \
	    -e 's#!CFLAGS!#$(MD_CFLAGS)#g;' \
	    -e 's#!LDFLAGS!#$(LDFLAGS)#g;'


