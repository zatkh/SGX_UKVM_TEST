include ./config.mk

global-incdirs-y += include






VPATH += include/bmfs

cflags-y += -Wall -Wextra -Werror -Wfatal-errors -std=gnu99 -Wno-declaration-after-statement -Wno-missing-prototypes -Wno-missing-declarations -Wno-pedantic
cflags-y += -O3
cflags-y += -fPIC
cflags-y += -ffreestanding

srcs-y += tfs.c
srcs-y += crc32.c
srcs-y += dir.c
srcs-y += disk.c
srcs-y += encoding.c
srcs-y += entry.c
srcs-y += errno.c
srcs-y += file.c
srcs-y += fs.c
srcs-y += header.c
srcs-y += host.c
srcs-y += memcpy.c
srcs-y += path.c
srcs-y += status.c
srcs-y += table.c

#srcs-y  += filedisk.c
srcs-y  += ramdisk.c
srcs-y  += time.c
srcs-y  += size.c
srcs-y  += stdhost.c
srcs-y += test_bmfs.c

cflags-lib-y += -Wno-unused-parameter
# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
