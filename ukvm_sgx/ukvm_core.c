/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_core.c: Core functionality.
 *
 * Maintains tables of modules, hypercall handlers and vmexit handlers.
 * Implements core hypercall functionality which is always present.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "ukvm.h"

// enclave headers
#include "sgx_urts.h"
#include "main.h"
#include "enclave_u.h"

struct ukvm_module ukvm_module_core;

struct ukvm_module *ukvm_core_modules[] = {
    &ukvm_module_core,
#ifdef UKVM_MODULE_BLK
    &ukvm_module_blk,
#endif
#ifdef UKVM_MODULE_NET
    &ukvm_module_net,
#endif
#ifdef UKVM_MODULE_GDB
    &ukvm_module_gdb,
#endif
    NULL,
};
#define NUM_MODULES ((sizeof ukvm_core_modules / sizeof (struct ukvm_module *)) - 1)

ukvm_hypercall_fn_t ukvm_core_hypercalls[UKVM_HYPERCALL_MAX] = { 0 };

// register the hypercall handler
int ukvm_core_register_hypercall(int nr, ukvm_hypercall_fn_t fn)
{
    if (nr >= UKVM_HYPERCALL_MAX)
        return -1;
    if (ukvm_core_hypercalls[nr] != NULL)
        return -1;

    ukvm_core_hypercalls[nr] = fn;
    return 0;
}

ukvm_vmexit_fn_t ukvm_core_vmexits[NUM_MODULES + 1] = { 0 };
static int nvmexits = 0;

int ukvm_core_register_vmexit(ukvm_vmexit_fn_t fn)
{
    if (nvmexits == NUM_MODULES)
        return -1;

    ukvm_core_vmexits[nvmexits] = fn;
    nvmexits++;
    return 0;
}
//hypercall handlers
static void hypercall_walltime(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_walltime *t =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_walltime));
    struct timespec ts;

    int rc = clock_gettime(CLOCK_REALTIME, &ts);
    assert(rc == 0);
    t->nsecs = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

static void hypercall_puts(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_puts *p =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_puts));
    int rc = write(1, UKVM_CHECKED_GPA_P(hv, p->data, p->len), p->len);
    assert(rc >= 0);
}

static void sgx_test(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    //printf("[sgx_test] enter \n");
    struct ukvm_test *p =
    UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_test));
    int rc = write(1, UKVM_CHECKED_GPA_P(hv, p->data, p->len), p->len);

    int val=100;
    ecall_test(global_eid,val);

    //printf("[sgx_test]: after ecall_tes\n");

    assert(rc >= 0);
}



static void hypercall_get_val(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_get_val *p =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_get_val));
    
    printf("[hypercall_get_val] val: %ld \n", p-> val);
}



static struct pollfd pollfds[NUM_MODULES];
static int npollfds = 0;
static sigset_t pollsigmask;

int ukvm_core_register_pollfd(int fd)
{
    if (npollfds == NUM_MODULES)
        return -1;

    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = POLLIN;
    npollfds++;
    return 0;
}

static void hypercall_poll(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_poll *t =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_poll));
    struct timespec ts;
    int rc;

    ts.tv_sec = t->timeout_nsecs / 1000000000ULL;
    ts.tv_nsec = t->timeout_nsecs % 1000000000ULL;

    rc = ppoll(pollfds, npollfds, &ts, &pollsigmask);
    assert(rc >= 0);
    t->ret = rc;
}


static void sgx_blkwrite(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_blkwrite *wr =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_blkwrite));

   printf("[sgx_blkwrite] enter %s, len %ld\n",(char*) UKVM_CHECKED_GPA_P(hv, wr->data, wr->len), wr->len );
    int ret=0;
    ecall_write_blk(global_eid, &ret, UKVM_CHECKED_GPA_P(hv, wr->data, wr->len),wr->len );


}


static void sgx_blkread(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{

    struct ukvm_blkread *rd =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_blkread));
 printf("[sgx_blkread] enter \n");
    int ret=0;
    ecall_read_blk(global_eid, &ret,UKVM_CHECKED_GPA_P(hv, rd->data, rd->len), rd->len );

}

static void sgx_blkseek(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{

    int ret=0;
     printf("[sgx_blkseek] enter \n");
     ecall_seek(global_eid, &ret);
}

static void sgx_blkinit(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
     struct ukvm_test *p =
    UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_test));
    printf("[sgx_blkinit] enter\n");
    ecall_init_blk(global_eid);
    printf("[sgx_blkinit] after\n");

}

static int setup(struct ukvm_hv *hv)
{
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_WALLTIME,
                hypercall_walltime) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_PUTS,
                hypercall_puts) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_POLL,
                hypercall_poll) == 0);
    assert(ukvm_core_register_hypercall(UKVM_SGX_HELLO,
                sgx_test) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_GET_VAL,
                hypercall_get_val) == 0);
    assert(ukvm_core_register_hypercall(UKVM_SGX_BLKINIT,
                sgx_blkinit) == 0);               
    assert(ukvm_core_register_hypercall(UKVM_SGX_BLKWRITE,
                sgx_blkwrite) == 0); 
    assert(ukvm_core_register_hypercall(UKVM_SGX_BLKSEEK,
                sgx_blkseek) == 0);  
    assert(ukvm_core_register_hypercall(UKVM_SGX_BLKREAD,
                sgx_blkread) == 0);  


    /*
     * XXX: This needs documenting / coordination with the top-level caller.
     */
    sigfillset(&pollsigmask);
    sigdelset(&pollsigmask, SIGTERM);
    sigdelset(&pollsigmask, SIGINT);

    return 0;
}

struct ukvm_module ukvm_module_core = {
    .name = "core",
    .setup = setup
};
