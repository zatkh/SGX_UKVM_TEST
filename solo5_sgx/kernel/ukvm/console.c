/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
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

#include "kernel.h"

int platform_puts(const char *buf, int n)
{
    struct ukvm_puts str;

    str.data = (char *)buf;
    str.len = n;

    ukvm_do_hypercall(UKVM_HYPERCALL_PUTS, &str);

    return str.len;
}

int platform_test(const char *buf, int n)
{
    struct ukvm_test str;

    str.data = (char *)buf;
    str.len = n;

    ukvm_do_hypercall(UKVM_SGX_HELLO, &str);

    return str.len;
}

void send_val(size_t val)
{
    struct ukvm_get_val gval;

    gval.val = val;

    ukvm_do_hypercall(UKVM_HYPERCALL_GET_VAL, &gval);

}


void solo5_sgx_hello(const char *buf, size_t size)
{
    (void)platform_test(buf, size);
}


void solo5_console_write(const char *buf, size_t size)
{
    (void)platform_puts(buf, size);
}

void solo5_console_send_val( size_t val)
{
    (void)send_val(val);
}

void console_init(void)
{
}
