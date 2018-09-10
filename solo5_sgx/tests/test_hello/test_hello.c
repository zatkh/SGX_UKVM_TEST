#include "solo5.h"
#include "../../kernel/lib.c"

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

int solo5_app_main(const struct solo5_start_info *si)
{
    puts("\n**** Solo5 standalone test_hello ****\n\n");
    puts("Hello, World\nCommand line is: '");

    size_t len = 0;
    const char *p = si->cmdline;

    while (*p++)
        len++;
    solo5_console_write(si->cmdline, len);

    puts("'\n");

    /* "Hello_Solo5" will be passed in via the command line */
    if (strcmp(si->cmdline, "Hello_Solo5") == 0)
        puts("SUCCESS\n");

    return SOLO5_EXIT_SUCCESS;
}
