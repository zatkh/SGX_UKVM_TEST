#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	for (const char *p = "Hello world!\n"; *p; ++p)
		outb(0xE9, *p);


	*(long *) 0x400 = 42;
//printf("hey what the fuck!");
	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}

