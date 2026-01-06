/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "debug_printf.h"

#include "regtable.h"
#include "rom_uart.h"

#include "stddef.h"
#include "stdarg.h"

static const char hexdigits[] = "0123456789ABCDEF";

static void print_hex_buffer(void (*addchar)(int c), int pad_width, 
                              unsigned int val, unsigned int base)
{
	if (pad_width - 1 > 0 || val >= base)
		print_hex_buffer(addchar, pad_width - 1, val / base, base);
	
	addchar(hexdigits[val % base]);
}

int vfnprintf(void (*addchar)(int c),
	      const char *format, va_list args)
{
	while (*format) {
		int c = *format++;

		/* Copy normal characters */
		if (c != '%') {
			if (c == '\n')
				addchar('\r');
			
			addchar(c);
			continue;
		}

		/* Get first format character */
		c = *format++;

		if (c == '\0')
			break;

		/* Count padding length */
		int pad_width = 0;
		while (c >= '0' && c <= '9') {
			pad_width = (10 * pad_width) + c - '0';
			c = *format++;
		}

		if (c == 'd') {
			int val = va_arg(args, int);
			
			if (val < 0) {
				addchar('-');
				val = -val;
			}
			
			print_hex_buffer(addchar, pad_width, val, 10);
		} else if (c == 'h') {
			int len = va_arg(args, int);
			char *ptr = va_arg(args, char *);
			
			while (len > 0) {
				unsigned char byte = *ptr++;
				addchar(hexdigits[byte >> 4]);
				addchar(hexdigits[byte & 0xf]);
				len--;
			}
		} else if (c == 'x') {
			unsigned int val = va_arg(args, unsigned int);
			print_hex_buffer(addchar, pad_width, val, 16);
		} else if (c == '%') {
			addchar('%');
		} else {
			addchar('%');
			addchar(c);
		}
	}
	
	return 0;
}

void debug_printf(const char *format, ...)
{
	if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 1)
		return;
	
	va_list args;

	va_start(args, format);
	vfnprintf(uart_txchar, format, args);
	va_end(args);
}
