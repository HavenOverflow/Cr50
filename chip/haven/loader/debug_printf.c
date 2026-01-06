/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "debug_printf.h"
#include "ro_uart.h"

#include "stdarg.h"
#include "stddef.h"


int vfnprintf(void (*addchar)(int c),
	      const char *format, va_list args)
{
	int flags;
	int pad_width;
	int precision;
	char *vstr;
	int vlen;

	while (*format) {
		int c = *format++;
		char sign = 0;

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
		pad_width = 0;
		if (c == '*') {
			pad_width = va_arg(args, int);
			c = *format++;
		} else {
			while (c >= '0' && c <= '9') {
				pad_width = (10 * pad_width) + c - '0';
				c = *format++;
			}
		}
		if (pad_width < 0 || pad_width > MAX_FORMAT) {
			/* Validity check for precision failed */
			format = error_str;
			continue;
		}

		/* Count precision */
		precision = -1;
		if (c == '.') {
			c = *format++;
			precision = 0;
			while (c >= '0' && c <= '9') {
				precision = (10 * precision) + c - '0';
				c = *format++;
			}

			if (precision < 0 || precision > MAX_FORMAT) {
				/* Validity check for precision failed */
				format = error_str;
				continue;
			}
		}

		if (c == 'd') {
			if (integer_is_negative) {
				addchar('-');
				integer_is_negative--;
			}

			
		}

		if (c == 'h') {

		}

		if (c == 'x') {

		}

		if (!c || c == '%') {
			addchar('%');
			continue;
		}

		addchar('%');
		addchar(c);
	}
}

void debug_printf(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfnprintf(uart_txchar, NULL, format, args);
	va_end(args);
}
