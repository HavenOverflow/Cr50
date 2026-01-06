/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#include "common.h"
#include "registers.h"
#include "rom_uart.h"
#include "scratch_reg1.h"

int suppress_uart(void)
{
	return GREG32(PMU, LONG_LIFE_SCRATCH1) & BOARD_NO_RO_UART;
}

int check_uart_state(void)
{
	if (suppress_uart())
		return 0;

	return (GREG32(UART, STATE) ^ 128) >> 7 & 1;
}

int check_uart_state_bit(void)
{
	if (suppress_uart())
		return 1;

	return (GREG32(UART, STATE) ^ 1) & 1;
}


uint32_t read_uart_rx_data(void)
{
	if (suppress_uart())
		return 0;

	/* Wait until we recieve new data. */
	while (!check_uart_state())
		;

	return GREG32(UART, RDATA);
}

int uart_write_char(uint32_t word)
{
	int i = suppress_uart();

	if (!i) {
		do
			i = check_uart_state_bit();
		while (!i);

		GREG32(UART, WDATA) = word;
	}

	return i;
}

int check_uart_tx(void)
{
	if (suppress_uart())
		return 1;

	if (!(GREG32(UART, CTRL) & 1))
		return 1;

	if ((GREG32(UART, STATE) & 0x30) != 0x30)
		return 0;

	return 1;
}

int uart_init(void)
{
	int i;

	if (suppress_uart())
		return 1;

	GREG32(PMU, PERICLKSET1) |= 32;

	do
		i = check_uart_tx();
	while (!i);

	GREG32(PINMUX, DIOA0_SEL) = 70;
	GREG32(PINMUX, UART0_RX_SEL) = 12;
	GREG32(PINMUX, DIOA13_CTL) = 6;
	GREG32(UART, NCO) = 0x13a9;
	GREG32(UART, CTRL) = 3;

	return i;
}