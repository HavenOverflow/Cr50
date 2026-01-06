/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by HavenOverflow and re-integrated with the original software.
 */

#include "common.h"
#include "registers.h"
#include "rom_uart.h"
#include "scratch_reg1.h"

int suppress_uart(void)
{
	return GREG32(PMU, LONG_LIFE_SCRATCH1) & BOARD_NO_RO_UART;
}

int uart_rx_ready(void)
{
	if (suppress_uart())
		return 0;

	return (GREG32(UART, STATE) ^ 0x80) & BIT(7);
}

char read_uart_rx_data(void)
{
	if (suppress_uart())
		return 0;

	while (!uart_rx_ready())
		;

	return (char)GREG32(UART, RDATA);
}

int uart_tx_ready(void)
{
	if (suppress_uart())
		return 1;

	return !(GREG32(UART, STATE) & 1);
}

int uart_tx_done(void)
{
	if (suppress_uart())
		return 1;

	if (!(GREG32(UART, CTRL) & 1))
		return 1;

	if ((GREG32(UART, STATE) & 0x30) != 0x30)
		return 0;

	return 1;
}

void uart_init(void)
{
	if (suppress_uart())
		return;

	/* Enable the PMU UART clock. */
	GWRITE_FIELD(PMU, PERICLKSET1, DUART0_CLK_TIMER, 1);

	while (!check_uart_tx())
		;

	/* Set then necessary UART pins. */
	GREG32(PINMUX, DIOA0_SEL) = 70;
	GREG32(PINMUX, UART0_RX_SEL) = 12;
	GREG32(PINMUX, DIOA13_CTL) = 6;

	/* Set the UART BAUD rate. */
	GREG32(UART, NCO) = 0x13a9;

	/* Enable UART Tx and Rx. */
	GREG32(UART, CTRL) = 3;
}

void uart_txchar(char tx)
{
	if (suppress_uart())
		return;
	
	while (!uart_tx_ready())
		;

	GREG32(UART, WDATA) = (uint32_t)tx;
}

void uart_write_char(char tx)
{
	if (suppress_uart)
		return;
		
	uart_txchar(tx);
}