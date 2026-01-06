/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#ifndef __EC_CHIP_G_LOADER_ROM_UART_H
#define __EC_CHIP_G_LOADER_ROM_UART_H

/* Returns 1 if BOARD_NO_RO_UART is present on LONG_LIFE_SCRATCH_REG1. */
int suppress_uart(void);

int check_uart_state(void);

/* Returns a single word from UART RX. */
uint32_t read_uart_rx_data(void);

/* Write a single char to UART TX. */
int uart_write_char(uint32_t word);

/* Returns 0 if UART TX is currently active. */
int check_uart_tx(void);

/* Initializes UART0 for data transfeer. */
int uart_init(void);
#endif /* __EC_CHIP_G_LOADER_ROM_UART_H */