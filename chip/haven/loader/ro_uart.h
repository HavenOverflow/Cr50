/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#ifndef __EC_CHIP_G_LOADER_RO_UART_H
#define __EC_CHIP_G_LOADER_RO_UART_H

/* Returns 1 if LONG_LIFE_SCRATCH1 disables RO UART. */
int suppress_uart(void);

/* Returns 1 if UART RX is active. */
int uart_rx_ready(void);

/* Await a single byte from UART RX. */
char read_uart_rx_data(void);

/* Returns 1 if UART TX is ready for transfer. */
int uart_tx_ready(void);

/* Returns 1 if UART TX is completed. */
int uart_tx_done(void);

/* Initialize UART for transfer. */
void uart_init(void);

/* Send a single byte over UART TX. */
void uart_txchar(char tx);
void uart_write_char(char tx);

#endif /* __EC_CHIP_G_LOADER_RO_UART_H */