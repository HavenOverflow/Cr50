/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef __EC_CHIP_G_ROM_ROM_UART_H
#define __EC_CHIP_G_ROM_ROM_UART_H

/* Return 1 if UART TX is ready to transmit a byte. */
int uart_tx_ready(void);

/* Return 1 if UART TX is done transmitting. */
int uart_tx_done(void);

/* TX a single byte over UART0 */
void uart_txchar(char tx);

#endif /* __EC_CHIP_G_ROM_ROM_UART_H */