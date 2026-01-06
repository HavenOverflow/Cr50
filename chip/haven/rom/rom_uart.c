/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "registers.h"
#include "rom_uart.h"

int uart_tx_ready(void)
{
    if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 1)
        return 1;
    
    return (GREG32(UART, STATE) ^ 1) & 1;
}

int uart_tx_done(void)
{
    if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 1)
        return 1;
    
    return (GREG32(UART, STATE) & 0x30) != 0x30;
}

void uart_txchar(char tx)
{
    if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 1)
        return;
    
    while (!uart_tx_ready())
        ;
    
    GREG32(UART, WDATA) = tx;
}


