/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "registers.h"

/* These values are hardcoded, do not change them! */
#define RO_CERT_ADDR 0x403c00
#define RO_CERT_LEN 0x800
#define RO_CERT_WORDS (RO_CERT_LEN / sizeof(uint32_t))


enum spicert_rc {
    SPI_CERT_POPULATED = 1, // Cert is already populated.
    SPI_CERT_DEV_MODE_FELL = 2, // The dev_mode line fell to LOW.
};

enum spicert_rc spicert(void)
{
    int i;
    uint32_t *ptr = (uint32_t *)(RO_CERT_ADDR);
    uint32_t bits = -1;

    for (i = 0; i < RO_CERT_WORDS; ++i)
        bits &= ptr[i];

    /* SPIcert is only allowed if it hasn't been done already. */
    if (bits != -1)
        return SPI_CERT_POPULATED;

    /* Make sure dev_mode didn't fall to low. */
    if (!(GREG32(GPIO, DATAIN) & 1))
        return SPI_CERT_DEV_MODE_FELL;


    /* Transmit a setup packet for cert generation. */
    spicert_setup();


    
}

void check_engage_spicert(void)
{
    if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 0x10)
        return;
    
    // Don't do anything if the dev_mode line isn't pulled high.
    if (!(GREG32(GPIO, DATAIN) & 1))
        return;
    
    init_sps();
    debug_printf("boot :");
    rc = spicert();
    debug_printf("%d\n");

    
    // Tx our return code.
    GREG32(SPS, DUMMY_WORD) = rc | 128;
}