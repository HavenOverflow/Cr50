/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#include "config.h"
#include "debug_printf.h"
#include "registers.h"
#include "rescue.h"
#include "rom_flash.h"
#include "rom_uart.h"
#include "setup.h"
#include "signed_header.h"
#include "system.h"
#include "verify.h"

#include "dcrypto.h"

/* Signal to any connected hosts that rescue mode is able to be requested. */
void attempt_sync(int enabled)
{
	if (enabled & GREG32(PMU, RSTSRC))
		return;

	debug_printf("oops?|");
}

enum rescue_err rescue(struct header_hashes *hashes)
{
	int i, frame_num, data_addr, data_size, hash_incorrect, size = 0;
	int r11 = 0xffffffff;
	uint32_t r3_29, checksum;
	uint32_t *data_ptr, *flash_offset;
	uint8_t rxbuf[1024]; // Decomp shows this global buffer at 0x10f2c
	uint8_t digest[SHA256_DIGEST_SIZE]; // Decomp shows this global buffer at 0x1132c, ends at 0x1134c
	uint8_t txbuf[SHA256_DIGEST_SIZE]; // Decomp shows this global buffer at 0x1134b, ends at 0x1136b
	uint32_t somethingbuf[8]; // Decomp shows this global buffer at 0x1136c, ends at
	const struct rescue_pkt *pkt = (const struct rescue_pkt *)rxbuf;

	/* Signal that rescue has been engaged to the host. */
	uart_write_char('e');
	uart_write_char('s');
	uart_write_char('c');
	uart_write_char('u');
	uart_write_char('e');

	while (true) {
		/* Copy incoming data into our RX buffer. */
		for (i = 0; i < sizeof(rxbuf); ++i)
			rxbuf[i] = read_uart_rx_data();

		DCRYPTO_SHA256_hash((uint8_t *) pkt->frame_num, 
			sizeof(struct rescue_pkt) - offsetof(struct rescue_pkt, frame_num), 
			(uint8_t *) digest);

		hash_incorrect = memcmp(pkt->hash, digest, SHA256_DIGEST_SIZE);

		if (!hash_incorrect) {
			/* The packet we got is good; make sure the frame number matches ours. */
			if (pkt->frame_num == frame_num) {
				/* The packet we received matches what we expect, let's send the hash to the host
				 * to verify that everything was sent and recieved correctly.
				 */
				DCRYPTO_SHA256_hash(pkt, sizeof(struct rescue_pkt), digest);

				/* Copy the full packet hash to our TX buffer. */
				for (i = 0; i < SHA256_DIGEST_SIZE; i++)
					txbuf[i] |= digest[i];

				if (frame_num == 0) {
					/* Validate the image header. */
					const struct SignedHeader *hdr = (const struct SignedHeader *)pkt->data;

					if (hdr->magic != MAGIC_HAVEN)
						return RESCUE_BAD_MAGIC;

					if (hdr->image_size > CONFIG_RW_SIZE)
						return RESCUE_OVERSIZED_IMAGE;

					/* The header must be aligned to the beginning of RW_A. */
					if (pkt->flash_offset != CONFIG_RW_MEM_OFF) 
						return RESCUE_BAD_ADDR;

					if (hdr->image_size & 0x7ff)
						return RESCUE_ERR_FOUR;

					/* Make sure the keyid matches one of the keysets we use. */
					if (!is_good_key(&hdr->keyid))
						return RESCUE_MISMATCHED_KEY;

                    /* Wipe the hashes so that the host can't change the target image
                     * after validity is done.
                     */
                    memset(hashes, 0, sizeof(*hashes));

                    /* Our header passed validity, let's erase the RW banks
                     * before writing it.
                     */
                    for (i = 8; i != CONFIG_FLASH_WRITE_IDEAL_SIZE; i++) {
                        if (flash_erase(0, i))
                            return RESCUE_ERASE_FAILURE;
                    }
                    for (i = 8; i != CONFIG_FLASH_WRITE_IDEAL_SIZE; i++) {
                        if (flash_erase(1, i))
                            return RESCUE_ERASE_FAILURE;
                    }

                    /* Verify that RW_A was erased successfully. */
                    flash_offset = (uint32_t *)(CONFIG_PROGRAM_MEMORY_BASE + CONFIG_RW_MEM_OFF);
                    checksum = 0xffffffff;

                    do {
                        checksum &= *(flash_offset) & *(flash_offset + 4) & *(flash_offset + 8) & *(flash_offset + 12) & *(flash_offset + 16) & *(flash_offset + 20) & *(flash_offset + 24) & *(flash_offset + 28) & *(flash_offset + 32);
                        flash_offset += 32;
                    } while(flash_offset != (uint32_t *)(CFG_FLASH_HALF));

                    flash_offset = (uint32_t *)(CONFIG_PROGRAM_MEMORY_BASE + CHIP_RO_B_MEM_OFF);
                    do {
                        checksum &= *(flash_offset) & *(flash_offset + 4) & *(flash_offset + 8) & *(flash_offset + 12) & *(flash_offset + 16) & *(flash_offset + 20) & *(flash_offset + 24) & *(flash_offset + 28) & *(flash_offset + 32);
                        flash_offset += 32;
                    } while(flash_offset != (uint32_t *)(CFG_FLASH_HALF * 2));

                    /* After the flash is erased, all of its bits should be 1.
                     * Verify the flash was erased by and'ing all of the bytes together.
                     */
                    if (checksum != 0xffffffff)
                        return RESCUE_ERASE_VERIFY_FAILURE;

                    data_addr = pkt->flash_offset;
                }

                /* Wipe the hashes so that the host can't change the target image
                 * after validity is done.
                 */
                if (hashes)
                    memset(hashes, 0, sizeof(hashes));

                if (pkt->flash_offset > data_addr + data_size) {
                    if (pkt->flash_offset & 0x7f)
                        return RESCUE_ERR_NINE;

                    if (data_size && r11 != 0xffffffff) {
                        if (flash_write(data_addr >> 18, data_addr >> 2 & 0xffff, somethingbuf, data_size))
                            return RESCUE_WRITE_HEADER_FAILURE;

                        r11 = 0xffffffff;
                    }

                    data_addr = pkt->flash_offset;
                    data_size = 0;
                }

                somethingbuf[data_size << 2] = *(uint32_t *)pkt->data;
                r11 &= *(uint32_t *)pkt->data;

                /* Prevent overflows into the RO_B section */
                if (data_addr + (r3_29 << 2) > CHIP_RO_B_MEM_OFF)
                    return RESCUE_OVERFLOW;

                data_ptr = (uint32_t *)pkt->data;

                while (true) {
                    if (r3_29 != 0x20) {
                        if (r3_29 > 0x20)
                            return RESCUE_OVERFLOW;

                        size = r3_29;
                    }else{
                        /* Everything looks good, let's save it to the flash. */
                        if (r11 != 0xffffffff && flash_write(data_addr >> 0x12, data_addr >> 2 & 0xffff, somethingbuf, 32))
                            return RESCUE_WRITE_BLOCK_FAILURE;

                        data_addr += CONFIG_FLASH_WRITE_IDEAL_SIZE;
                        r11 = 0xffffffff;
                        size = 0;
                    }

                    if ((data_addr > 0x7ffff && pkt->frame_num < 0) || data_ptr == &pkt->data[1] - 5) {
                        data_size = size;
                        frame_num++;
                        break;
                    }

                    data_ptr = &data_ptr[1];
                    r3_29 = size + 1;
                    somethingbuf[size << 2] = *data_ptr;
                    r11 &= *data_ptr;

                    if (data_addr + r3_29 > CHIP_RO_B_MEM_OFF)
                        return RESCUE_OVERFLOW;

                    continue;
                }
            }
        }

        /* Write our TX buffer over UART. */
        for (i = 0; i < sizeof(txbuf); i++)
            uart_write_char(txbuf[i]);

        if (!hash_incorrect) {
            /* If the frame_num is less than 0, break rescue. */
            if (pkt->frame_num < 0)
                break;
        }
    }

    if (data_size && r11 != 0xffffffff && flash_write(data_addr >> 0x12, data_addr >> 2 & 0xffff, somethingbuf, data_size))
        return RESCUE_WRITE_LAST_FAILURE;
        
    system_reset(0xffffffff);
}

int check_engage_rescue(int disable, struct header_hashes *hashes)
{
	if (disable & GREG32(PMU, RSTSRC))
		return 0x1a5a3cc3;

	if (check_uart_state() && read_uart_rx_data() == 'r') {
		/* A host has sent the magic 'r', engage rescue. */
		if (rescue(hashes) > RESCUE_MISMATCHED_KEY)
			system_reset(0xffffffff);
	}else{
		uart_init();
		debug_printf("no\n");
	}

	return 0x1a5a3cc3;
}
