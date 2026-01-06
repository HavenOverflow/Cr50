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
#include "ro_uart.h"
#include "setup.h"
#include "signed_header.h"
#include "system.h"
#include "verify.h"

#include "dcrypto.h"

void rescue_sync(int enabled)
{
	if (enabled & GREG32(PMU, RSTSRC))
		return;

	debug_printf("oops?|");
}


int rescue(void *hashes)
{
	uint8_t rxbuf[1024];
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t txbuf[SHA256_DIGEST_LENGTH];
	struct rescue_pkt *pkt = (struct rescue_pkt *)rxbuf;
	uint32_t last, bits, *ptr, 
	int i, mismatch, frame_num;

	uart_write_char('e');
	uart_write_char('s');
	uart_write_char('c');
	uart_write_char('u');
	uart_write_char('e');

	while (true) {
		/* Read incoming data into our RX buffer. */
		for (i = 0; i < sizeof(rxbuf); ++i)
			rxbuf[i] = read_uart_rx_data();

		DCRYPTO_SHA256_hash((uint8_t *) &pkt->frame_num, 
			sizeof(rxbuf) - offsetof(struct rescue_pkt, frame_num), 
			(uint8_t *) hash);
		
		/* Compare the packet hash to our calculated digest */
		mismatch = memcmp(pkt->hash, hash, SHA256_DIGEST_LENGTH);

		if (!mismatch && (uint8_t)pkt->frame_num == frame_num) {
			DCRYPTO_SHA256_hash((uint8_t *) rxbuf, 
					sizeof(rxbuf), 
					(uint8_t *) hash);
			
			/* Get rid of null bytes in the digest and copy it into txbuf. */
			for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				if (rxbuf[i] == 0)
					rxbuf[i] |= 1;
				txbuf[i] = rxbuf[i];
			}

			if (frame_num == 0) {
				/* This is the first write; verify the incoming image header. */
				struct SignedHeader *hdr = (struct SignedHeader *hdr)(pkt->data);

				if (hdr->magic != -1)
					return RESCUE_BAD_MAGIC;

				/* Make sure that the image is destined to and fits in RW_A. */
				if (hdr->image_size)
					return RESCUE_OVERSIZED_IMAGE;
				if (pkt->flash_offset != CONFIG_RW_MEM_OFF)
					return RESCUE_BAD_FLASH_OFFSET;
				if (hdr->image_size & 0x7ff)
					return RESCUE_UNDERSIZED_IMAGE;
				
				/* Only allow images with known keys to be flashed. */
				if (!LOADERKEY_find(&hdr->keyid))
					return RESCUE_UNKNOWN_KEY;

				/* Wipe our set of hashes before making modifications to flash. */
				if (hashes)
					memset(hashes, 0, SHA256_DIGEST_LENGTH * 3);


				/* Erase the RW_A and RW_B flash banks. */
				for (i = 8; i != 128; i++) {
					if (flash_erase(0, i, 0) != 0)
						return RESCUE_ERASE_FAILURE;
				}
				for (i = 8; i != 128; i++) {
					if (flash_erase(1, i, 0) != 0)
						return RESCUE_ERASE_FAILURE;
				}

				/* Verify the RW banks were erased successfully. */
				bits = 0xffffffff;

				ptr = (CONFIG_PROGRAM_MEMORY_BASE + CONFIG_RW_MEM_OFF);
				do {
					bits &= ptr[0] & ptr[1] & ptr[2] & ptr[3] & ptr[4] & ptr[5] & ptr[6] & ptr[7] & ptr[8];
					ptr += 32;
				} while(ptr != (uint32_t *)(CONFIG_PROGRAM_MEMORY_BASE + CFG_FLASH_HALF));

				ptr = (CONFIG_PROGRAM_MEMORY_BASE + CONFIG_RW_B_MEM_OFF);
				do {
					bits &= ptr[0] & ptr[1] & ptr[2] & ptr[3] & ptr[4] & ptr[5] & ptr[6] & ptr[7] & ptr[8];
					ptr += 32;
				} while(ptr != (uint32_t *)(CONFIG_PROGRAM_MEMORY_BASE + (CFG_FLASH_HALF * 2)));

				/* If all of the bits are not 1, then we failed to erase the RW banks. */
				if (bits != 0xffffffff) 
					return RESCUE_ERASE_VERIFY_FAILURE;

				last = pkt->flash_offset;
			}

			if (hashes)
				memset(hashes, 0, SHA256_DIGEST_LENGTH * 3);

			
			/* And now the decomp gets iffy! funnnn... */
			if (pkt->flash_offset <= last + (write_size << 2)) {

			}else{
				/* Writes must be aligned to a 128-word boundary. */
				if (pkt->flash_offset & 0x7f)
					return RESCUE_UNALIGNED_WRITE;
				
				if (write_size != 0 && r11 != 0xffffffff) {
					if (flash_write(last > CFG_FLASH_HALF, last / sizeof(uint32_t), write_buffer, write_size))
						return RESCUE_WRITE_HEADER_FAILURE;

					r11 = 0xffffffff;
				}

				last = pkt->flash_offset;
			}
		}

		/* Send back our formatted rxbuf digest. */
		for (i = 0; i < sizeof(txbuf); ++i)
			uart_write_char(txbuf[i]);

		/* If frame_num is less than 0, end rescue. */
		if (!mismatch && pkt->frame_num < 0)
			break;
	}
}

int check_engage_rescue(int disable, void *hashes)
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