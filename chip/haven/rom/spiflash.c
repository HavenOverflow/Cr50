/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#include "config.h"
#include "debug_printf.h"
#include "flash.h"
#include "hw_sha256.h"
#include "regtable.h"
#include "signed_header.h"
#include "spiflash.h"
#include "verify.h"
#include "sha256.h"
#include "setup.h"

void init_spi(void)
{
	GREG32(PINMUX, DIOA6_CTL) |= 4;
	GREG32(PINMUX, DIOA2_CTL) |= 4;
	GREG32(PINMUX, DIOA12_CTL) |= 4;
	GREG32(PINMUX, DIOA10_CTL) &= ~4;

	/* Disable SPI interrupts. */
	GREG32(SPS, ICTRL) = 0;

	GREG32(SPS, CTRL) = 0x70;

	/* Clear SPI status. */
	GREG32(SPS, DUMMY_WORD) = 0;

	GREG32(SPS, FIFO_CTRL) = 0x13;
}

uint32_t spi_get_offset(void)
{
	uint32_t fifo_rptr = GREG32(SPS, RXFIFO_RPTR);
	uint32_t fifo_wptr = GREG32(SPS, RXFIFO_WPTR);

	/* If both offsets are 1KiB aligned, return 1KiB. */
	if ((fifo_wptr ^ fifo_rptr) & 0x400)
		return 0x400;

	uint32_t fifo_rptr_1 = fifo_rptr & 0x3ff;
	uint32_t fifo_wptr_1 = fifo_wptr & 0x3ff;

	if (fifo_rptr & 0x3ff || fifo_wptr & 0x3ff)
		return 0;

	if (fifo_rptr_1 > fifo_wptr_1)
		fifo_wptr_1 += 0x400;

	return fifo_wptr_1 - fifo_rptr_1;
}


/* I want someone to double-check these two and fix the Gregs. -Kayla */
// void spi_txdata(uint32_t *txbuf, size_t len)
// {
// 	uint32_t offset;
//	uint32_t index;

// 	/* Make sure all values are 4-byte aligned. */
// 	if (len & 3 || txbuf & 3 || !len)
// 		return;

// 	/* Find our Tx FIFO buffer offset. Do we need greg32_addr instead?*/
// 	offset = GREG32(SPS, TXFIFO_WPTR) - txbuf;
//	index = (offset >> 2) & 0xff;

// 	while (len) {
// 		GREG32_ADDR(SPS, TX_DATA)[index] = *txbuf++;

//		/*Wrap at fifo bounds*/
//		index = (index + 1) & 0xff;
// 		len -= 4;
// 	}
// }

// void spi_read_data(uint32_t *out, size_t len)
// {
// 	uint32_t offset;
//	uint32_t index

// 	/* Make sure all values are 4-byte aligned. */
// 	if (len & 3 || out & 3 || !len) 
// 		return;

//	//need replace magic with Greg
//	offset =  *0x40510040 - out;
//	//out is charstar because bn says so. maybe should be change
//	index = (((char*)out + offset) >> 2) & 0xff;

//	while(len){ 
//		//Probably shouldnt be Greg32_addr
//		*out++ = GREG32_ADDR(SPS, RX_DATA)[index << 2];

//		/* Wrap at fifo bounds*/
//		index = (index + 1) & 0xff;
//		len -= 4;
//	}
// }

int sps_tx_active(void)
{
	return (GREG32(SPS, VAL) ^ 4) >> 2 & 1;
}

void move_sps_ptrs(uint32_t rxr_offset, uint32_t txw_offset)
{
	GREG32(SPS, RXFIFO_RPTR) += rxr_offset;
	GREG32(SPS, TXFIFO_WPTR) += txw_offset;
}



// enum bootstrap_err spiflash(void)
// {
// 	uint8_t rxbuf[1024];
// 	uint8_t hash[SHA256_DIGEST_LENGTH];
// 	uint8_t txbuf[SHA256_DIGEST_LENGTH]; 
// 	int frame_num = 0;
// 	uint32_t *flash_ptr, flash_bits;
// 	enum bootstrap_err rv;
// 	struct bootstrap_pkt *pkt = (struct bootstrap_pkt *)rxbuf;
// 	struct SignedHeader *hdr = (struct SignedHeader *)pkt->data;

// 	while (true) {
// 		if (frame_num || GREG32(GPIO, DATAIN) & 1) {
// 			if (get_spi_fifo_offset() < sizeof(rxbuf)) {
// 				continue;
// 			}else{
// 				read_spi_input(rxbuf, sizeof(rxbuf));
				
// 				hwSHA256((uint8_t *) pkt->frame_num, 
// 					sizeof(struct bootstrap_pkt) - offsetof(struct bootstrap_pkt, frame_num), 
// 					(uint8_t *) hash);

// 				if (memcmp(pkt->hash, hash, SHA256_DIGEST_SIZE) || pkt->frame_num != frame_num) {
// 					/* Recieved packet is eithr invalid or out of sync;
// 					 * Send our TX buffer back and realign SPS.
// 					 */
// 					sps_tx_active(txbuf, sizeof(txbuf));

// 					while (sps_tx_active())
// 						;

// 					move_sps_ptrs(1024, SHA256_DIGEST_LENGTH);
// 				}else{
// 					// Hash the recieved packet and send it to the host.
// 					hwSHA256(pkt, sizeof(struct rescue_pkt), hash);
					
// 					// Get rid of all those NULL bytes in there.
// 					for (i = 0; i < sizeof(txbuf); ++i) {
// 						if (!hash[i])
// 							hash[i] |= 1;
// 						txbuf[i] = hash[i];
// 					}

// 					sps_tx_data(txbuf, sizeof(txbuf));

// 					while (sps_tx_active())
// 						;

// 					move_sps_ptrs(1024, SHA256_DIGEST_LENGTH);

// 					/* If this is the first write, verify the provided header. */
// 					if (frame_num == 0) {
// 						if (!(GREG32(GPIO, DATAIN) & 1))
// 							return BOOTSTRAP_NO_DATA;

// 						hdr = (struct SignedHeader *)pkt->data;
						
// 						if (hdr->magic != -1)
// 							return BOOTSTRAP_BAD_MAGIC;
						
// 						/* Make sure image belongs at flash_offset. */
// 						if (hdr->image_size > 0x80000)
// 							return BOOTSTRAP_OVERSIZED_IMAGE;
// 						if (pkt->flash_offset >= 0x80000)
// 							return BOOTSTRAP_BAD_ADDR;
// 						if (pkt->flash_offset & 0x7ff)
// 							return 5;
// 						if (pkt->flash_offset & 0x3ffff)
// 							return 8;
// 						if (pkt->flash_offset + hdr->image_size > 0x80000)
// 							return BOOTSTRAP_OVERSIZED_IMAGE;
// 						if (hdr->image_size & 0x7ff) 
// 							return 6;
						
// 						/* 
// 						 * Do not allow unknown keysets.
// 						 */
// 						if (!is_supported_key(hdr->keyid))
// 							return 7;

// 						/* 
// 						 * Bulk-erase the entire FLASH bank.
// 						 */
// 						GREG32(GLOBALSEC, FLASH0_BULKERASE_CTRL) = 1;
// 						rc = flash_bulkerase(0);
// 						G32PROT(GLOBALSEC, FLASH0_BULKERASE_CTRL, 0);
// 						if (rc) {
// 							rv = 11;
// 							break;
// 						}

// 						GREG32(GLOBALSEC, FLASH1_BULKERASE_CTRL) = 1;
// 						rc = flash_bulkerase(1);
// 						G32PROT(GLOBALSEC, FLASH1_BULKERASE_CTRL, 0);
// 						if (rc) {
// 							rv = 12;
// 							break;
// 						}

// 						/* Skip flash erase validity if config0 requests it. */
// 						if (!(GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 4)) {
// 							flash_offset = pkt->flash_offset;
// 							goto write_page;
// 						}

// 						flash_ptr = (uint32_t *)(CONFIG_PROGRAM_MEMORY_BASE);

// 						do {
// 							if (flash_ptr > (CONFIG_PROGRAM_MEMORY_BASE + CONFIG_FLASH_SIZE - 1)) {
// 								flash_offset = pkt->flash_offset;
// 								goto write_page;
// 							}

// 							flash_bits = flash_ptr[0] & flash_ptr[1] & flash_ptr[2] & flash_ptr[3] & flash_ptr[4] & flash_ptr[5] & flash_ptr[6] & flash_ptr[7];
// 						} while (flash_bits == 0xffffffff);

// 						return BOOTSTRAP_FLASH_WIPE_ERROR;
// 					}
					

// 					write_page:

// 					/* Ensure that each write is targetting a higher
// 					 * address than the prior write.
// 					*/
// 					if (pkt->flash_offset > flash_offset + (r5_1 << 2)) {
// 						if (pkt->flash_offset & 0x7f) {
// 							rv = 15;
// 							break;
// 						}

// 						if (r5_1) {
// 							if (r6_1 != 0xffffffff && flash_write(flash_offset >> 0x12, flash_offset >> 2 & 0xffff, 0x10f68, r5_1)) {
// 								rv = 14;
// 								break;
// 							}

// 							flash_offset = pkt->flash_offset;
// 							r6_1 = 0xffffffff;
// 							r5_1 = 0;
// 						}
// 					}
					
// 					int32_t r2_14 = pkt->data;
// 					int32_t r3_22 = r5_1 + 1;
// 					*(uint32_t*)((r5_1 << 2) + 0x10f68) = r2_14;
// 					r6_1 &= r2_14;

// 					if (flash_offset + (r3_22 << 2) > 0x80000) {
// 						rv = 0x10;
// 						break;
// 					}

// 					int32_t* r7_4 = pkt->data;

// 					while (true) {
// 						if (r3_22 != 0x20) {
// 							if (r3_22 > 0x20) {
// 								rv = 0x10;
// 								goto fatal_err;
// 							}
							
// 							r5_1 = r3_22;
// 						}else{
// 							if (r6_1 != 0xffffffff && flash_write(flash_offset >> 0x12, flash_offset >> 2 & 0xffff, 0x10f68, r3_22)) {
// 								rv = 0xe;
// 								goto fatal_err;
// 							}
							
// 							flash_offset += 0x80;
// 							r6_1 = 0xffffffff;
// 							r5_1 = 0;
// 						}
						
// 						if (r7_4 == 0x10f24) {
// 							frame_num++;
							
// 							if (pkt->frame_num >= 0)
// 								break;
							
// 							int32_t r0_18;

// 							if (r5_1 && r6_1 != 0xffffffff)
// 								r0_18 = flash_write(flash_offset >> 0x12, flash_offset >> 2 & 0xffff, 0x10f68, r5_1);
							
// 							if (r5_1 && r6_1 != 0xffffffff && r0_18) {
// 								rv = 0xe;
// 								goto fatal_err;
// 							}
							
// 							return BOOTSTRAP_SUCCESS;
// 						}
						
// 						r7_4 = &r7_4[1];
// 						int32_t r2_12 = *(uint32_t*)r7_4;
// 						r3_22 = r5_1 + 1;
// 						*(uint32_t*)((r5_1 << 2) + 0x10f68) = r2_12;
// 						r6_1 &= r2_12;
						
// 						if (flash_offset + (r3_22 << 2) > 0x80000) {
// 							rv = 16;
// 							goto fatal_err;
// 						}
// 					}

// 					continue;
// 				}
// 			}
// 		}else{
// 			rv = 1;
// 		}
// 	}

// 	fatal_err:
// 	debug_printf(":%d\n", rv);
// 	GREG32(SPS, DUMMY_WORD) = rv;
// 	_purgatory((GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE) >> 9 & 1) | 2);
// }

void check_engage_spiflash(void)
{
	enum bootstrap_err rc;
	// Allow firmware to disable SPI bootstrapping.
	if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 0x10)
		return;

	// If the dev_mode line isn't pulled high, continue verified boot as normal.
	if (!(GREG32(GPIO, DATAIN) & 1))
		return;

	GREG32(PINMUX, HOLD) = 0;

	init_spi();

	debug_printf("boot ");
	//rc = spiflash();
	rc = 0; // filler
	debug_printf(":%d\n", rc);

	GREG32(SPS, DUMMY_WORD) = rc;
}
