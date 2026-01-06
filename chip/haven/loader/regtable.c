/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "registers.h"
#include "trng.h"
#include "vectors.h"

#define REGISTER_PADDING 0x34687195

uint32_t reg_counter;
uint32_t offset;
uint32_t regvals[200];
uint32_t regmap[200];


/* Find where to place a register in the register map. */
static uint32_t find_register_offset(uint32_t reg)
{
	if (offset == 0)
		return offset;
	if (regmap[0] == reg)
		return 0;
	
	for (int i = 0; i < offset; i++) {
		if (regmap[i] == reg)
			return i;
	}

	return offset;
}

/* Write a register and store its value and address for later
 * validity for glitch resistance. 
 */
void glitch_reg32(uint32_t reg, uint32_t val)
{
	uint32_t mapoffset = find_register_offset(reg);

	if (mapoffset != offset) {
		regvals[mapoffset] = val ^ REGISTER_PADDING;
		REG32(reg) = val;
		return;
	}

	if (offset < 200)
		offset++;
	
	regmap[offset] = reg;
	regvals[offset] = val ^ REGISTER_PADDING;
	REG32(reg) = val;
}

/* Handle violations from a register write count mismatch. */
int increment_reg_counter(void)
{
	return reg_counter++;
}

void set_reg_counter(int count)
{
	reg_counter = count;
}

void verify_reg_counter(uint32_t expectation, uint32_t violation)
{
	if (reg_counter != expectation) {
		/* Store the mismatch in the upper and lower 16 bits of PWRDN_SCRATCH28 */
		GREG32(PMU, PWRDN_SCRATCH28) = expectation | reg_counter << 16;  // Violating register counter
		GREG32(PMU, PWRDN_SCRATCH29) = 5;                                // Violation mode

		_purgatory((GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE) >> 2 & 3) | violation);
	}

	increment_reg_counter();
}



/* Handle violations from a register table mismatch. */
static void handle_register_mismatch(uint32_t step, uint32_t got,
					uint32_t violation, uint32_t expectation)
{
	// e.g. !exp 400940d0: 0 vs. 1
	debug_printf("!exp @%8x: %x vs. %x\n", 
		regmap[step], got, 
		regvals[step] ^ REGISTER_PADDING);

	GREG32(PMU, PWRDN_SCRATCH28) = regtable[step];  // Violating register value
	GREG32(PMU, PWRDN_SCRATCH29) = 4;               // Violation mode

	_purgatory((GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE) >> 2 & 3) | violation);
}

void verify_reg_table(uint32_t violation)
{
	uint32_t i, step;

	/* Adjust the jittery clock. */
	G32PROT(XO, JTR_SYNC_CONTENTS, 0);

	step = rand();

	if (!offset) {
		/* Nothing to verify. */
		increment_reg_counter();
		return;
	}
	
	for (i = 0; i < offset; ++i) {
		step = (step + 211) % offset;

		if (regmap[i] != regvals[i] ^ REGISTER_PADDING)
			handle_register_mismatch(step, addr, );
	}

	increment_reg_counter();
}



/* Initialize the hardware register glitch resistance
 * table. This should prevent faults from being able to skip
 * certain registers from being written to.
 */
void init_reg_table(void)
{
	int i;

	if (offset < 200) {
		for (i = offset; i != 200; ++i) {
			regvals[i] = 0xffffffff;
			regmap[i] = 0;
		}
	}
}