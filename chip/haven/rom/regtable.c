/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "registers.h"
#include "regtable.h"
#include "setup.h"

#define REGISTER_PADDING 0x34687195
#define MAX_REGS 200

struct {
	uint32_t reg_counter;
	uint32_t offset;
	uint32_t regvals[MAX_REGS];
	uint32_t regmap[MAX_REGS];
} regtable __attribute__((section(".bss.regtable")));

#define reg_counter regtable.reg_counter
#define offset regtable.offset
#define regvals regtable.regvals
#define regmap regtable.regmap




/* Handle violations from a register write count mismatch. */
int increment_reg_counter(void)
{
	return ++reg_counter;
}

void set_reg_counter(int count)
{
	reg_counter = count;
}

void verify_reg_counter(uint32_t expectation, uint32_t violation)
{
	uint32_t err_resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);

	if (reg_counter != expectation) {
		/* Store the mismatch in the upper and lower 16 bits of PWRDN_SCRATCH28 */
		GREG32(PMU, PWRDN_SCRATCH28) = expectation | (reg_counter << 16);
		GREG32(PMU, PWRDN_SCRATCH29) = 5;

		_purgatory((err_resp >> 2 & 3) | violation);
	}

	increment_reg_counter();
}

/* Handle violations from a register table mismatch. */
static void handle_register_mismatch(uint32_t step, uint32_t val,
					uint32_t violation)
{
	debug_printf("!exp @%8x: %x vs. %x\n",
		regmap[step], val,
		regvals[step] ^ REGISTER_PADDING);

	uint32_t err_resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);

	GREG32(PMU, PWRDN_SCRATCH28) = regmap[step];
	GREG32(PMU, PWRDN_SCRATCH29) = 4;

	_purgatory((err_resp >> 2 & 3) | violation);
}


/* Write a register and store its value and address for later
 * validity for glitch resistance.
 */
void glitch_reg32(uint32_t reg, uint32_t val)
{
	uint32_t i;

	if (offset == 0)
		goto add_entry;

	if (regmap[0] == reg) {
		i = 0;
		goto update_entry;
	}

	for (i = 0; i < offset; i++) {
		if (regmap[i] == reg)
			goto update_entry;
	}

	if (offset > 0xc7) {
		i = offset;
		goto store_value;
	}

add_entry:
	i = offset++;

store_value:
	regmap[i] = reg;
	regvals[i] = val ^ REGISTER_PADDING;
	REG32(reg) = val;
	return;

update_entry:
	regvals[i] = val ^ REGISTER_PADDING;
	REG32(reg) = val;
}


uint32_t glitch_reg32_val(uint32_t reg, uint32_t val)
{
	uint32_t current_val, mapval;
	int i;

	if (offset == 0)
		goto add_entry;

	if (regmap[0] == reg) {
		i = 0;
		goto verify_entry;
	}

	for (i = 0; i < offset; i++) {
		if (regmap[i] == reg)
			goto verify_entry;
	}

	if (offset > 0xc7) {
		i = offset;
		goto store_value;
	}

add_entry:
	i = offset++;

store_value:
	regmap[i] = reg;
	regvals[i] = val ^ REGISTER_PADDING;
	REG32(reg) = val;
	return val;

verify_entry:
	current_val = REG32(regmap[i]);

	mapval = current_val ^ REGISTER_PADDING;
	if (mapval != regvals[i])
		handle_register_mismatch(i, current_val, 2);

	if (val != current_val)
		handle_register_mismatch(i, val, 2);

	return val;
}

void verify_reg_table(uint32_t violation)
{
	uint32_t i, step, val, expectation;

	debug_printf("exp  ?%d\n", offset);

	/* Adjust the jittery clock sync. */
	G32PROT(XO, CLK_JTR_SYNC_CONTENTS, 0);

	step = rand();

	if (offset == 0) {
		increment_reg_counter();
		return;
	}

	for (i = 0; i < offset; i++) {
		step = (step + 211) % offset;

		val = REG32(regmap[step]);

		expectation = val ^ REGISTER_PADDING;
		if (expectation != regvals[step])
			handle_register_mismatch(step, val, violation);
	}

	increment_reg_counter();
}



/* Initialize the hardware register glitch resistance
 * table. This should prevent faults from being able to skip
 * certain registers from being written to.
 */
void init_regtable(void)
{
	offset = 0;
	reg_counter = 0;

	for (int i = 0; i < MAX_REGS; i++)
		regmap[i] = 0xffffffff;
}