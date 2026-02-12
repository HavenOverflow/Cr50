/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef __EC_CHIP_G_ROM_REGTABLE_H
#define __EC_CHIP_G_ROM_REGTABLE_H

#include "registers.h"

#define G32PROT(REGION, OFFSET, VAL) \
    glitch_reg32((uint32_t)GREG32_ADDR(REGION, OFFSET), VAL)

#define G32PROT_OFFSET(REGION, OFFSET, I, VAL) \
    glitch_reg32((uint32_t)GREG32_ADDR(REGION, OFFSET)[I], VAL)

#define G32PROT_VAL(REGION, OFFSET) \
    glitch_reg32_val((uint32_t)GREG32_ADDR(REGION, OFFSET), GREG32(REGION, OFFSET))

#define G32PROT_FIELD(mname, rname, fname, fval) \
	(G32PROT(mname, rname, \
	((GREG32(mname, rname) & (~GFIELD_MASK(mname, rname, fname))) | \
	(((fval) << GFIELD_LSB(mname, rname, fname)) & \
		GFIELD_MASK(mname, rname, fname)))))

/* Write a register and store its value and address for later
 * validity for glitch resistance. 
 */
void glitch_reg32(uint32_t reg, uint32_t val);

/* Write a register and store its value and address for later
 * validity for glitch resistance. Returns val.
 */
uint32_t glitch_reg32_val(uint32_t reg, uint32_t val);

/* Handle violations from a register write count mismatch. */
int increment_reg_counter(void);

void set_reg_counter(int count);

void verify_reg_counter(uint32_t expectation, uint32_t violation);

/* Handle violations from a register mismatch. */
void verify_reg_table(uint32_t violation);

/* Initialize the hardware register glitch resistance
 * table. This should prevent faults from being able to skip
 * certain registers from being written to.
 */
void init_regtable(void);

#endif /* __EC_CHIP_G_ROM_REGTABLE_H */