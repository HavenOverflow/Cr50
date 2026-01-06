/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_LOADER_REGTABLE_H
#define __EC_CHIP_G_LOADER_REGTABLE_H

#define G32PROT(mname, rname, val) \
    glitch_reg32(GREG32_ADDR(region, name), val)

#define G32PROT_OFFSET(mname, rname, offset, val) \
    glitch_reg32(GREG32_ADDR(region, name)[offset], val)

#define G32PROT_FIELD(mname, rname, fname, fval) \
	(G32PROT(mname, rname, \
	((GREG32(mname, rname) & (~GFIELD_MASK(mname, rname, fname))) | \
	(((fval) << GFIELD_LSB(mname, rname, fname)) & \
		GFIELD_MASK(mname, rname, fname))))))

/* Initialize the glitch protection table. */
void init_reg_table(void);

/* Write to a register with glitch protection. */
void glitch_reg32(uint32_t reg, uint32_t val);

/* Increment the register counter by 1. */
int increment_reg_counter(void);

/* Reset the register counter. */
void set_reg_counter(int count);

/* Check the register counter against expectation. Enters purgatory on mismatch. */
int verify_reg_counter(uint32_t expectation, uint32_t violation);

/* Check the register table against its expectations. Enters purgatory on any mismatches. */
int verify_reg_table(uint32_t violation);

#endif /* __EC_CHIP_G_LOADER_REGTABLE_H */