/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "pmu.h"

/*
 * RC Trim constants
 */
#define RCTRIM_RESOLUTION       (12)
#define RCTRIM_LOAD_VAL	        BIT(11)
#define RCTRIM_RANGE_MAX	(7 * 7)
#define RCTRIM_RANGE_MIN	(-8 * 7)
#define RCTRIM_RANGE		(RCTRIM_RANGE_MAX - RCTRIM_RANGE_MIN + 1)

/*
 * Enable peripheral clock
 * @param perih Peripheral from @ref uint32_t
 */
void pmu_clock_en(uint32_t periph)
{
	if (periph <= 31)
		GR_PMU_PERICLKSET0 = BIT(periph);
	else
		GR_PMU_PERICLKSET1 = (1 << (periph - 32));
}

/*
 * Disable peripheral clock
 * @param perih Peripheral from @ref uint32_t
 */
void pmu_clock_dis(uint32_t periph)
{
	if (periph <= 31)
		GR_PMU_PERICLKCLR0 = BIT(periph);
	else
		GR_PMU_PERICLKCLR1 = (1 << (periph - 32));
}

/*
 * Peripheral reset
 * @param periph Peripheral from @ref uint32_t
 */
void pmu_peripheral_rst(uint32_t periph)
{
	/* Reset high */
	if (periph <= 31)
		GR_PMU_RST0 = 1 << periph;
	else
		GR_PMU_RST1 = 1 << (periph - 32);
}