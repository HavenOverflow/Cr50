/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "signed_header.h"
#include "common.h"
#include "registers.h"
#include "regtable.h"
#include "sha256.h"
#include "setup.h"
#include "pmu.h"

#define GRAWREG(mname, rname) (GBASE(mname) + GOFFSET(mname, rname))

#define BURN_CYCLES_DELAY(x) do { \
    volatile uint32_t i = (x); \
    do { \
        volatile uint32_t temp = i; \
        i--; \
        if (temp == 1) break; \
    } while (1); \
} while (0)

#define BROM_FWBIT_APPLYSEC_SC300       0
#define BROM_FWBIT_APPLYSEC_CAMO        1
#define BROM_FWBIT_APPLYSEC_BUSERR      2
#define BROM_FWBIT_APPLYSEC_BUSOBF      3
#define BROM_FWBIT_APPLYSEC_HEARTBEAT   4
#define BROM_FWBIT_APPLYSEC_BATMON      5
#define BROM_FWBIT_APPLYSEC_RTCCHECK    6
#define BROM_FWBIT_APPLYSEC_JITTERY     7
#define BROM_FWBIT_APPLYSEC_TRNG        8
#define BROM_FWBIT_APPLYSEC_VOLT        9
#define BROM_FWBIT_APPLYSEC_NOB5        10
#define BROM_FWBIT_APPLYSEC_UNKNOWN     11

int rand(void)
{
    /* Mix TRNG with CYCCNT to make TRNG manipulation harder. */
    return (uint32_t)(GREG16(TRNG, READ_DATA) + GREG16(M3, DWT_CYCCNT));
}

void set_cpu_d_regions(void)
{
	static uint8_t region0[SHA256_DIGEST_SIZE];
	static uint8_t region1[SHA256_DIGEST_SIZE];
	static uint8_t region2[SHA256_DIGEST_SIZE];

	G32PROT(GLOBALSEC, CPU0_D_REGION0_BASE_ADDR, (uint32_t)region0);
	G32PROT(GLOBALSEC, CPU0_D_REGION0_SIZE, SHA256_DIGEST_SIZE - 1);
	G32PROT(GLOBALSEC, CPU0_D_REGION0_CTRL, 1);
	G32PROT(GLOBALSEC, CPU0_D_REGION1_BASE_ADDR, (uint32_t)region1);
	G32PROT(GLOBALSEC, CPU0_D_REGION1_SIZE, SHA256_DIGEST_SIZE - 1);
	G32PROT(GLOBALSEC, CPU0_D_REGION1_CTRL, 1);
	G32PROT(GLOBALSEC, CPU0_D_REGION2_BASE_ADDR, (uint32_t)region2);
	G32PROT(GLOBALSEC, CPU0_D_REGION2_SIZE, SHA256_DIGEST_SIZE - 1);
	G32PROT(GLOBALSEC, CPU0_D_REGION2_CTRL, 1);
}

void disarmRAMGuards(void)
{
	G32PROT(GLOBALSEC, CPU0_D_REGION0_CTRL, 7);
	G32PROT(GLOBALSEC, CPU0_D_REGION1_CTRL, 7);
	G32PROT(GLOBALSEC, CPU0_D_REGION2_CTRL, 7);
}

void unlockINFO1(void)
{
	G32PROT(GLOBALSEC, FLASH_REGION7_BASE_ADDR, 0x28000);
	G32PROT(GLOBALSEC, FLASH_REGION7_SIZE, 0x800 - 1);
	G32PROT(GLOBALSEC, FLASH_REGION7_CTRL, 3);
}

void unlockFlashForRO(void)
{
	G32PROT(GLOBALSEC, FLASH_REGION0_BASE_ADDR, CONFIG_PROGRAM_MEMORY_BASE);
	G32PROT(GLOBALSEC, FLASH_REGION0_SIZE, CONFIG_FLASH_SIZE - 1);
	G32PROT(GLOBALSEC, FLASH_REGION0_CTRL, 7);
}

void init_cpu(void)
{
	GWRITE_FIELD(M3, DEMCR, TRCENA, 1);
	GWRITE_FIELD(M3, DWT_CTRL, CYCCNTENA, 1);
}

int cpu_setup(void)
{
	uint32_t cpuid;

	if (!(G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC) & 1))
		return 1;

	cpuid = GREG32(M3, CPUID);
	
	if (cpuid != 0x410fc331) {
		if (cpuid == 0x412fc231)
			return 1;

		return 3;
	}

	GREG32(M3, ITCMCR) = 0x5ec0007;

	if (GREG32(M3, ITCMCR) != 7)
		return 5;

	GREG32(GLOBALSEC, DUMMYKEY0) = 0x52ea7186;
	GREG32(GLOBALSEC, DUMMYKEY1) = 0xfc0e479d;
	GREG32(GLOBALSEC, DUMMYKEY2) = 0x396ab32c;

	G32PROT(GLOBALSEC, DBG_CONTROL, 0x1414f0);
	
	return 0;
}

int init_parity(void)
{
	if (!(G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC) & 8))
		return 1;

	G32PROT(GLOBALSEC, OBFS_SW_EN, 1);
	G32PROT(GLOBALSEC, TRANSMISSION_PARITY_EN, 1);

	return 0;
}

int init_gpio(void)
{
	uint32_t config0;
    uint32_t applysec;

	G32PROT(PMU, PERICLKSET0, (GREG32(PMU, PERICLKSET0) | 0x50000000 | 0x118));
	G32PROT(PMU, PERICLKSET1, (GREG32(PMU, PERICLKSET1) | 0xc30));

	config0 = G32PROT_VAL(FUSE, FW_DEFINED_BROM_CONFIG0);
    applysec = G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC);

	if ((G32PROT_VAL(FUSE, RC_JTR_OSC48_CC_EN) & 7) != 5 &&
		(G32PROT_VAL(FUSE, RC_JTR_OSC60_CC_EN) & 7) != 5 &&
        (applysec & 0x400) == 0) {
		GREG32(PINMUX, DIOB5_CTL) = 0xc;
		GREG32(PINMUX, GPIO0_GPIO1_SEL) = 5;
	}

	if (!(config0 & 0x10)) {
		GREG32(PINMUX, DIOB4_CTL) = 0xc;
		GREG32(PINMUX, GPIO0_GPIO0_SEL) = 6;
	}

    if (!(config0 & BIT(0))) {
        GREG32(PINMUX, DIOA0_SEL) = 0x46;
        GREG32(UART, NCO) = 0x13a9;
        GREG32(UART, CTRL) = 1;
    };

    return 0;
};

int init_trng(void)
{
    if (!(G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC) & BIT(8)))
        return 1;


    uint32_t trng_ldo_ctrl;
    uint32_t trng_analog_ctrl;

    if ((G32PROT_VAL(FUSE, TRNG_LDO_CTRL_EN) & 7) != 5) {
        trng_ldo_ctrl = 5;
    } else {
        trng_ldo_ctrl = G32PROT_VAL(FUSE, TRNG_LDO_CTRL) & 31;
    };
    G32PROT(TRNG, LDO_CTRL, trng_ldo_ctrl);


    if ((G32PROT_VAL(FUSE, TRNG_ANALOG_CTRL_EN) & 7) != 5)
        trng_analog_ctrl = 0;
    else
        trng_analog_ctrl = G32PROT_VAL(FUSE, TRNG_ANALOG_CTRL) & 15;

    G32PROT(TRNG, ANALOG_CTRL, trng_analog_ctrl);

    // set other TRNG regs
    G32PROT(TRNG, POST_PROCESSING_CTRL, 8);
    G32PROT(TRNG, SLICE_MAX_UPPER_LIMIT, 3);
    G32PROT(TRNG, SLICE_MIN_LOWER_LIMIT, 0);
    G32PROT(TRNG, OUTPUT_TIME_COUNTER, 0);
    G32PROT(TRNG, POWER_DOWN_B, 1);
    G32PROT(TRNG, GO_EVENT, 1);

    return 0;
};

int init_power(void)
{
    uint32_t applysec = G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC);
    uint32_t ret;

    if (!(applysec & BIT(9))) {
        ret = 1;
    }else{
        G32PROT(VOLT, ANALOG_POWER_DOWN_B, 1);
        G32PROT(VOLT, ANALOG_CONTROL, 0x1792f);
        ret = 0;
    };

    if (applysec & BIT(5)) {
        GREG32(PMU, SW_PDB_SECURE) = 1;
        BURN_CYCLES_DELAY(25);
        G32PROT(PMU, SW_PDB_SECURE, 3);
    };

    return ret;
};

void init_jittery_clock(void)
{
    uint32_t trim48 = G32PROT_VAL(FUSE, RC_JTR_OSC48_CC_TRIM);
    uint32_t trimfast = G32PROT_VAL(FUSE, RC_JTR_OSC60_CC_TRIM);
    uint32_t delta = trim48 - trimfast;

    G32PROT(XO, CLK_JTR_JITTERY_TRIM_BANK8, trim48);
    G32PROT(XO, CLK_JTR_JITTERY_TRIM_BANK0, trimfast);

    uint32_t setting = trim48 << 3;
    uint32_t current_val = setting;

    // write to de banks
    for (uint32_t reg = GRAWREG(XO, CLK_JTR_JITTERY_TRIM_BANK7);
            reg > GRAWREG(XO, CLK_JTR_JITTERY_TRIM_BANK1);
            reg -= 4) {
        current_val -= delta;
        glitch_reg32(reg, current_val >> 3);
    }

    // write to de banks
    for (uint32_t reg = GRAWREG(XO, CLK_JTR_JITTERY_TRIM_BANK9);
            reg <= GRAWREG(XO, CLK_JTR_JITTERY_TRIM_BANK15);
            reg += 4) {
        setting += delta;
        glitch_reg32(reg, setting >> 3);
    }

    G32PROT(XO, CLK_JTR_TRIM_CTRL, 0x8c9);
    G32PROT(XO, CLK_JTR_JITTERY_TRIM_EN, 1);
    G32PROT(XO, CLK_JTR_JITTERY_TRIM_RELOAD_PERIOD, 0);
    G32PROT(XO, CLK_JTR_SYNC_CONTENTS, 0);
};

void init_xtl_osc(void)
{
    /* Turn on DXO clock so we can write in the trim code in */
    pmu_clock_en(PERIPH_XO);
    
    /* Disable the XTL Clock */
    GWRITE_FIELD(PMU, OSC_CTRL, XTL_READYB, 0x1);

    GWRITE_FIELD(PMU, SW_PDB_SECURE, XTL, 0x1);
    
    /* Enable the flops for XTL in the glitchless switch */
    GWRITE_FIELD(PMU, OSC_CTRL, XTL_READYB, 0x0);

    GREG32(PMU, XTL_OSC_BYPASS) = 1;
    GREG32(XO, CLK_JTR_CTRL) = 0;
    GREG32(XO, CLK_TIMER_CTRL) = 0;
};

int init_clock(int cpu_setup_ret)
{
    uint32_t ret = cpu_setup_ret;
    uint32_t brom_applysec = G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC);
    
    if (!(brom_applysec & BIT(7))) {
        ret = 1;
    } else if ((G32PROT_VAL(FUSE, RC_JTR_OSC48_CC_EN) & 7) != 5 ||
               (G32PROT_VAL(FUSE, RC_JTR_OSC60_CC_EN) & 7) != 5) {
        ret = 3;
    } else {
        init_jittery_clock();
        ret = 0;
    }

    // appleflyer: not really sure what this is, but it's never triggered
    // on production devices as far as we know. it seems to be using an
    // external oscillator instead of the internal RC oscillators.
    if ((G32PROT_VAL(FUSE, RC_JTR_OSC48_CC_EN) & 7) != 5 && 
        (G32PROT_VAL(FUSE, RC_JTR_OSC60_CC_EN) & 7) != 5 && 
        !(G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC) & BIT(10)) &&
        (GREG32(GPIO, DATAIN) & 2)
    ) {
        init_xtl_osc();
    };

    if (!(brom_applysec & BIT(6)) &&
        ((G32PROT_VAL(FUSE, RC_RTC_OSC256K_CC_EN) & 7) == 5)
    ) {
        G32PROT(RTC, CTRL, G32PROT_VAL(FUSE, RC_RTC_OSC256K_CC_TRIM));
    };

    return ret;
};

int is_newer_than(const struct SignedHeader *a, const struct SignedHeader *b)
{
    if (a->epoch_ != b->epoch_)
        return a->epoch_ > b->epoch_;
    if (a->major_ != b->major_)
        return a->major_ > b->major_;
    return a->minor_ > b->minor_;
};

int is_known_key(uint32_t keyid)
{
	// Prod RO key is always allowed.
	if (keyid == 0xaa66150f)
		return 1;

	// Do not allow dev images to run if CONFIG0 has the prod bit set
	if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 8)
		return 0;

	if (keyid == 0x3716ee6b)
		return 1;

	// Any other key is a no go.
	return 0;
}

void apply_header_security(const struct SignedHeader *hdr)
{
    uint32_t applysec = G32PROT_VAL(FUSE, FW_DEFINED_BROM_APPLYSEC);

    /* 
        based on the fuse locked applysec config, 
        and based on the SignedHeader's applysec config,
        determine which features we should enable.
    */
    uint32_t allowed_applysec_features = hdr->applysec_ & applysec; 

    uint32_t alert_intr_sts0 = GREG32(GLOBALSEC, ALERT_INTR_STS0);
    uint32_t alert_intr_sts1 = GREG32(GLOBALSEC, ALERT_INTR_STS1);

    G32PROT(XO, CLK_JTR_SYNC_CONTENTS, 0);

    uint32_t pwrdn_scratch30 = 0;
    uint32_t alert_intr_masked;

    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_CAMO)) {
        alert_intr_masked = alert_intr_sts0 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                CAMO0_BREACH_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_CAMO);
    };

    // bus error alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_BUSERR)) {
        alert_intr_masked = alert_intr_sts0 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0,
                DBCTRL_DUSB0_IF_BUS_ERR_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_DSPS0_IF_BUS_ERR_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_DDMA0_IF_BUS_ERR_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_S_IF_BUS_ERR_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_I_IF_BUS_ERR_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_D_IF_BUS_ERR_ALERT)
        );
        
        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_BUSERR);
    };

    // bus obfuscation alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_BUSOBF)) {
        alert_intr_masked = alert_intr_sts0 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0,
                DBCTRL_DUSB0_IF_UPDATE_WATCHDOG_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_DSPS0_IF_UPDATE_WATCHDOG_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_DDMA0_IF_UPDATE_WATCHDOG_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_S_IF_UPDATE_WATCHDOG_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_I_IF_UPDATE_WATCHDOG_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0, 
                DBCTRL_CPU0_D_IF_UPDATE_WATCHDOG_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_BUSOBF);
    };

    // heartbeat alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_HEARTBEAT)) {
        alert_intr_masked = alert_intr_sts0 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0,             
                GLOBALSEC_HEARTBEAT_FAIL_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0,
                GLOBALSEC_DIFF_FAIL_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS0,
                CRYPTO0_IMEM_PARITY_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_HEARTBEAT);
    };

    // battery alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_BATMON)) {
        alert_intr_masked = alert_intr_sts1 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                PMU_BATTERY_MON_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_BATMON);
    };

    // timer alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_RTCCHECK)) {
        alert_intr_masked = alert_intr_sts1 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                RTC0_RTC_DEAD_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_RTCCHECK);
    };

    // jitter alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_JITTERY)) {
        alert_intr_masked = alert_intr_sts1 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                XO0_JITTERY_TRIM_DIS_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_JITTERY);
    };

    // trng alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_TRNG)) {
        alert_intr_masked = alert_intr_sts1 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                TRNG0_TIMEOUT_ALERT) |
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                TRNG0_OUT_OF_SPEC_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_TRNG);
    };

    // volt alerts
    if (allowed_applysec_features & BIT(BROM_FWBIT_APPLYSEC_VOLT)) {
        alert_intr_masked = alert_intr_sts1 & (
            GFIELD_MASK(GLOBALSEC, ALERT_INTR_STS1, 
                VOLT0_VOLT_ERR_ALERT)
        );

        if (alert_intr_masked)
            pwrdn_scratch30 |= BIT(BROM_FWBIT_APPLYSEC_VOLT);
    };

    /* 
        based on the fuse locked bootrom err response config, 
        and based on the SignedHeader's err response config,
        determine the bootrom's error response.
    */
    uint32_t brom_err_resp = G32PROT_VAL(
        FUSE, FW_DEFINED_BROM_ERR_RESPONSE
    ) | hdr->err_response_;

    uint32_t scratch_31 = GREG32(PMU, PWRDN_SCRATCH31);
    if (scratch_31 & 0x36db6)
		_purgatory(brom_err_resp & 3);

    if (pwrdn_scratch30) {
        brom_err_resp = (brom_err_resp >> 4) & 3;
        GREG32(PMU, PWRDN_SCRATCH30) = pwrdn_scratch30;
        _purgatory(brom_err_resp);

        if (brom_err_resp > 1)
            return;
    };

    increment_reg_counter();
};
