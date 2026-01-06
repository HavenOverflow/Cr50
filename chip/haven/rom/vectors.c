#include "registers.h"
#include "setup.h"
#include "regtable.h"

extern void reset(void);
extern void stack_end(void);
void common_handler(void);
void busfault_handler(void);

typedef void (*func)(void);

/* Vector table */
const func vectors[] __attribute__((section(".text.vecttable"))) = {
	stack_end,
	reset,
    common_handler, // NMI
    common_handler, // HardFault
    common_handler, // MPUFault
	busfault_handler, // BusFault
    common_handler, // UsageFault
    common_handler, // reserved
    common_handler, // reserved
    common_handler, // reserved
    common_handler, // reserved
    common_handler, // SVCall
    common_handler, // Debug
    common_handler, // reserved
    common_handler, // PendSV
    common_handler, // SysTick
};

void busfault_handler(void) {
    GREG32(PMU, PWRDN_SCRATCH29) = 2;
    uint32_t brom_err_resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
    _purgatory((brom_err_resp & BIT(7)));
};

void common_handler(void) {
    GREG32(PMU, PWRDN_SCRATCH29) = 3;
    uint32_t brom_err_resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
    _purgatory((brom_err_resp & BIT(8)));
};

void _purgatory(int level)
{
    uint32_t resp;

    if (level == 3) {
        resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);

        /* Wipe flash and keymgr secrets. */
        GREG32(CRYPTO, WIPE_SECRETS) = 0xffffffff;
        GREG32(KEYMGR, AES_WIPE_SECRETS) = 0xffffffff;
        GREG32(KEYMGR, FLASH_RCV_WIPE) = 0xffffffff;

        if (resp & 0x2000) {
            /* Disable read and exec access to the loader and lock INFO1. */
            GREG32(GLOBALSEC, CPU0_I_REGION0_CTRL) = 0;
            GREG32(GLOBALSEC, FLASH_REGION0_CTRL) = 0;
            GREG32(GLOBALSEC, FLASH_REGION7_CTRL) = 0;
        }

        if (resp & 0x4000) {
            GREG32(GLOBALSEC, ALERT_DLYCTR0_EN0) = 0x80000;
            GREG32(GLOBALSEC, ALERT_DLYCTR0_LEN) = 1;
            GREG32(GLOBALSEC, ALERT_FW_TRIGGER) = 0xa9;
        }

        if (resp & 0x8000) {
            GREG32(GLOBALSEC, ALERT_DLYCTR0_SHUTDOWN_EN) = 1;
            GREG32(GLOBALSEC, ALERT_DLYCTR0_EN0) = 0x80000;
            GREG32(GLOBALSEC, ALERT_DLYCTR0_LEN) = 1;
            GREG32(GLOBALSEC, ALERT_FW_TRIGGER) = 0xa9;
        }

        if (resp & 0x1000) {
            do {
                level = GREG32(GLOBALSEC, CPU0_S_PERMISSION);
                GREG32(GLOBALSEC, DDMA0_PERMISSION) = 0;
                GREG32(GLOBALSEC, CPU0_S_DAP_PERMISSION) = 0;
                GREG32(GLOBALSEC, CPU0_S_PERMISSION) = 0;
            } while (level != 0x33);
        }
    }

    if (level - 2 > 1)
        return;

    while (true)
        __asm__ volatile("wfe");
}