#include "common.h"
#include "registers.h"
#include "vectors.h"

void nmi_handler(void)
{
	while (true)
		asm("wfi");
}

int _purgatory(int level)
{
	uint32_t resp;

	if (level == 3) {
		resp = GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
		GREG32(CRYPTO, WIPE_SECRETS) = 0xffffffff;
		GREG32(KEYMGR, AES_WIPE_SECRETS) = 0xffffffff;
		GREG32(KEYMGR, FLASH_RCV_WIPE) = 0xffffffff;

		if (resp & 0x2000) {
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
			int i;

			do {
				i = GREG32(GLOBALSEC, CPU0_S_PERMISSION);
				GREG32(GLOBALSEC, DDMA0_PERMISSION) = 0;
				GREG32(GLOBALSEC, CPU0_S_DAP_PERMISSION) = 0;
				GREG32(GLOBALSEC, CPU0_S_PERMISSION) = 0;
			} while (i != 0x33);
		}
	}

	if (level > 3)
		return level - 2;

	while (true)
		;
}