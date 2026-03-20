#ifndef __TANTIBUS_BOARD_H
#define __TANTIBUS_BOARD_H
/* General board configuration sourced at build time. */


/* ============= Features that we don't want ============= */
/* Get rid of common EC features */
#undef CONFIG_FMAP
#undef CONFIG_FLASH /* This only removes the EC flash code, we make our own in chip/dauntless. */
#undef CONFIG_GPIO
#undef CONFIG_COMMON_GPIO
#undef CONFIG_CMD_MEM
#undef CONFIG_COMMON_PANIC_OUTPUT
#undef CONFIG_CMD_LID_ANGLE
#undef CONFIG_CMD_POWERINDEBUG
#undef CONFIG_DMA_DEFAULT_HANDLERS
#undef CONFIG_HIBERNATE
#undef CONFIG_LID_SWITCH
#undef CONFIG_CMD_RW
#undef CONFIG_CMD_SYSLOCK
#undef CONFIG_CONSOLE_CMD_HISTORY
#undef HAS_TASK_HOSTCMD /* We don't need to send events to the AP */
#undef CONFIG_HOSTCMD_EVENTS
#undef CONFIG_DCRYPTO /* Don't use dcrypto code from chip/dauntless */
/* We're not ready for these just yet. */
#undef CONFIG_EXTENSION_COMMAND
#undef CONFIG_TPM2
#undef CONFIG_WATCHDOG
#define CONFIG_NO_PINHOLD /* Removes PINMUX, HOLD register usage */
#undef CONFIG_RBOX_WAKEUP

/* ============= Features we do want ============= */
#define CONFIG_FPU              /* Dauntless has an FPU! */
#define CONFIG_USB
#define CONFIG_SPP
#define CONFIG_CMD_SYSINFO
#define CONFIG_CUSTOMIZED_RO
#define CONFIG_FW_INCLUDE_RO
#define CONFIG_FLASH_PHYSICAL
#define CONFIG_LOW_POWER_IDLE
/* Most of us testing don't have UART, so we'll output panic data over the console as well. */
#define CONFIG_PANIC_CONSOLE_OUTPUT
/* Tantibus CFW is still very much in development as of the time of writing,
 * so we'll want the most information out of crashes as possible.
 */
#define CONFIG_DEBUG_STACK_OVERFLOW
#define CONFIG_BOARD_ID_SUPPORT
#define CONFIG_NON_HC_FW_UPDATE
#define CONFIG_FLASH_FILESYSTEM
/* For now, enable ROM vectors until we find all the Dauntless hardware registers. */
#define CONFIG_USE_ROM_VECTORS
/* Build the DeCrypto RO firmware update. This won't always work once it gets
 * patched, but we leave it in anyway to make CFW easier. 
 */
#define CONFIG_DECRYPTO
/* Unlock all restrictions in regards to the flash. */
#define CONFIG_UNRESTRICTED_FLASH_ACCESS
/* The RW's are designed to by dynamic on Dauntless. */
#define CONFIG_DYNAMIC_FLASH_LAYOUT


/* ============= Board-specific chip configuration ============= */
/* UART indexes (use define rather than enum to expand them) */
#define UART_TI50	0     /* GSC <-> Servo Header */
#define UART_AP		1     /* EC <-> GSC */
#define UART_EC		2     /* AP <-> GSC */
#define UART_FPMCU  3     /* FPMCU <-> GSC */
#define UART_UNUSED 4
#define UART_NULL	0xff

#define UARTN UART_TI50 /* Default UART Channel */

#endif /* __TANTIBUS_BOARD_H */