/* Copyright 2025 HavenOverflow
 * Use of this code is permissible so long as the appropriate credit
 * is provided. See the LICENSE file for more info.
 */

#ifndef __OPENTITAN_HW_REGDEFS_H
#define __OPENTITAN_HW_REGDEFS_H

/* Base Addresses */
#define GC_UART_BASE_ADDR                        0x40000000
#define GC_UART0_BASE_ADDR                       0x40000000
#define GC_UART1_BASE_ADDR                       0x40010000
#define GC_UART2_BASE_ADDR                       0x40020000
#define GC_UART3_BASE_ADDR                       0x40030000
#define GC_GPIO_BASE_ADDR                        0x40040000
#define GC_GPIO0_BASE_ADDR                       0x40040000
#define GC_SPI_BASE_ADDR                         0x40050000
#define GC_SPI0_BASE_ADDR                        0x40050000
#define GC_I2C_BASE_ADDR                         0x40080000
#define GC_I2C0_BASE_ADDR                        0x40080000
#define GC_I2C1_BASE_ADDR                        0x40090000
#define GC_I2C2_BASE_ADDR                        0x400a0000

#define GC_IBEX_BASE_ADDR                        0x411F0000

/* IBEX Registers */
#define GC_IBEX_ALERT_TEST_OFFSET                0x0
#define GC_IBEX_ALERT_TEST_DEFAULT               0x0
#define GC_IBEX_SW_RECOV_ERR_OFFEST              0x4
#define GC_IBEX_SW_RECOV_ERR_DEFAULT             0x9
#define GC_IBEX_SW_FATAL_ERR_OFFSET              0x8
#define GC_IBEX_SW_FATAL_ERR_DEFAULT             0x9
#define GC_IBEX_IBUS_REWGEN0_OFFSET              0xc
#define GC_IBEX_IBUS_REWGEN0_DEFAULT             0x1
#define GC_IBEX_IBUS_REWGEN1_OFFSET              0x10
#define GC_IBEX_IBUS_REWGEN1_DEFAULT             0x0
#define GC_IBEX_IBUS_ADDR_EN0_OFFSET             0x14
#define GC_IBEX_IBUS_ADDR_EN0_DEFAULT            0x0
#define GC_IBEX_IBUS_ADDR_EN1_OFFSET             0x18
#define GC_IBEX_IBUS_ADDR_EN1_DEFAULT            0x0
#define GC_IBEX_IBUS_ADDR_MATCHING0_OFFSET       0x1c
#define GC_IBEX_IBUS_ADDR_MATCHING0_DEFAULT      0x0
#define GC_IBEX_IBUS_ADDR_MATCHING1_OFFSET       0x20
#define GC_IBEX_IBUS_ADDR_MATCHING1_DEFAULT      0x0

#endif /* __OPENTITAN_HW_REGDEFS_H */