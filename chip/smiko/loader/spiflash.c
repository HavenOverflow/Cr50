#include "debug_printf.h"
#include "printf.h"
#include "sps_info_reset.h"

int setup_fifo(int arg1, int arg2)
{
    int result = arg1 + GREG32(SPS, RXFIFO_RPTR);
    int r1 = arg2 + GREG32(SPS, TXFIFO_WPTR);
    GREG32(SPS, RXFIFO_RPTR) = result;
    GREG32(SPS, TXFIFO_WPTR) = r1;
    return result;
}

int get_sps_val(void)
{
    return (GREG32(SPS, VAL) ^ 4) >> 2 & 1;
}

struct sps_pkt {
    uint8_t data[992];
    uint8_t hash[SHA256_DIGEST_SIZE];
};

#define DATAIN_RX_START 0x1082c
#define DATAIN_RX_END 0x10c2c

#define MAX_SPS_RX_SIZE 0x400

int clear_datain(void)
{
    uint32_t rxbuf[MAX_SPS_RX_SIZE / sizeof(uint32_t)];
    struct sps_pkt *pkt = (struct sps_pkt *)rxbuf;

    memset(rxbuf, 0, sizeof(rxbuf));

    rxbuf[0] = 0xb2;
    rxbuf[1] = 0x8000;

    GREG32(FUSE, DEV_ID0);
    GREG32(FUSE, DEV_ID1);
    
    /* Let's read the first byte of RWR0, RWR1, and RWR7 into our RX buffer. */
    char r6 = (int8_t)GREG32(KEYMGR, HKEY_RWR0);
    char r5 = (int8_t)GREG32(KEYMGR, HKEY_RWR1);
    char r4 = (int8_t)GREG32(KEYMGR, HKEY_RWR7);

    uint32_t r0 = (uint32_t)*(uint32_t*)0x10832;
    *(uint32_t*)0x10832 = r0 + 1;
    *(uint32_t*)0x10828 = (r0 << 5) + 0x10834;
    uint32_t r1_1 = *(uint32_t*)0x4001fff8 >> 0x1c;

    int r1_2;

    if (r1_1 == 3)
        r1_2 = 0;
    else if (r1_1 == 4)
        r1_2 = 1;
    else
        r1_2 = 0xff;

    uint32_t var_28 = (uint32_t)r6;
    uint32_t var_24 = (uint32_t)r5;
    uint32_t var_20 = (uint32_t)r4;
    int var_1c = 0x200;
    debug_printf("%02x:%08x%08x:%02x%02x%02x:%04x", r1_2);
    DCRYPTO_SHA256_hash(rxbuf, 0x4e0, 0x10c0c);
    read_sps_tx(rxbuf, MAX_SPS_RX_SIZE);
    
    int i_1;
    do
        i_1 = get_sps_val();
    while(i_1);

    return setup_fifo(i_1, MAX_SPS_RX_SIZE);
}

int spiflash(void)
{
    uint32_t *certs_ptr = 0x437fc;
    uint32_t cert_bits = 0xffffffff;

    do {
        certs_ptr += sizeof(*certs_ptr);
        cert_bits &= *(uint32_t*)certs_ptr;
    } while (i != 0x43ffc);

    /* Expect the RO_A certificates to be wiped before proceeding. */
    if (cert_bits != 0xffffffff)
        return 1;

    /* Make sure we're actually recieving data before continuing. */
    if (!(GREG32(GPIO, DATAIN) & 1))
        return 2;

    /* Ensure everything is cleared before continuing. */
    clear_datain();

    /* Read the incoming data from SPI. */
    int i_1;
    do
        i_1 = read_sps_fifo();
    while (i_1 != MAX_SPS_RX_SIZE);

    setup_fifo(i_1, 0);

    int i_2;
    do
        i_2 = read_sps_fifo();
    while (i_2 != MAX_SPS_RX_SIZE);

    void *var_810;
    read_sps_rx(var_810, MAX_SPS_RX_SIZE);
    read_sps_tx(var_810, MAX_SPS_RX_SIZE);
    setup_fifo(MAX_SPS_RX_SIZE, MAX_SPS_RX_SIZE);

    int i_3;
    do
        i_3 = read_sps_fifo();
    while (i_3 != MAX_SPS_RX_SIZE);

    void var_410;
    read_sps_rx(&var_410, MAX_SPS_RX_SIZE);
    setup_fifo(MAX_SPS_RX_SIZE, 0);

    /* Reset FWR before writing INFO page. */
    memset(GREG32(KEYMGR, HKEY_FWR0), 0, SHA256_DIGEST_SIZE);
    GREG32(KEYMGR, FW_MAJOR_VERSION) = 0;
    GREG32(KEYMGR, FW_VLD) = 2;

    /* Let's make sure these certificates run before continuing. */
    if (!try_cert(0, NULL, NULL) && 
        !try_cert(3, NULL, NULL) && 
        !try_cert(4, NULL, NULL) && 
        !try_cert(5, NULL, NULL) && 
        !try_cert(7, NULL, NULL) && 
        !try_cert(15, NULL, NULL) && 
        !try_cert(20, NULL, NULL)) {
        int r4_1 = 254;

        while (!try_cert(25, NULL, NULL)) {
            if (r4_1 + 1 == 1) {
                if (!try_cert(26, NULL, NULL)) {
                    void var_874;
                    void *r6_1 = &var_874;
                    void *r2_1 = &var_874;

                    for (int *i_4 = GREG32(KEYMGR, HKEY_FRR0); i_4 != GREG32_ADDR(KEYMGR, FLASH_RCV_WIPE); ) {
                        int r0_12 = *(uint32_t*)i_4;
                        i_4 = &i_4[1];
                        r2_1 += 4;
                        *(uint32_t*)r2_1 = r0_12;
                    }

                    void flash_info;
                    void *flash_info_ptr = &flash_info;
                    int flash_offset = 0x180;

                    while (!flash_info_read(flash_offset, flash_info_ptr)) {
                        flash_offset++;
                        flash_info_ptr += sizeof(uint32_t);

                        if (flash_offset == 0x188) {
                            void var_854;
                            void *i_5 = &var_854;
                            void var_834;

                            do {
                                i_5 += 4;
                                r6_1 += 4;
                                *(uint32_t*)i_5 ^= *(uint32_t*)r6_1;
                            } while (i_5 != &var_834);

                            void *var_830;
                            sha_trigger(var_830, &flash_info);

                            dcrpyto_sha_update(var_830, "RSA ", 4);
                            do_hash_words(var_830);
                            sha_trigger(var_830, var_830);

                            dcrpyto_sha_update(var_830, var_810, 0x7e0);

                            void var_31;
                            void *i_6 = &var_31;
                            void *r0_22 = do_hash_words(var_830) - 1;
                            int r1_7 = 0;
                            void var_11;

                            /* Verify that the two hashes match. */
                            /*do {
                                r0_22++;
                                i_6++;
                                r1_7 |= (uint32_t)*(uint8_t*)i_6 ^ (uint32_t)*(uint8_t*)r0_22;
                            } while (i_6 != &var_11);

                            if (r1_7)
                                return 3;*/

                            if (!memcmp(i_6, r0_22, SHA256_DIGEST_SIZE))
                                return 3;

                            int result = flash_write(0, 0xe00, var_810, 0x200, 0);

                            if (result)
                                return 4;

                            return result;
                        }
                    }
                }

                return 3;
            }

            r4_1--;
        }
    }

    return 3;
}

void check_engage_spiflash(void)
{
    if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 0x10 || !(GREG32(GPIO, DATAIN) & 1))
        return;
    
    init_pinmux();
    debug_printf("boot :");
    int rc = gpio_flashwrite();
    debug_printf("%d\n", rc);
    GREG32(SPS, DUMMY_WORD) = rc | 0x80;
}