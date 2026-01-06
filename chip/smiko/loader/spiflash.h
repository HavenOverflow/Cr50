enum spi_resp {
    SPI_VERIFY_FAIL = 3,
    SPI_WRITE_ERROR = 4
};

void check_engage_spiflash(void);

int setup_fifo(int arg1, int arg2);

int spiflash(void);