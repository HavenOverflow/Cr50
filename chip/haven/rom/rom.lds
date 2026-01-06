MEMORY
{
    FLASH (rx) : ORIGIN = 0x0, LENGTH = 0x2000
    IRAM (rw)  : ORIGIN = 0x10000, LENGTH = 0x10000
}

SECTIONS
{
    .text : {
        KEEP(*(.text.vecttable))

        . = ALIGN(4);
        *(.rodata*)

        . = ALIGN(4);
        KEEP(*(.text.__reset))
        
        . = ALIGN(4);
        build/init.o (.text)
        . = ALIGN(4);
        build/main.o (.text)
        
        . = ALIGN(4);
    } > FLASH =0xFFFFFFFF

    .bss : {
        . = ALIGN(8);
        *(.bss.regtable)
        *(.bss*)
    } > IRAM
    
    stack_end = ORIGIN(IRAM) + LENGTH(IRAM);
}

