/* Position-Independent Linker Script for C Bootstrapper (AArch64)
 *
 * Key features:
 * - Entry point at the beginning (bootstrap function)
 * - No absolute addresses (PIC)
 * - Minimal sections
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(bootstrap)

SECTIONS
{
    /* Start at address 0 - position independent */
    . = 0;

    /* Code section - executable */
    .text : {
        /* Ensure bootstrap() is at the very start */
        KEEP(*(.text.bootstrap))
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : {
        *(.data .data.*)
    }

    /* Uninitialized data */
    .bss : {
        *(.bss .bss.*)
    }

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.rela*)
        *(.got*)
        *(.plt*)
    }
}
