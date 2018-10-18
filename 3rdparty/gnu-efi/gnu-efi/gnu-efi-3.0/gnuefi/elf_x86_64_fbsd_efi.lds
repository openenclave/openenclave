/* Same as elf_x86_64_efi.lds, except for OUTPUT_FORMAT below - KEEP IN SYNC */
OUTPUT_FORMAT("elf64-x86-64-freebsd", "elf64-x86-64-freebsd", "elf64-x86-64-freebsd")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SECTIONS
{
  . = 0;
  ImageBase = .;
  .hash : { *(.hash) }	/* this MUST come first! */
  . = ALIGN(4096);
  .eh_frame : 
  { 
    *(.eh_frame)
  }
  . = ALIGN(4096);
  .text :
  {
   *(.text)
  }
  .reloc :
  {
   *(.reloc)
  }
  . = ALIGN(4096);
  .data :
  {
   *(.rodata*)
   *(.got.plt)
   *(.got)
   *(.data*)
   *(.sdata)
   /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
   *(.sbss)
   *(.scommon)
   *(.dynbss)
   *(.bss)
   *(COMMON)
   *(.rel.local)
  }
  . = ALIGN(4096);
  .dynamic  : { *(.dynamic) }
  . = ALIGN(4096);
  .rela :
  {
    *(.rela.data*)
    *(.rela.got)
    *(.rela.stab)
  }
  . = ALIGN(4096);
  .dynsym   : { *(.dynsym) }
  . = ALIGN(4096);
  .dynstr   : { *(.dynstr) }
  . = ALIGN(4096);
  .ignored.reloc :
  {
    *(.rela.reloc)
  }
}
