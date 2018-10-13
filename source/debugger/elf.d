module debugger.elf;

import core.sys.linux.elf;
import std.file;
import std.algorithm;
import std.bitmanip;
import debugger.exception;

abstract class ELF {
  public:
    ulong entryPoint();
    uint bitLength();
    ulong registerOf(ubyte[], string);
}

ELF readELF(string filename) {
  auto ehdr = *cast(Elf32_Ehdr*)(read(filename).ptr);
  switch (ehdr.e_ident[EI_CLASS]) {
    case ELFCLASS32: 
      return new ELF32(filename);
    case ELFCLASS64:
      return new ELF64(filename);
    default:
      throw new DebuggerException("Neither ELF32 nor ELF64");
  }
  assert(0);
}

bool isElf(T)(T ehdr) {
  return (ehdr.e_ident[EI_MAG0] == ELFMAG0) &&
    (ehdr.e_ident[EI_MAG1] == ELFMAG1) &&
    (ehdr.e_ident[EI_MAG2] == ELFMAG2) &&
    (ehdr.e_ident[EI_MAG3] == ELFMAG3);
}

class ELF32 : ELF {
  protected:
    ubyte[] data;
    Elf32_Ehdr ehdr;
  public:
    this(string filename) {
      data = cast(ubyte[])read(filename);
      ehdr = *cast(Elf32_Ehdr*)(data.ptr);

      if (!ehdr.isElf()) {
        throw new DebuggerException("not a ELF file");
      }
      if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
        throw new DebuggerException("not a 32bit ELF file");
      }
    }

    override uint bitLength() { return 32; }

    override ulong entryPoint() {
      return ehdr.e_entry;
    }

    override ulong registerOf(ubyte[] reg_struct, string reg_name) { return 0; }
}

class ELF64 : ELF {
  protected:
    ubyte[] data;
    Elf64_Ehdr ehdr;
  public:
    this(string filename) {
      data = cast(ubyte[])read(filename);
      ehdr = *cast(Elf64_Ehdr*)(data.ptr);

      if (!ehdr.isElf()) {
        throw new DebuggerException("not a ELF file");
      }
      if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        throw new DebuggerException("not a 32bit ELF file");
      }
    }

    override uint bitLength() { return 64; }

    override ulong entryPoint() {
      return ehdr.e_entry;
    }

    override ulong registerOf(ubyte[] reg_struct, string reg_name) {
      char[] name = reg_name.dup;

      auto reg_names = ["r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx","rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss","fs_base","gs_base","ds","es","fs","gs"];

      // 64bit registers
      auto i = reg_names.countUntil(name); 
      if (i >= 0) {
        return reg_struct.peek!(ulong, Endian.littleEndian)(i*8);
      }

      // 32bit registers
      name[0] = 'r';
      i = reg_names.countUntil(name); 
      if (i >= 0) {
        return reg_struct.peek!(ulong, Endian.littleEndian)(i*8) & 0xffffffff;
      }

      throw new DebuggerException("invalid register name: " ~ reg_name);
    }
}

