module debugger.elf;

import core.sys.linux.elf;
import std.file;
import std.algorithm;
import std.bitmanip;
import debugger.exception;
import core.stdc.string;
import std.conv;

struct Function {
  public:
    string name;
    ulong addr;
    ubyte[] opbytes;
}

abstract class ELF {
  public:
    abstract ulong entryPoint();
    abstract uint bitLength();
    abstract ulong registerOf(ubyte[], string);
    abstract Function[] functions();
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
    override Function[] functions() { return []; }
}

class ELF64 : ELF {
  protected:
    ubyte[] data;
    Elf64_Ehdr ehdr;
    ulong[string] section_offsets;
    // Symbol[string] symbols;

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

      this.analyze();
    }

    Elf64_Shdr getSection(string section_name) {
      char[] name = section_name.dup;
      if (name[0] != '.') {
        name = '.' ~ name;
      }

      if (auto offset = name in section_offsets) {
        return *cast(Elf64_Shdr*)(data.ptr + *offset);
      }
      throw new DebuggerException("invalid section name: " ~ section_name);
    }

    /// Analyze ELF structure
    /// sections, symbols and relocatables
    void analyze() {
      section_offsets[".symstrtab"] = cast(ulong)(ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx);  // .symstrtab
      auto symstrtab = this.getSection(".symstrtab");

      // linear search all sections
      foreach (i; 0..ehdr.e_shnum) {
        auto section = cast(Elf64_Shdr*)(data.ptr + ehdr.e_shoff + ehdr.e_shentsize * i);
        
        // .strtab
        auto section_name = (cast(char*)(data.ptr + symstrtab.sh_offset + section.sh_name)).to!string();
        section_offsets[section_name] = cast(ulong)(ehdr.e_shoff + ehdr.e_shentsize * i);
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

    override Function[] functions() {
      Function[] funcs = [];
      auto symstrtab = this.getSection(".strtab");
      auto strtab = this.getSection(".strtab");
      auto symtab = this.getSection(".symtab");
      auto text = this.getSection(".text");

      // loop all symbols
      foreach (i; 0..(symtab.sh_size / symtab.sh_entsize)) {
        auto sym = cast(Elf64_Sym*)(data.ptr + symtab.sh_offset + symtab.sh_entsize * i);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC) {
          funcs ~= Function(
            (cast(char*)(data.ptr + strtab.sh_offset + sym.st_name)).to!string(),
            sym.st_value,
            (cast(ubyte*)(data.ptr + text.sh_offset + sym.st_value - text.sh_addr))[0..sym.st_size]
          );
        }
      }
      
      return funcs;
    }

    auto e_entry() {
      return ehdr.e_entry;
    }
}

