import std.stdio;
import core.sys.posix.unistd;
import std.process;
import std.file;
import std.path;
import std.string;
import std.typecons;
import std.conv;
import std.range;
import std.array;
import std.algorithm;
import std.exception;
import std.format;
import debugger;
import core.sys.posix.sys.wait;
import core.stdc.stdlib;
import core.stdc.string;
import core.stdc.errno : errno;
import editline;
import dapstone;

static class DDBException : Exception
{
    mixin basicExceptionCtors;
}

class DDB {
  protected:
    static const string TMPFILE = "/tmp/ddb.tmp";
    string elf_name;
    Capstone cs;
    ELF elf = null;
    debugger.Function[string] funcs;
    bool target_running = false;
    bool first_break = false;
    pid_t pid = 0;
    ulong load_addr;
    ulong[] break_addrs = [];
    ubyte[] regs = [];

    ulong[] wannabreaks = [];
    ulong[] tmpbreaks = [];

    string[] messages = [];
    string[] prefixes = [];
    alias CommandT = bool delegate(string[]);
    alias CmdEntry = Tuple!(string[], "names", string, "desc", CommandT, "func");
    CmdEntry[] command_table;

  public:
    this(string elf_name) {
      this.elf_name = elf_name;
      this.elf = readELF(elf_name);
      this.funcs = this.elf.functions();

      if (cast(ELF32)(elf) !is null) {
        cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
      } else if (cast(ELF64)(elf) !is null) {
        cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64);
      }

      this.command_table = [
        CmdEntry(["s", "start"], "tart target program", &cmdStart),
        CmdEntry(["b", "break"], "set hadware breakpoint at addr", &cmdBreak),
        CmdEntry(["c", "cont", "continue"], "continue execution", &cmdContinue),
        CmdEntry(["fls", "funcs", "functions"], "list function symbols", &cmdFunctions),
        CmdEntry(["d", "dis", "disasm"], "disassemble function", &cmdDisasm),
        CmdEntry(["g", "gengraph"], "generate jumpgraph", &cmdGengraph),
        CmdEntry(["h", "?", "help"], "show help", &cmdHelp),
        CmdEntry(["exit"], "exit debugger", (string[] args) { this.exit(); return true; }),
      ];
    }

    void exit() {
      if (target_running) {
        ptrace(PTRACE_KILL, pid, null, null);
      }
      clear_history();
      core.stdc.stdlib.exit(0);
    }

    void pushPrefix(string s) {
      this.prefixes ~= s;
    }
    void popPrefix() {
      this.prefixes.popBackN(1);
    }

    void msg(string s) {
      messages ~= prefixes.join("") ~ s;
    }

    void log(string msg, bool positive=true) {
      auto prefix = positive? "[+]" : "[-]";
      writeln(prefix ~ msg);
      stdout.flush();
    }

    auto readWhileNextJump(ulong addr) {
      auto cond_irs = ["je", "jne", "jb", "jbe", "jl", "jle"];
      const auto len = 800;
      auto offset = 0;
      while (true) {
        auto codes = getCodes(addr + offset, len);
        auto irs = cs.disasm(codes, addr + offset);

        foreach (ir; irs) {
          if (cond_irs.canFind(ir.opcode)) {
            auto operand1 = ir.addr + ir.bytes.length;
            auto operand2 = ir.operand.stripLeft("0x").stripLeft("0X").to!ulong(16);
            return tuple(ir.addr, operand1, operand2);
          }
          if (ir.opcode == "jmp") {
            return tuple(ir.addr, ir.operand.stripLeft("0x").stripLeft("0X").to!ulong(16), cast(ulong)0);
          }
        }

        offset += len;
      }
      assert(0);
    }

    void wait() {
      // wait break
      int status;
      waitpid(pid, &status, 0);
      if (!WIFSTOPPED(status)) {
        target_running = false;
      }

      // get register
      if (target_running) {
        regs.length = 256;
        if (ptrace(PTRACE_GETREGS, pid, null, regs.ptr) != 0) {
          throw new Exception("[-]failed to get regsiter");
        }

        auto eip = elf.registerOf(regs, (elf.bitLength == 64) ? "rip" : "eip");
        this.log("break at 0x%x".format(eip));

        // temporarily broke
        if (tmpbreaks.canFind(eip)) {
          removeAllHardwareBreakpoints();

          auto next = readWhileNextJump(eip);
          foreach (wb; wannabreaks) {
            if (eip < wb && wb <= next[0]) {
              // set breakpoint at wb
              setBreakpoint(wb);
            }
          }
          setBreakpoint(next[1]);
          if (next[2] == 0) {
            tmpbreaks = [next[1]];
          }
          else {
            setBreakpoint(next[2]);
            tmpbreaks = [next[1], next[2]];
          }

          // restart without interaction
          ptrace(PTRACE_CONT, pid, null, null);
          wait();
          return;
        }


        if (first_break) {
          first_break = false;

          // parse /proc/pid/maps and get real effective entry point address
          auto elf_abspath = absolutePath(this.elf_name, getcwd());
          auto maplines = readText("/proc/%d/maps".format(pid)).split("\n");
          auto elf_sections = maplines.filter!(line => line.canFind(elf_abspath));
          auto text_section = elf_sections.filter!(line => line.split(" ")[1].canFind('x')).array;
          if (text_section.length == 0) {
            throw new Exception("Failed to parse /prof/pid/maps"); 
          }
          this.load_addr = text_section[0].until("-").to!(string).to!(ulong)(16);
        }
      }
    }

    void removeAllHardwareBreakpoints() {
      foreach (i, _; this.break_addrs) {
        unset_hw_breakpoint_to(pid, cast(uint)i);
      }
      this.break_addrs.length = 0;
    }

    void setBreakpoint(ulong addr) {
      if (break_addrs.length >= 4) {
        this.log("Hardware breakpoint can be set at most four.", false);
        return;
      }

      if (target_running) {
        if (! set_hw_breakpoint_to(pid, addr, cast(int)break_addrs.length)) {
          throw new Exception("[-]Failed to Set Haredware Breakpoint");
        }
      }
      break_addrs ~= addr;
      this.log("set hardware breakpoint at 0x%x".format(addr));
    }

    ubyte[] getCodes(long addr, ulong len) {
      import std.bitmanip;
      import std.system : Endian;


      auto addr2 = addr;
      auto cnt = 0;
      ubyte[] codes = [];

      while (cnt < len) {
        // peek machine code 4 or 8 bytes
        auto code = ptrace(PTRACE_PEEKDATA, pid, cast(void*)addr, null);
        addr += elf.bitLength / 8;
        cnt += elf.bitLength / 8;

        // convert returned machine codes (long) to ubyte[]
        ubyte[] buf = new ubyte[]( code.sizeof );
        std.bitmanip.write!(typeof(code), Endian.littleEndian)(buf, code, 0);
        codes ~= buf;
      }

      return codes;
    }

    bool printCodesUntilRet(ubyte[] opbytes, ulong addr) {
      string[] opbytes_str = [];
      auto irs = cs.disasm(opbytes, addr);
      foreach (ir; irs) {
        opbytes_str ~= ir.bytes.formatOpbytes();
      }
      // long pad_length = opbytes_str.map!(x => x.length).reduce!((a, b) => max(a, b));
      const long pad_length = 32;

      foreach (i, ir; irs) {
        msg("0x%x\t%s\t%s %s".format(ir.addr, opbytes_str[i].leftJustifier(pad_length), ir.opcode, ir.operand));
        if (ir.opcode == "ret") {
          return true;
        }
      }
      return false;
    }


    void disasmBytes(ubyte[] opbytes, ulong addr) {
      string[] opbytes_str = [];
      auto irs = cs.disasm(opbytes, addr);
      foreach (ir; irs) {
        opbytes_str ~= ir.bytes.formatOpbytes();
      }
      // long pad_length = opbytes_str.map!(x => x.length).reduce!((a, b) => max(a, b));
      const long pad_length = 32;

      foreach (i, ir; irs) {
        msg("0x%x\t%s\t%s %s".format(ir.addr, opbytes_str[i].leftJustifier(pad_length), ir.opcode, ir.operand));
      }
    }

    bool cmdStart(string[] args) {
      if (target_running) {
        this.log("program is already running", false);
        return true;
      }

      this.pid = execTarget([elf_name] ~ args);
      this.log("target pid is: %d".format(pid));

      first_break = true;
      target_running = true;
      return false;
    }


    bool cmdBreak(string[] args) {
      if (args.length == 0) {
        this.log("<Usage>: break addr", false);
        return true;
      }

      if (auto f = args[0] in this.funcs) {
        this.wannabreaks ~= f.addr + this.load_addr;
        return true;
      }

      try {
        auto addr = fromAddr(args[0]);
        this.wannabreaks ~= addr;
      }
      catch (Exception e) {
        this.log("invalid address: " ~ args[0], false);
      }
      return true;
    }

    bool cmdContinue(string[] args) {
      if (!target_running) {
        this.log("program isn't running", false);
        return true;
      }
      // ---
      if (wannabreaks.length > 0) {
          removeAllHardwareBreakpoints();

          auto eip = elf.registerOf(regs, (elf.bitLength == 64) ? "rip" : "eip");
          auto next = readWhileNextJump(eip);
          foreach (wb; wannabreaks) {
            if (eip < wb && wb <= next[0]) {
              // set breakpoint at wb
              setBreakpoint(wb);
            }
          }
          setBreakpoint(next[1]);
          if (next[2] == 0) {
            tmpbreaks = [next[1]];
          }
          else {
            setBreakpoint(next[2]);
            tmpbreaks = [next[1], next[2]];
          }
      }
      // ---

      ptrace(PTRACE_CONT, pid, null, null);
      return false;
    }

    bool cmdDisasm(string[] args) {
      auto f = (ulong addr) {
        auto read_len = 800;
        auto offset = 0;
        while (true) {
          auto codes = getCodes(addr + offset, read_len);
          offset += read_len;
          if (printCodesUntilRet(codes, addr + offset)) {
            break;
          }
        }
      };

      if (args.length == 0) {
        auto eip = elf.registerOf(regs, (elf.bitLength == 64) ? "rip" : "eip");
        f(eip);
        return true;
      }

      if (args[0] == "help") {
        this.log("<Usage>: disasm addr", false);
        return true;
      }

      if (auto func = args[0] in this.funcs) {
        if (target_running) {
          f(func.addr + this.load_addr);
        }
        else {
          disasmBytes(func.opbytes, func.addr);
        }
        return true;
      }

      try {
        auto addr = args[0].fromAddr();
        getCodes(addr, 20 * elf.bitLength);
        return true;
      }
      catch (Exception e) {
        this.log("no function or addr: " ~ args[0], false);
      }
      return true;
    }

    bool cmdFunctions(string[] args) {
      // 関数の一覧を出してみる
      foreach (_, f; this.funcs) {
        if (f.opbytes.length > 0) {
          msg("0x%x\t\t%s".format(f.addr, f.name));
        }
      }
      return true;
    }

    // create jump graph from specific function
    bool cmdGengraph(string[] args) {
      if (args.length < 1) {
        this.log("<Usage>: jump_graph func [-a]", false);
        return true;
      }
      auto fname = args[0];
      if (fname !in this.funcs) {
        this.log("no such function: " ~ fname, false);
        return true;
      }


      // (bytes, jumpto)[addr]
      auto graph = makeJumpgraph(this.funcs[fname], this.cs);
      foreach (addr; graph.keys.sort) {
        // addr: [jumpto1,  jumpto2, ...]
        string heading = "0x%x:[%s]".format(addr, graph[addr].jumpto.map!(x => "0x%x".format(x)).array.join(", "));
        this.msg(cast(string)heading);
        
        // if -a is specified, show disassemble of block
        if (args.canFind("-a")) {
          pushPrefix("   ");
          disasmBytes(graph[addr][0], addr);
          this.msg("");
          popPrefix();
        }
      }
      return true;
    }

    bool cmdHelp(string[] args) {
      string[] left;
      foreach (cmd; this.command_table) {
        left ~= cmd.names.join("|");
      }
      auto pad_length = left.map!(x => x.length).array.sort[$-1] + 2;

      foreach (i, cmd; this.command_table) {
        writeln(left[i].leftJustifier(pad_length), cmd.desc);
      }
      return true;
    }

    // execute command and return continue loop(true) or wait break(false)
    bool evalCmd(string[] args) {
      foreach (cmd; this.command_table) {
        if (cmd.names.canFind(args[0])) {
          if (args.length > 1) {
            return cmd.func(args[1..$]);
          } else {
            return cmd.func([]);
          }
        }
      }

      this.log("unknown cmmand: " ~ args[0]);
      return true;
    }

    // return commands and pipe shell commands
    Tuple!(string[], string) readCmd() {
      string[] cmd;
      char[] pipe;

      while (cmd.length == 0) {
        // get input from readline
        writeln();
        auto line = readline("> ");
        if (line is null) {
          this.exit();
        }
        add_history(line);

        auto line2 = line.fromStringz();
        auto p = line2.countUntil('|');

        // if pipe
        if (p >= 0) {
          pipe = line2[p..$];
          cmd = cast(string[])(line2[0..p].split());
        }
        else {
          cmd = cast(string[])(line2.split());
        }
      }
      return tuple(cmd, cast(string)pipe);
    }
      
    void cmdRepl() {
      bool cont = true;
      while (cont) {
        // get input
        auto cmd = readCmd();
        try {
          cont = this.evalCmd(cmd[0]);
        } catch (DDBException e) {
          writeln(e.toString());
          continue;
        }

        // pipe message
        if (cmd[1].length > 0) {
          auto tmp = File(TMPFILE, "w");
          tmp.writeln(messages.join("\n"));
          tmp.close();

          auto r = executeShell("cat " ~ TMPFILE ~ cmd[1]);
          writeln(r.output.stripRight());
        }
        // print message
        else {
            writeln(messages.join("\n"));
        }


        // clear message buffer
        messages.length = 0;
      }
    }
}

DDB ddb = null;


alias AsmBlock = Tuple!(ubyte[], "opbytes", ulong[], "jumpto");
alias AsmBlocks = AsmBlock[ulong];

AsmBlocks makeJumpgraph(debugger.Function f, Capstone cs) {
  AsmBlocks blocks;

  const auto start_addr = f.addr;
  const auto end_addr = f.addr + f.opbytes.length;
  const auto irs = cs.disasm(f.opbytes, f.addr);

  ulong[] offsetof;
  ulong[ulong] addr_to_index;
  ulong addr = 0;
  foreach (i, ir; irs) {
    offsetof ~= addr;
    addr_to_index[ir.addr] = i;
    addr += ir.bytes.length;
  }


  void delegate(ulong) loopf;
  loopf = (ulong i) {
    const auto start_i = i;
    for (; i < irs.length; i++) {
      switch (irs[i].opcode) {
        // TODO: jmp rax
        case "jmp":
          auto target = irs[i].operand.stripLeft("0x").stripLeft("0X").to!ulong(16);
          if (!(start_addr <= target && target <= end_addr)) {
            throw new DDBException("unsupported jump target");
          }
          blocks[irs[start_i].addr] = AsmBlock(f.opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target]);
          if (target !in blocks) {
            loopf(addr_to_index[target]);
          }
          return;
        case "je":
        case "jne":
        case "jb":
        case "jbe":
        case "jl":
        case "jle":
          auto target1 = irs[i].operand.stripLeft("0x").stripLeft("0X").to!ulong(16);
          if (!(start_addr <= target1 && target1 <= end_addr)) {
            throw new DDBException("unsupported jump target");
          }
          auto target2 = irs[i + 1].addr;
          if (!(start_addr <= target2 && target2 <= end_addr)) {
            throw new DDBException("unsupported jump target");
          }

          blocks[irs[start_i].addr] = AsmBlock(f.opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target1, target2]);
          if (target1 !in blocks) {
            loopf(addr_to_index[target1]);
          }
          if (target2 !in blocks) {
            loopf(addr_to_index[target2]);
          }
          return;
        default:
          break;
      }
    }
    if (i == irs.length) {
      blocks[irs[start_i].addr] = AsmBlock(f.opbytes[offsetof[start_i]..offsetof[i-1] + irs[i-1].bytes.length], cast(ulong[])[]);
    }
  };
  loopf(0);

  return blocks;
}



auto execTarget(string[] args) {
  // デバッグ対象の起動
  auto pid = fork();
  if (pid == 0) {
    // child
    if (ptrace(PTRACE_TRACEME, 0, null, null) != 0) {
      throw new Exception("PTRACE_TRACEME failed");
    }
    execv(args[0], args);
    perror("failed to execv");
  }

  return pid;
}

ulong fromAddr(string addrstr) {
  if (addrstr.startsWith("0x") || addrstr.startsWith("0X")) {
    return addrstr[2..$].to!ulong(16);
  }

  throw new Exception("unimplemented");
}

string toAddrStr(ulong addr) {
  return "0x08%x".format(addr);
}


string formatOpbytes(ubyte[] bytes) {
  string[] buf = [];
  foreach (b; bytes) {
    buf ~= "%02x".format(b);
  }
  return buf.join(" ");
}

void main(string[] args)
{
  if (args.length == 1) {
    writefln("<Usage>%s <target>", args[0]);
    return;
  }
  
  // ELF を解析
  ddb = new DDB(args[1]);
  while (true) {
    if (ddb.target_running) {
      ddb.wait();
    }
    ddb.cmdRepl();
  }
}
