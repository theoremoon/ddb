import std.stdio;
import core.sys.posix.unistd;
import std.process;
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
import editline;
import dapstone;

static class DDBException : Exception
{
    mixin basicExceptionCtors;
}

string elf_name;
Capstone cs;
ELF elf = null;
bool target_running = false;
bool first_break = true;
pid_t pid = 0;
ulong[] break_addrs = [];
ubyte[] regs = [];
string[] messages = [];
string[] prefixes = [];

alias AsmBlocks = Tuple!(ubyte[], ulong[])[ulong];

AsmBlocks make_jumpgraph(debugger.Function f) {
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
        case "jmp":
          auto target = irs[i].operand.stripLeft("0x").stripLeft("0X").to!ulong(16);
          if (!(start_addr <= target && target <= end_addr)) {
            throw new DDBException("unsupported jump target");
          }
          blocks[irs[start_i].addr] = tuple(f.opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target]);
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

          blocks[irs[start_i].addr] = tuple(f.opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target1, target2]);
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
      blocks[irs[start_i].addr] = tuple(f.opbytes[offsetof[start_i]..offsetof[i-1] + irs[i-1].bytes.length], cast(ulong[])[]);
    }
  };
  loopf(0);

  return blocks;
}

void ddb_make_jumpgraph(string entry_function) {
  const auto functions = elf.functions();
  if (entry_function !in functions) {
    ddb_log("function does not exist: " ~ entry_function, false);
    return;
  }
  auto f = functions[entry_function];

}

void ddb_msg(string message) {
  char[] msg = [];
  foreach (p; prefixes) {
    msg ~= p.dup;
  }
  messages ~= (msg.idup ~ message);
}

void ddb_push_prefix(string p) {
  prefixes ~= p;
}

void ddb_pop_prefix() {
  if (prefixes.length > 0) {
    prefixes.popBackN(1);
  }
}

void ddb_log(string message, bool positive=true) {
  auto prefix = positive? "[+]" : "[-]";
  writeln(prefix ~ message);
}

void ddb_exit() {
  if (target_running) {
    ptrace(PTRACE_KILL, pid, null, null);
  }
  clear_history();
  exit(0);
}

void ddb_new_breakpoint(ulong addr) {
  if (break_addrs.length >= 4) {
    ddb_log("Hardware breakpoint can be set at most four.", false);
    return;
  }

  if (target_running) {
    if (! set_hw_breakpoint_to(pid, addr, cast(int)break_addrs.length)) {
      throw new Exception("[-]Failed to Set Haredware Breakpoint");
    }
  }
  break_addrs ~= addr;
  ddb_log("set hardware breakpoint at 0x%x".format(addr));
}

void ddb_list_functions() {
  // 関数の一覧を出してみる
  foreach (_, f; elf.functions()) {
    if (f.opbytes.length > 0) {
      ddb_msg("0x%x\t\t%s".format(f.addr, f.name));
    }
  }
}

string format_opbytes(ubyte[] bytes) {
  string[] buf = [];
  foreach (b; bytes) {
    buf ~= "%02x".format(b);
  }
  return buf.join(" ");
}

void ddb_disasm_bytes(ubyte[] opbytes, ulong addr) {
    string[] opbytes_str = [];
    auto irs = cs.disasm(opbytes, addr);
    foreach (ir; irs) {
      opbytes_str ~= ir.bytes.format_opbytes();
    }
    // long pad_length = opbytes_str.map!(x => x.length).reduce!((a, b) => max(a, b));
    const long pad_length = 32;

    foreach (i, ir; irs) {
      ddb_msg("0x%x\t%s\t%s %s".format(ir.addr, opbytes_str[i].leftJustifier(pad_length), ir.opcode, ir.operand));
    }
}

void ddb_start(string[] args) {
  // デバッグ対象の起動
  pid = fork();
  if (pid == 0) {
    // child
    if (ptrace(PTRACE_TRACEME, 0, null, null) != 0) {
      throw new Exception("PTRACE_TRACEME failed");
    }
    execv(elf_name, elf_name ~ args);
  }

  ddb_log("target pid is: %d".format(pid));

  target_running = true;
  first_break = true;
}

Tuple!(string[], string) ddb_read() {
  string[] cmd;
  char[] pipe = [];
  while (true) {
    writeln();
    auto line = readline("> ");
    if (line is null) {
      ddb_exit();
    }
    add_history(line);

    auto line2 = line.fromStringz();
    auto p = line2.countUntil('|');
    if (p >= 0) {
      pipe = line2[p..$];
      cmd = cast(string[])(line2[0..p].split());
    } else {
      cmd = cast(string[])(line2.split());
    }
    if (cmd.length == 0) {
      continue;
    }
    break;
  }
  return tuple(cmd, cast(string)pipe);
}

bool ddb_eval(string[] cmd) {
  bool continue_repl = true;

  switch (cmd[0]) {
    case "g":
    case "jump_graph":
      if (cmd.length < 2) {
        ddb_log("<Usage>: jump_graph func [-a]", false);
        break;
      }
      if (auto func = cmd[1] in elf.functions()) {
        auto graph = make_jumpgraph(*func);
        foreach (addr; graph.keys.sort) {
          char[] msg = "0x%x:".format(addr).dup;
          if (graph[addr][1].length > 0) {
            foreach (j; graph[addr][1]) {
              msg ~= " -->0x%x".format(j);
            }
          }

          ddb_msg(cast(string)msg);
          if (cmd.length >= 3 && cmd[2] == "-a") {
            ddb_push_prefix("   ");
            ddb_disasm_bytes(graph[addr][0], addr);
            ddb_msg("");
            ddb_pop_prefix();
          }
        }
      } else {
        ddb_log("no such function: " ~ cmd[1], false);
      }
      break;
    case "b":
    case "break":
      if (cmd.length != 2) {
        ddb_log("<Usage>: break addr", false);
        break;
      }
      ulong addr = 0;
      try {
        addr = cmd[1].stripLeft("0x").stripLeft("0X").to!int(16);
      }
      catch (Exception e) {
        ddb_log("invalid address: " ~ cmd[1], false);
        break;
      }

      ddb_new_breakpoint(addr);
      break;

    case "fls":
    case "functions":
      ddb_list_functions();
      break;

    case "d":
    case "disasm":
      if (cmd.length == 1) {
        ddb_log("<Usage>: disasm func", false);
        break;
      }
      if (auto func = cmd[1] in elf.functions()) {
        ddb_disasm_bytes(func.opbytes, func.addr);
      } else {
        ddb_log("no such function: " ~ cmd[1], false);
      }
      break;

    case "s":
    case "start":
      if (target_running) {
        ddb_log("program already running", false);
        break;
      }

      continue_repl = false;
      if (cmd.length == 1) {
        ddb_start([]);
      } else {
        ddb_start(cmd[1..$]);
      }
      break;

    case "c":
    case "continue":
      if (!target_running) {
        ddb_log("program isn't running", false);
        break;
      }

      continue_repl = false;
      ptrace(PTRACE_CONT, pid, null, null);
      break;

    case "exit":
      ddb_exit();
      break;

    case "?":
    case "h":
    case "help":
      if (target_running) {
        ddb_msg("[c]ontinue");
      } else {
        ddb_msg("[s]tart [args]");
      }
      ddb_msg("[b]reak addr");
      ddb_msg("[d]isasm function");
      ddb_msg("functions|lfs");
      ddb_msg("[h]elp|?");
      ddb_msg("exit");

      break;
    default:
      ddb_log("invalid command: " ~ cmd[0], false);
      break;
  }
  return continue_repl;
}

void main(string[] args)
{
  if (args.length == 1) {
    writefln("<Usage>%s <target>", args[0]);
    return;
  }
  
  // ELF を解析
  elf_name = args[1];
  elf = readELF(elf_name);
  if (cast(ELF32)(elf) !is null) {
    cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
  } else if (cast(ELF64)(elf) !is null) {
    cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64);
  }

  while (true) {
    // wait break
    int status;
    if (target_running) {
      waitpid(pid, &status, 0);
      if (!WIFSTOPPED(status)) {
        target_running = false;
      }
    }

    // get register
    if (target_running && !first_break) {
      regs.length = 256;
      if (ptrace(PTRACE_GETREGS, pid, null, regs.ptr) != 0) {
        throw new Exception("[-]failed to get regsiter");
      }

      auto eip = elf.registerOf(regs, "eip");
      ddb_log("break at 0x%x".format(eip));
    }

    // set hardware breakpoint when execve
    if (target_running && first_break) {
      first_break = false;
      foreach (i, addr; break_addrs) {
        if (! set_hw_breakpoint_to(pid, addr, cast(int)i)) {
          throw new Exception("[-]Failed to Set Haredware Breakpoint");
        }
      }
      ptrace(PTRACE_CONT, pid, null, null);
    } else {
      auto cont = true;
      while (cont) {
        Tuple!(string[], string) cmd;
        try {
          cmd = ddb_read();
          cont = ddb_eval(cmd[0]);
        } catch(DDBException e) {
          writeln("[-]"~e.toString());
          messages.length = 0;
          continue;
        }

        if (cmd[1].length > 0) {
          auto tmp = File("/tmp/ddb.tmp", "w");
          tmp.writeln(messages.join("\n"));
          tmp.close();

          auto r = executeShell("cat /tmp/ddb.tmp " ~ cmd[1]);
          writeln(r.output.stripRight());
        } else {
          writeln(messages.join("\n"));
        }
        messages.length = 0;
      }
    }
  }
}
