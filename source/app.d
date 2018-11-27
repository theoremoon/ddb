import std.stdio;
import core.sys.posix.unistd;
import std.process;
import std.string;
import std.typecons;
import std.conv;
import std.file;
import std.path;
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
    bool first_break = true;
    pid_t pid = 0;
    ulong[] break_addrs = [];
    ulong[] wanna_breaks = [];
    ulong load_addr = 0x0;
    ubyte[] regs = [];
    ulong ip;
    ulong numof_regs = 0x0;

    string[] messages = [];
    string[] prefixes = [];
    alias CommandT = bool delegate(string[]);
    alias CmdEntry = Tuple!(string[], "names", string, "desc", CommandT, "func");
    CmdEntry[] command_table;

  public:
    this(string elf_name, ulong numof_regs) {
      this.elf_name = elf_name;
      this.elf = readELF(elf_name);
      this.funcs = this.elf.functions();
      this.numof_regs = numof_regs;

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
        CmdEntry(["a", "analy"], "analyze jumpgraph", &cmdAnalyze),
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


    void wait() {
      // wait break
      int status;
      waitpid(pid, &status, 0);
      if (!WIFSTOPPED(status)) {
        target_running = false;
      }

      // set hardware breakpoint when execve
      if (target_running && first_break) {
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

          return;
      } 

      // get register
      if (target_running && !first_break) {
        regs.length = 256;
        if (ptrace(PTRACE_GETREGS, pid, null, regs.ptr) != 0) {
          throw new Exception("[-]failed to get regsiter");
        }

        this.ip = elf.registerOf(regs, (elf.bitLength == 64) ? "rip" : "eip");
        this.log("break at 0x%x".format(this.ip));
      }
    }

    void setBreakpoint(ulong addr) {
      /*
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
      */
      wanna_breaks ~= addr;
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

      target_running = true;
      first_break = true;
      return false;
    }


    bool cmdBreak(string[] args) {
      if (args.length == 0) {
        this.log("<Usage>: break addr", false);
        return true;
      }

      ulong addr = 0;
      try {
        addr = parseAddr(args[0]);
        setBreakpoint(addr);
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

      auto r = select_breakpoints(this.cs, ubyte[] opbytes, ulong func_addr, current_addr, this.numof_regs, this.wanna_breaks);

      ptrace(PTRACE_CONT, pid, null, null);
      return false;
    }

    bool cmdDisasm(string[] args) {
      if (args.length == 0) {
        this.log("<Usage>: disasm addr", false);
        return true;
      }

      if (auto func = args[0] in this.funcs) {
        disasmBytes(func.opbytes, func.addr);
      } else {
        this.log("no such function: " ~ args[0], false);
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
        // addr: [{jumpto1,  jumpto2, ...}, {jumpfrom1, jumpfrom2, ...}]
        string jumpto = "{%s}".format(graph[addr].jumpto.map!(x => "0x%x".format(x)).join(", "));
        string jumpfrom = "{%s}".format(graph[addr].jumpfrom.map!(x => "0x%x".format(x)).join(", "));
        string heading = "0x%x:[%s, %s]".format(addr, jumpto, jumpfrom);
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

    // main work
    bool cmdAnalyze(string[] args) {
      if (args.length < 1) {
        this.log("<Usage>: banalyze func <break points>", false);
        return true;
      }
      auto fname = args[0];
      if (fname !in this.funcs) {
        this.log("no such function: " ~ fname, false);
        return true;
      }

      // (bytes, jumpto)[addr]
      auto graph = makeJumpgraph(this.funcs[fname], this.cs);

      ulong[] bps;
      foreach (a; args[1..$]) {
        bps ~= parseAddr(a);
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
ulong parseAddr(string addrstr) {
  if (addrstr.startsWith("0x") || addrstr.startsWith("0X")) {
    return addrstr[2..$].to!ulong(16);
  }

  throw new Exception("unimplemented");
}
string toAddr(ulong addr) {
  return "0x" ~ addr.to!string(16);
}


DDB ddb = null;

alias AsmBlock = Tuple!(ubyte[], "opbytes", ulong[], "jumpto", ulong[], "jumpfrom");

AsmBlock[ulong] makeJumpgraph(debugger.Function f, Capstone cs) {
  return makeJumpgraph(f.opbytes, f.addr, cs);
}

AsmBlock[ulong] makeJumpgraph(ubyte[] opbytes, ulong addr, Capstone cs) {
  AsmBlock[ulong] blocks;
  ulong[][ulong] jumpfroms;

  const auto start_addr = addr;
  const auto end_addr = addr + opbytes.length;
  const auto irs = cs.disasm(opbytes, addr);

  ulong[] offsetof;
  ulong[ulong] addr_to_index;
  ulong offset_addr = 0;
  foreach (i, ir; irs) {
    offsetof ~= offset_addr;
    addr_to_index[ir.addr] = i;
    offset_addr += ir.bytes.length;
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
          blocks[irs[start_i].addr] = AsmBlock(opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target], []);
          if (target in jumpfroms) {
            jumpfroms[target] ~= irs[start_i].addr;
          } else {
            jumpfroms[target] = [irs[start_i].addr];
          }

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

          blocks[irs[start_i].addr] = AsmBlock(opbytes[offsetof[start_i]..offsetof[i] + irs[i].bytes.length], [target1, target2], []);
          if (target1 in jumpfroms) {
            jumpfroms[target1] ~= irs[start_i].addr;
          } else {
            jumpfroms[target1] = [irs[start_i].addr];
          }
          if (target2 in jumpfroms) {
            jumpfroms[target2] ~= irs[start_i].addr;
          } else {
            jumpfroms[target2] = [irs[start_i].addr];
          }

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
      blocks[irs[start_i].addr] = AsmBlock(opbytes[offsetof[start_i]..offsetof[i-1] + irs[i-1].bytes.length], cast(ulong[])[], []);
    }
  };
  loopf(0);

  foreach (k; blocks.keys) {
    if (k in jumpfroms) {
      blocks[k].jumpfrom = jumpfroms[k];
    }
  }

  return blocks;
}


auto getRoots(AsmBlock[ulong] graph, ulong entry) {
  /// IDEA: Node 毎に持たずとも root からの全経路みたいなのを持っておけばよいのでは？？
  ///  ↑いまの探索でも自然にそうなる
  ulong[][][ulong] roots;  // 経路のリスト（をNode毎にもつ）
  int [ulong][ulong] loop_nodes;  // from, to の間に loop があることを示す（無向
  ulong[] exploring;  // 探索中であることを表すリスト
  
  // 経路のリストを返す
  ulong[][] delegate(ulong) loopf;

  // 経路全探索する
  loopf = (ulong addr) {
    // メモがあれば使う
    if (addr in roots) {
      return roots[addr];
    }
    exploring ~= addr; // このNodeを含む経路をたどっていることを示しておく

    /*
    == 省略される点にBreakPointを仕掛ける場合に、その点がなくなってしまうので死ぬ。それが治ったらこれをコメントインして ==
    // 1個しかジャンプ先がない場合はそちらに処理を任せてこちらの情報は保存しない
    if (graph[addr].jumpto.length == 1) {
      auto to = graph[addr].jumpto[0];

      // 探索中ならループするという情報だけを入れておく
      if (exploring.canFind(to)) {
        loop_nodes[addr][to] = 1;
        exploring.popBack(); 
        ulong[][] dummy;  // ここからの経路はないのでこうする
        return dummy;
      }

      auto r = loopf(to);

      // entryが存在しないとあとで死ぬ
      if (addr == entry) {
        roots[entry] = r;
      }

      exploring.popBack();  // たどり終えた
      return r;
    }
    */


    ulong[][] node_roots = [];  // このNode からたどる経路
    // このNodeから伸びている先
    foreach (to; graph[addr].jumpto) {
      // 探索中ならループするという情報だけを入れておく
      if (exploring.canFind(to)) {
        loop_nodes[addr][to] = 1;
        continue;
      }

      auto to_roots = loopf(to);  // 伸びている先の伸びている先……と辿った経路
      if (to_roots.length == 0) {
        node_roots ~= [to];  // 先が行き止まりだったらこう
      } else {
        foreach (r; to_roots) {
          node_roots ~= (to ~ r);  // 伸びた先も追加しておいて……ということ
        }
      }
    }

    exploring.popBack();  // たどり終えた
    return roots[addr] = node_roots;
  };
  loopf(entry);

  return roots[entry];
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

string formatOpbytes(ubyte[] bytes) {
  string[] buf = [];
  foreach (b; bytes) {
    buf ~= "%02x".format(b);
  }
  return buf.join(" ");
}

long linearSearch(E)(E[] range, E element) {
  foreach (i, e; range) {
    if (element == e) {
      return i;
    }
  }
  return -1;
}


/// return true if x including all bits of y 
bool binaryIncluding(ulong x, ulong y) {
  return ((~x)&y) == 0;
}


// breakする点で探索する
// breakしたい点M > HardwareBreakpointの数N だとうまく行かないように見えるかもしれないが
// 少なくともどこかに現在地の直後の点が存在するはずなので保証はある
// でも失敗するかもしれないので一応 bool で成否を帰している
Tuple!(bool, ulong[]) search_break_set(uint numof_bpreg, ulong[][ulong]to_breaks, ulong[ulong] breakpoint_binexpr) {
  const uint ideal_binexpr = (1 << to_breaks.keys.length) - 1;
  ulong[][] breakpoints = to_breaks.values;
  Tuple!(bool, ulong[]) delegate(ulong[], ulong, int) f;

  // 現状breakするということにした点
  // 現状でカバーできる範囲の2進数表記
  // 探索する点のindex
  // 絶対全探索以外の方法があると思うんだが ^ ^
  // 計算量は N = numof_wannabreak, to_breaksの各配列の要素数をそれぞれM_i として
  // O(M_1 * M_2 * ... * M_N) です
  f = (ulong[] current_points, ulong current_x, int index) {
    if (current_points.length == numof_bpreg || index >= breakpoints.length) {
      return tuple(false, cast(ulong[])[]);
    }

    foreach (bp; breakpoints[index]) {
      auto bin = breakpoint_binexpr[bp];
      if (! binaryIncluding(current_x, bin)) {
        writefln("trying: [%s](0b%08b)", (current_points ~ bp).map!(toAddr).join(", "), current_x | bin);
        if ((current_x | bin) == ideal_binexpr) {
          return tuple(true, current_points ~ bp);  // 見つけた
        }
        
        // とりあえず加えてみて探索
        auto r = f(current_points ~ bp, current_x | bin, index + 1);
        if (r[0] == true) {
          return r;
        }
      }
    }
    return f(current_points, current_x, index+1);
  };

  auto r = f([], 0, 0);
  return r;
}

/// かなりメインの処理。breakしたい点を受け取ってどこにbreakpointを設置するか決定する
auto select_breakpoints(Capstone cs, ubyte[] opbytes, ulong func_addr, ulong current_addr, long numof_bpreg, ulong[] wanna_breaks) {
  //TODO: wanna_breaks はいまblockのアドレスが渡されることを期待しているので、
  // 実際の命令のアドレスを受け取ってblockのアドレスに変換するようにする

  // グラフを作る
  auto graph = makeJumpgraph(opbytes, func_addr, cs);

  // 経路を取る
  auto roots = getRoots(graph, current_addr);
  // writeln("roots:");
  // foreach (r; roots) {
  //   write("\t");
  //   writeln(r.map!(toAddr).join("->"));
  // }


  // break される点をkeyにして、breakできる点をリストとして持つ
  ulong[][ulong] to_breaks; 
  ulong[ulong] breakpoint_breakablenums;
  ulong[ulong] breakpoint_binexpr;

  // 全経路のうち、breakしたい点を含むものを列挙する
  // 経路数N, breakしたい点の数をMとしておよそ O(NM)
  foreach (j, addr; wanna_breaks) {
    ulong[][] addr_roots = [];

    foreach (i, r; roots) {
      auto u = r.linearSearch(addr);
      if (u != -1) {  // アドレスAを含む
        addr_roots ~= r[0..u+1];
      }
    }

    if (addr_roots.length == 0) {
      continue;
    }

    // 複数の経路で共通のNodeを探す（＝＞通らない可能性がある点に仕掛けるのは無駄が大きいため）
    // なければそこにはBPしかけなくていい（＝＞たどり着けないということなので）
    ulong[] intersects = addr_roots[0];
    foreach (i; 1..addr_roots.length) {
      intersects = setIntersection(intersects, addr_roots[i]).array;
    }
    to_breaks[addr] = intersects;

    // intersectsに含まれる各点がbreakできる個数を加算しておく
    foreach (p; intersects) {
      // ある点がいくつのwannabreakに対処できるか集計する
      // これは↓の1のビット数と同じになる
      if (p in breakpoint_breakablenums) {
        breakpoint_breakablenums[p] += 1;
      } else {
        breakpoint_breakablenums[p] = 1;
      }

      if (p in breakpoint_binexpr) {
        breakpoint_binexpr[p] |= 1 << j;
      } else {
        breakpoint_binexpr[p] = 1 << j;
      }
    }
  }

  // breakできる個数でソートするといい感じ
  foreach (ref breakpoints; to_breaks) {
    breakpoints.sort!((x, y) => breakpoint_breakablenums[x] < breakpoint_breakablenums[y]);
  }
  
  // foreach (addr, binexpr; breakpoint_binexpr) {
  //   writefln("%s:  0b%08b", addr.toAddr(), binexpr);
  // }
  // foreach (key, values; to_breaks) {
  //   write(key.toAddr() ~ ": ");
  //   writeln(values.map!(toAddr).join(", "));
  // }

  // breakする点で探索する
  // breakしたい点M > HardwareBreakpointの数N だとうまく行かないように見えるかもしれないが
  // 少なくともどこかに現在地の直後の点が存在するはずなので保証はある
  auto r = search_break_set(cast(uint)numof_bpreg, to_breaks, breakpoint_binexpr);
  return r;
}


void main(string[] args)
{
  if (args.length < 4) {
    writefln("<Usage>%s <target> <numof_bpreg>", args[0]);
    return;
  }

  auto elf = readELF(args[1]);
  Capstone cs;
  auto funcs = elf.functions();

  if (cast(ELF32)(elf) !is null) {
    cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_32);
  } else if (cast(ELF64)(elf) !is null) {
    cs = new Capstone(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64);
  }
  auto funcname = args[2];
  auto numof_bpreg = args[3].to!int;
  auto wannabreaks = args[4..$].map!(parseAddr).array;

}
