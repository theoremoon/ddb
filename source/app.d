import std.stdio;
import core.sys.posix.unistd;
import std.process;
import std.string;
import std.conv;
import debugger;
import core.sys.posix.sys.wait;
import core.stdc.stdlib;

void main(string[] args)
{
  if (args.length == 1) {
    writefln("<Usage>%s <target>", args[0]);
    return;
  }
  
  // ELF を解析。とりあえず e_entry をみる
  auto elf = readELF(args[1]);
  auto entry_address = elf.entryPoint();
  writefln("Entry point is: 0x%X", entry_address);

  // 関数の一覧を出してみる
  foreach (f; elf.functions()) {
    if (f.length > 0) {
      writefln("0x%x    %s", f.address, f.name);
    }
  }
  writeln();

  writeln("You can set hardware breakpoint at most four, or type start to debug program");
  writefln("example: >b 0x%x", entry_address);
  writeln("example: >start");

  // e_entry で break してもいいししなくてもいい
  int next_dr = 0;
  ulong[] break_addrs = [];
loop: while (!stdin.eof()) {
    write("\n>");
    auto cmd = readln.strip();
    if (cmd.startsWith("b ")) {
      if (break_addrs.length >= 4) {
        writeln("[-]hardware breakpoint can be set at most four");
        continue;
      }
      ulong addr = 0;
      try {
        addr = cmd[2..$].strip().stripLeft("0x").stripLeft("0X").to!int(16);
      }
      catch (Exception e) {
        writeln("[-]invalid address: " ~ cmd[2..$].strip());
        continue;
      }
      break_addrs ~= addr;
      writefln("Set breakpoint %d at: 0x%x", break_addrs.length, addr);
      continue;
    }

    if (cmd.startsWith("start")) {
      break;
    }

    writeln("[-]invalid command: " ~ cmd);
  }

  auto pid = fork();
  if (pid == 0) {
    // child
    ptrace(PTRACE_TRACEME, 0, null, null);
    execv(args[1], args[1..$]);
  }

  // execv で BREAK することになってるのでとまる
  int status;
  waitpid(pid, &status, 0);
  
  foreach (i, addr; break_addrs) {
    if (! set_hw_breakpoint_to(pid, addr, cast(int)i)) {
      throw new Exception("[-]Failed to Set Haredware Breakpoint");
    }
  }

  // start
  ptrace(PTRACE_CONT, pid, null, null);

  while (true) {
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
      break;
    }
    ubyte[] buf = new ubyte[](256);
    if (ptrace(PTRACE_GETREGS, pid, null, buf.ptr) != 0) {
      throw new Exception("[-]failed to get regsiter");
    }
    auto eip = elf.registerOf(buf, "eip");
    writefln("[+]break at 0x%X", eip);
    writeln("cont to continue execution program");

    while (!stdin.eof()) {
      write("\n>");
      auto cmd = readln.strip();
      if (cmd == "cont") {
        break;
      }

      writeln("[-]invalid command: " ~ cmd);
    }

    ptrace(PTRACE_CONT, pid, null, null);
  }

  writeln("[+]Debugger Exit");

  return;
}
