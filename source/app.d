import std.stdio;
import core.sys.posix.unistd;
import std.process;
import std.string;
import debugger;
import core.sys.posix.sys.wait;
import core.stdc.stdlib;

void main(string[] args)
{
  const auto addr = 0x401156;
  if (args.length == 1) {
    writefln("<Usage>%s <target>", args[0]);
    return;
  }
  
  // ELF を解析。とりあえず e_entry をみる
  auto elf = readELF(args[1]);
  auto entry_address = elf.entryPoint();
  writefln("Entry point is: 0x%X", entry_address);

  // e_entry で break してもいいししなくてもいい
  bool break_at_main;
loop: while (true) {
    write("break at entrypoint? [y/n]:");
    switch (readln.strip()) {
      case "y":
        break_at_main = true;
        break loop;
      case "n":
        break_at_main = false;
        break loop;
      default:
        break;
    }
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

  // entry_point へのbreak
  if (break_at_main) {
    if (! set_hw_breakpoint_to(pid, entry_address, 0)) {
      throw new Exception("[-]Failed to Set Haredware Breakpoint");
    }
  }

  if (!set_hw_breakpoint_to(pid, addr, 3)) {
    throw new Exception("[-]Failed to Set Haredware Breakpoint");
  }


  // 再開
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
    writefln("[+]BREAK at 0x%X", eip);

    stdin.readln();
    ptrace(PTRACE_CONT, pid, null, null);
  }

  writeln("[+]Debugger Exit");

  return;
}
