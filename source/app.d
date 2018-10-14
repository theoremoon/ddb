import std.stdio;
import core.sys.posix.unistd;
import std.process;
import std.string;
import std.typecons;
import std.conv;
import std.array;
import std.algorithm;
import std.format;
import debugger;
import core.sys.posix.sys.wait;
import core.stdc.stdlib;
import editline;

string elf_name;
ELF elf = null;
bool target_running = false;
bool first_break = true;
pid_t pid = 0;
ulong[] break_addrs = [];
ubyte[] regs = [];
string[] messages = [];

void ddb_msg(string message) {
  messages ~= message;
}

void ddb_log(string message, bool positive=true) {
  auto prefix = positive? "[+]" : "[-]";
  messages ~= prefix ~ message;
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
  foreach (f; elf.functions()) {
    if (f.length > 0) {
      ddb_msg("0x%x\t\t%s".format(f.address, f.name));
    }
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
  bool continue_repl = false;

  switch (cmd[0]) {
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
      continue_repl = true;
      break;

    case "fls":
    case "functions":
      ddb_list_functions();
      continue_repl = true;
      break;

    case "s":
    case "start":
      if (target_running) {
        ddb_log("program already running", false);
        continue_repl = true;
        break;
      }

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
        continue_repl = true;
        break;
      }

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
      ddb_msg("functions|lfs");
      ddb_msg("[h]elp|?");
      ddb_msg("exit");

      continue_repl = true;
      break;
    default:
      ddb_log("invalid command: " ~ cmd[0], false);
      continue_repl = true;
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
        messages.length = 0;

        auto cmd = ddb_read();
        cont = ddb_eval(cmd[0]);
        if (cmd[1].length > 0) {
          auto tmp = File("/tmp/ddb.tmp", "w");
          tmp.writeln(messages.join("\n"));
          tmp.close();

          auto r = executeShell("cat /tmp/ddb.tmp " ~ cmd[1]);
          writeln(r.output.stripRight());
        } else {
          writeln(messages.join("\n"));
        }
      }
    }
  }
}
