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

  auto pid = fork();
  if (pid == 0) {
    // child
    ptrace(PTRACE_TRACEME, 0, null, null);
    execv(args[1], args[1..$]);
  }

  int status;
  waitpid(pid, &status, 0);
  if (!set_hw_breakpoint_to(pid, addr, 0)) {
    stderr.writeln("[-]Faild to set Hardware Breakpoint");
    exit(EXIT_FAILURE);
  }

  ptrace(PTRACE_CONT, pid, null, null);

  waitpid(pid, &status, 0);
  if (!WIFSTOPPED(status)) {
    stderr.writeln("[-]Child process may be exited");
    exit(EXIT_FAILURE);
  }

  writeln("[+]BREAK!");
  stdin.readln();

  // DETACH して子プロセスが終了するまで待つ
  if (ptrace(PTRACE_DETACH, pid, null, null) != 0) {
    stderr.writeln("[-]PTRACE_DETACH");
    exit(EXIT_FAILURE);
  }

  waitpid(pid, &status, 0);  // 子プロセスがBREAKするのまつ
  writeln("[+]Debugger Exit");

  return;
}
