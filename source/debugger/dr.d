module debugger.dr;

import debugger.ptrace;
import std.bitmanip;
import core.sys.posix.sys.types;

enum BreakOn{
  EXEC  = 0,
  WRITE = 1,
  RW    = 3,
}

enum BreakLength{
  LEN1 = 0,
  LEN2 = 1,
  LEN8 = 2,  // when long mode 
  LEN4 = 3,
}

// DR7 レジスタの内部構造 32bit
alias dr7_t = uint;
auto set_local(ref dr7_t r, uint i, uint v) {
  uint x = (v & 1) << (i * 2);
  return r = (r & (~x)) | x;
}
auto set_RW(ref dr7_t r, uint i, uint v) {
  uint x = (v & 0b11) << (i * 4 + 16);
  return r = (r & (~x)) | x;
}
auto set_length(ref dr7_t r, uint i, uint v) {
  uint x = (v & 0b11) << (i * 4 + 18);
  return r = (r & (~x)) | x;
}

long offsetof_dr(long i) {
  return 848 + i*8;
}

// pid のプロセスの addr の位置に HW BP を設置する。 DRr 番を用いる
bool set_hw_breakpoint_to(pid_t pid, ulong addr, uint r) {
  if (!(0 <= r && r < 4)) {
    return false;
  }

  // PTRACE_POKEUSER: USER領域に書き込み
  // DRr に addr を書き込む
  if (ptrace(PTRACE_POKEUSER, pid, cast(void*)offsetof_dr(r), cast(void*)addr) != 0) {
    return false;
  }

  dr7_t dr7 = cast(uint)(ptrace(PTRACE_PEEKUSER, pid, cast(void*)offsetof_dr(7), null));

  // 必要な情報を書き込む
  dr7.set_local(r, 1);  // local enable for braekpoint in DRr
  dr7.set_RW(r, BreakOn.EXEC);  // when that address is executed 
  dr7.set_length(r, BreakLength.LEN1);

  if (ptrace(PTRACE_POKEUSER, pid, cast(void*)offsetof_dr(7), cast(void*)dr7) != 0) {
    return false;
  }
  return true;
}
