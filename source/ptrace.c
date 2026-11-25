/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#include <pthread.h>
#endif

#ifdef __PROSPERO__
#include <pthread.h>

#include <ps5/kernel.h>
#include <ps5/nid.h>
#endif

#include "log.h"
#include "ptrace.h"

#ifdef __ORBIS__

#define PT_DETACH_ADDR ((caddr_t)1)
#define PT_STEP_STOPPED(status)                                               \
  (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
#define PT_SCRATCH_SIZE 0x20000

static int ps4_ptrace_is_patched = 0;

static int
patch_ps4_site(unsigned long addr, const unsigned char *before,
               const unsigned char *after, size_t len, const char *name) {
  unsigned char current[8];

  if(!addr || !before || !after || !len || len > sizeof(current)) {
    errno = EINVAL;
    return -1;
  }
  if(kernel_copyout(addr, current, len)) {
    LOG_EPRINTF("Cannot read kernel patch site %s at 0x%lx\n", name, addr);
    errno = EIO;
    return -1;
  }
  if(!memcmp(current, after, len)) {
    return 0;
  }
  if(memcmp(current, before, len)) {
    LOG_EPRINTF("Unexpected bytes at kernel patch site %s 0x%lx\n", name,
                addr);
    errno = EINVAL;
    return -1;
  }
  if(kernel_patch(addr, before, after, len)) {
    LOG_PERROR("kernel_patch");
    return -1;
  }
  if(kernel_copyout(addr, current, len) || memcmp(current, after, len)) {
    LOG_EPRINTF("Kernel patch verification failed at %s 0x%lx\n", name, addr);
    errno = EIO;
    return -1;
  }
  return 0;
}

/*
 * Reject ambiguous scans so a changed kernel layout cannot patch the wrong
 * site.
 */
static unsigned long
ps4_kernel_text_size(void) {
  static unsigned long size;
  unsigned char ehdr[64];
  unsigned char phdr[56];
  unsigned long first = ~0ul;
  unsigned long end = 0;

  if(size) {
    return size;
  }
  size = KERNEL_IMAGE_SIZE;
  if(kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE, ehdr, sizeof(ehdr))
     || memcmp(ehdr,
               "\x7f"
               "ELF",
               4)) {
    return size;
  }

  const unsigned long phoff = *(unsigned long *)(ehdr + 0x20);
  const unsigned short phnum = *(unsigned short *)(ehdr + 0x38);

  for(unsigned short i = 0; i < phnum; i++) {
    if(kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + phoff + i * sizeof(phdr),
                      phdr, sizeof(phdr))) {
      return size;
    }

    const unsigned int type = *(unsigned int *)phdr;
    const unsigned int flags = *(unsigned int *)(phdr + 4);
    const unsigned long vaddr = *(unsigned long *)(phdr + 0x10);
    const unsigned long memsz = *(unsigned long *)(phdr + 0x28);

    if(type != 1) {
      continue;
    }
    if(vaddr < first) {
      first = vaddr;
    }
    if((flags & 1) && vaddr + memsz > end) {
      end = vaddr + memsz;
    }
  }
  if(end > first && end - first < KERNEL_IMAGE_SIZE) {
    size = end - first;
  }
  return size;
}

static unsigned long
find_unique_ps4_pattern(const char *pattern) {
  const unsigned long base = KERNEL_ADDRESS_IMAGE_BASE;
  const unsigned long text = ps4_kernel_text_size();
  unsigned long match = kernel_find_pattern(base, text, pattern);

  if(!match) {
    errno = ENOENT;
    return 0;
  }
  if(match <= base || match - base >= text) {
    errno = EFAULT;
    return 0;
  }
  const size_t remaining = text - (match + 1 - base);
  if(remaining && kernel_find_pattern(match + 1, remaining, pattern)) {
    errno = EEXIST;
    return 0;
  }
  return match;
}

static int
patch_ps4_aob_site(const char *before_pattern, const char *after_pattern,
                   size_t site_offset, const unsigned char *before,
                   const unsigned char *after, size_t length,
                   const char *name) {
  errno = 0;
  unsigned long match = find_unique_ps4_pattern(before_pattern);
  if(!match && errno == EEXIST) {
    LOG_EPRINTF("Ambiguous AOB for kernel patch site %s\n", name);
    return -1;
  }
  if(!match) {
    errno = 0;
    match = find_unique_ps4_pattern(after_pattern);
    if(!match && errno == EEXIST) {
      LOG_EPRINTF("Ambiguous patched AOB for kernel patch site %s\n", name);
      return -1;
    }
    if(match) {
      return patch_ps4_site(match + site_offset, after, after, length, name);
    }
  }
  if(!match) {
    return 1;
  }
  return patch_ps4_site(match + site_offset, before, after, length, name);
}

static const unsigned char *
ps4_acmgr_call_bytes(unsigned int fw) {
  switch(fw & 0xffff0000) {
    case 0x4500000:
    case 0x4550000:
      return (const unsigned char *)"\x77\x39\x13\x00";
    case 0x4700000:
      return (const unsigned char *)"\x37\x69\x13\x00";
    case 0x4710000:
    case 0x4720000:
    case 0x4730000:
    case 0x4740000:
      return (const unsigned char *)"\xc7\x68\x13\x00";
    case 0x5000000:
      return (const unsigned char *)"\xe7\xe7\x1b\x00";
    case 0x5010000:
      return (const unsigned char *)"\xe7\xe7\x1b\x00";
    case 0x5030000:
      return (const unsigned char *)"\xf7\xe8\x1b\x00";
    case 0x5050000:
      return (const unsigned char *)"\xf7\xe8\x1b\x00";
    case 0x5070000:
      return (const unsigned char *)"\xf7\xe8\x1b\x00";
    case 0x5500000:
      return (const unsigned char *)"\x77\xe8\xfd\xff";
    case 0x5530000:
      return (const unsigned char *)"\x97\xe8\xfd\xff";
    case 0x5550000:
      return (const unsigned char *)"\x97\xe8\xfd\xff";
    case 0x5560000:
    case 0x6000000:
    case 0x6020000:
    case 0x6200000:
      return (const unsigned char *)"\xf7\x04\x0e\x00";
    case 0x6500000:
    case 0x6510000:
    case 0x6700000:
    case 0x6710000:
    case 0x6720000:
      return (const unsigned char *)"\x07\xc4\x09\x00";
    case 0x7000000:
    case 0x7010000:
    case 0x7020000:
      return (const unsigned char *)"\x97\x47\x0a\x00";
    case 0x7500000:
    case 0x7510000:
    case 0x7550000:
      return (const unsigned char *)"\x67\xd1\xd7\xff";
    case 0x8000000:
    case 0x8010000:
    case 0x8020000:
    case 0x8030000:
      return (const unsigned char *)"\x77\x40\xfb\xff";
    case 0x8500000:
    case 0x8520000:
      return (const unsigned char *)"\x27\x18\xeb\xff";
    case 0x9000000:
      return (const unsigned char *)"\x07\xc1\x28\x00";
    case 0x9030000:
    case 0x9040000:
      return (const unsigned char *)"\xa7\xbd\x28\x00";
    case 0x9500000:
    case 0x9510000:
    case 0x9600000:
      return (const unsigned char *)"\xa7\x45\x29\x00";
    case 0x10000000:
    case 0x10010000:
      return (const unsigned char *)"\xc7\xcc\x01\x00";
    case 0x10500000:
    case 0x10700000:
    case 0x10710000:
      return (const unsigned char *)"\x17\xa4\x01\x00";
    case 0x11000000:
    case 0x11020000:
      return (const unsigned char *)"\xb7\x96\xff\xff";
    case 0x11500000:
    case 0x11520000:
    case 0x12000000:
    case 0x12020000:
    case 0x12500000:
    case 0x12520000:
    case 0x13000000:
    case 0x13020000:
    case 0x13040000:
    case 0x13500000:
    case 0x13520000:
    case 0x14000000:
      return (const unsigned char *)"\x57\xc9\x06\x00";
    case 0x14020000:
      return (const unsigned char *)"\xc7\xc9\x06\x00";
    default:
      return 0;
  }
}

static int
patch_ps4_acmgr_debug_gate(unsigned int fw) {
  static const unsigned char before_prefix[5]
      = { 0x55, 0x48, 0x89, 0xe5, 0xe8 };
  static const unsigned char after[8]
      = { 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3 };
  char before_pattern[] = "554889e5e8????????31c983f8010f94c189c85dc3";
  const unsigned char *call_bytes = ps4_acmgr_call_bytes(fw);
  static const char after_pattern[]
      = "48c7c001000000c3??31c983f8010f94c189c85dc3";
  static const char legacy_pattern[]
      = "b001c3????????????31c983f8010f94c189c85dc3";
  unsigned long match;
  unsigned char original[sizeof(after)];

  if((fw & 0xffff0000) < 0x04500000) {
    return 0;
  }

  if(call_bytes) {
    snprintf(before_pattern, sizeof(before_pattern),
             "554889e5e8%02x%02x%02x%02x31c983f8010f94c189c85dc3",
             call_bytes[0], call_bytes[1], call_bytes[2], call_bytes[3]);
  }

  errno = 0;
  match = find_unique_ps4_pattern(before_pattern);
  if(!match && errno == EEXIST) {
    LOG_EPUTS("Ambiguous AOB for ACMGR debug gate");
    return -1;
  }
  if(!match) {
    errno = 0;
    match = find_unique_ps4_pattern(after_pattern);
    if(!match && errno == EEXIST) {
      LOG_EPUTS("Ambiguous patched AOB for ACMGR debug gate");
      return -1;
    }
    if(match) {
      return patch_ps4_site(match, after, after, sizeof(after),
                            "acmgr-system-debug");
    }
  }
  if(!match) {
    errno = 0;
    match = find_unique_ps4_pattern(legacy_pattern);
    if(!match && errno == EEXIST) {
      LOG_EPUTS("Ambiguous legacy AOB for ACMGR debug gate");
      return -1;
    }
    if(match) {
      return 0;
    }
  }
  if(!match) {
    LOG_EPRINTF("ACMGR debug gate AOB not found for firmware 0x%x\n", fw);
    errno = ENOENT;
    return -1;
  }
  if(kernel_copyout(match, original, sizeof(original))) {
    LOG_PERROR("read ACMGR debug gate");
    return -1;
  }
  if(memcmp(original, before_prefix, sizeof(before_prefix))) {
    errno = EINVAL;
    return -1;
  }
  return patch_ps4_site(match, original, after, sizeof(after),
                        "acmgr-system-debug");
}

static int
patch_ps4_ptrace_allow_gate(unsigned int fw) {
  static const unsigned char before[2] = { 0x77, 0x1c };
  static const unsigned char after[2] = { 0xeb, 0x1c };
  int result
      = patch_ps4_aob_site("ffff4189c483f82a????48b8361000007e0200004c0fa3e0",
                           "ffff4189c483f82aeb1c48b8361000007e0200004c0fa3e0",
                           8, before, after, sizeof(before), "ptrace-allow");

  if(result > 0 && (fw & 0xffff0000) >= 0x07000000) {
    LOG_EPRINTF("Ptrace-allow AOB missing on firmware 0x%x\n", fw);
    errno = ENOENT;
    return -1;
  }
  return result < 0 ? -1 : 0;
}

static int
patch_ps4_ptrace_policy_gate(unsigned int fw) {
  static const unsigned char before[5] = { 0x48, 0x8b, 0x41, 0x08, 0x44 };
  static const unsigned char after[5] = { 0xe9, 0x7c, 0x02, 0x00, 0x00 };
  int result = patch_ps4_aob_site("488b41084489c3488b7840e8",
                                  "e97c02000089c3488b7840e8", 0, before, after,
                                  sizeof(before), "ptrace-policy");

  if(result > 0 && (fw & 0xffff0000) >= 0x07000000) {
    LOG_EPRINTF("Ptrace-policy AOB missing on firmware 0x%x\n", fw);
    errno = ENOENT;
    return -1;
  }
  return result < 0 ? -1 : 0;
}

static void
patch_ps4_candebug_gate_monolithic(unsigned int fw) {
  static const unsigned char before[3] = { 0x0f, 0x94, 0xc0 };
  static const unsigned char after[3] = { 0x31, 0xc0, 0x90 };
  unsigned char current[3];
  unsigned long match;

  errno = 0;
  match = find_unique_ps4_pattern(
      "b81000000041f6442403047515488b4308488b7840e8????????85c00f94c0");
  if(!match) {
    LOG_EPRINTF("Candebug monolithic AOB %s on firmware 0x%x; skipped\n",
                errno == EEXIST ? "ambiguous" : "missing", fw);
    return;
  }
  if(kernel_copyout(match + 28, current, sizeof(current))) {
    LOG_EPRINTF("Cannot read candebug gate at 0x%lx\n", match);
    return;
  }
  if(!memcmp(current, after, sizeof(after))) {
    return;
  }
  if(memcmp(current, before, sizeof(before))) {
    LOG_EPRINTF("Unexpected candebug gate bytes on firmware 0x%x; skipped\n",
                fw);
    return;
  }
  if(patch_ps4_site(match + 28, current, after, sizeof(after), "candebug")) {
    LOG_EPRINTF("Candebug gate left unpatched on firmware 0x%x\n", fw);
  }
}

static int
patch_ps4_candebug_gate_pair(unsigned long match, unsigned int fw) {
  static const unsigned char nops[2] = { 0x90, 0x90 };
  unsigned char caller[2];
  unsigned char target[2];

  if(kernel_copyout(match + 12, caller, sizeof(caller))
     || kernel_copyout(match + 42, target, sizeof(target))) {
    LOG_EPRINTF("Cannot read candebug gate at 0x%lx\n", match);
    return 0;
  }
  if(!memcmp(caller, nops, sizeof(nops))
     && !memcmp(target, nops, sizeof(nops))) {
    return 1;
  }
  if(caller[0] != 0x74 || target[0] != 0x74
     || 14 + (signed char)caller[1] != 44 + (signed char)target[1]) {
    LOG_EPRINTF("Unexpected candebug gate bytes on firmware 0x%x; skipped\n",
                fw);
    return 0;
  }
  if(patch_ps4_site(match + 12, caller, nops, sizeof(nops), "candebug-caller")
     || patch_ps4_site(match + 42, target, nops, sizeof(nops),
                       "candebug-target")) {
    LOG_EPRINTF("Candebug gate left unpatched on firmware 0x%x\n", fw);
    return 0;
  }
  return 1;
}

static void
patch_ps4_candebug_gate(unsigned int fw) {
  unsigned long match;

  errno = 0;
  match = find_unique_ps4_pattern(
      "e8????????bb0100000085c0????498b4708488b7840e8????????85c0740d498b7e40"
      "e8????????85c0????31db");
  if(match) {
    patch_ps4_candebug_gate_pair(match, fw);
    return;
  }

  errno = 0;
  match = find_unique_ps4_pattern(
      "e8????????85c0bb01000000????498b4708488b7840e8????????85c0740d498b7e40"
      "e8????????85c0????31db");
  if(match) {
    patch_ps4_candebug_gate_pair(match, fw);
    return;
  }

  patch_ps4_candebug_gate_monolithic(fw);
}

static int
patch_ps4_nop_site(const char *head, const char *site_before,
                   const char *site_after, const char *tail, size_t length,
                   const char *name) {
  static const unsigned char nops[8]
      = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
  const size_t offset = strlen(head) / 2;
  unsigned char current[8];
  char pattern[256];
  unsigned long match;

  if(length > sizeof(current)) {
    errno = EINVAL;
    return -1;
  }

  snprintf(pattern, sizeof(pattern), "%s%s%s", head, site_before, tail);
  match = kernel_find_pattern(KERNEL_ADDRESS_IMAGE_BASE,
                              ps4_kernel_text_size(), pattern);
  if(!match) {
    snprintf(pattern, sizeof(pattern), "%s%s%s", head, site_after, tail);
    if(kernel_find_pattern(KERNEL_ADDRESS_IMAGE_BASE, ps4_kernel_text_size(),
                           pattern)) {
      return 0;
    }
    LOG_EPRINTF("Ptrace AOB %s not found\n", name);
    errno = ENOENT;
    return -1;
  }
  if(kernel_copyout(match + offset, current, length)) {
    LOG_PERROR("kernel_copyout");
    errno = EIO;
    return -1;
  }
  return patch_ps4_site(match + offset, current, nops, length, name);
}

static int
patch_ps4_ptrace_core(unsigned int fw) {
  switch(fw & 0xffff0000) {
    case 0x1050000:
    case 0x1060000:
    case 0x1070000:
    case 0x1500000:
    case 0x1510000:
    case 0x1520000:
    case 0x1600000:
    case 0x1610000:
    case 0x1620000:
    case 0x1700000:
    case 0x1710000:
    case 0x1720000:
    case 0x1740000:
    case 0x1750000:
    case 0x1760000:
    case 0x2000000:
    case 0x2010000:
    case 0x2020000:
    case 0x2030000:
    case 0x2040000:
    case 0x2500000:
    case 0x2510000:
    case 0x2550000:
    case 0x2570000:
    case 0x3000000:
    case 0x3100000:
    case 0x3110000:
    case 0x3150000:
    case 0x3500000:
    case 0x3550000:
    case 0x3700000:
      return 0;
    case 0x4000000:
    case 0x4010000:
    case 0x4050000:
    case 0x4060000:
    case 0x4070000:
    case 0x4500000:
    case 0x4550000:
    case 0x4700000:
    case 0x4710000:
    case 0x4720000:
    case 0x4730000:
    case 0x4740000:
      return patch_ps4_nop_site("48b8361000007e020000"
                                "???????????????????????????????????????????"
                                "???????????????????????",
                                "0f84????????", "909090909090", "", 6,
                                "ptrace-core");
    case 0x5000000:
    case 0x5010000:
    case 0x5030000:
    case 0x5050000:
    case 0x5070000:
    case 0x5500000:
    case 0x5530000:
    case 0x5550000:
    case 0x5560000:
    case 0x6000000:
    case 0x6020000:
    case 0x6200000:
    case 0x6500000:
    case 0x6510000:
    case 0x6700000:
    case 0x6710000:
    case 0x6720000:
      return patch_ps4_nop_site("48b8361000007e020000"
                                "??????????????????????????",
                                "0f84????????", "909090909090", "", 6,
                                "ptrace-core");
    case 0x7000000:
    case 0x7010000:
    case 0x7020000:
    case 0x7500000:
    case 0x7510000:
    case 0x7550000:
    case 0x8000000:
    case 0x8010000:
    case 0x8020000:
    case 0x8030000:
    case 0x8500000:
    case 0x8520000:
    case 0x9000000:
    case 0x9030000:
    case 0x9040000:
    case 0x9500000:
    case 0x9510000:
    case 0x9600000:
    case 0x10000000:
    case 0x10010000:
    case 0x10500000:
    case 0x10700000:
    case 0x10710000:
    case 0x11000000:
    case 0x11020000:
    case 0x11500000:
    case 0x11520000:
    case 0x12000000:
    case 0x12020000:
    case 0x12500000:
    case 0x12520000:
    case 0x13000000:
    case 0x13020000:
    case 0x13040000:
    case 0x13500000:
    case 0x13520000:
    case 0x14000000:
    case 0x14020000:
      return patch_ps4_nop_site("48b8361000007e020000"
                                "????????????????????????",
                                "0f8419020000", "909090909090", "4c8b", 6,
                                "ptrace-core");
    default:
      LOG_EPRINTF("Unsupported firmware (0x%x)\n", fw);
      errno = ENOSYS;
      return -1;
  }
}

int
patch_ps4_ptrace(void) {
  const unsigned int fw = kernel_get_fw_version();

  if(ps4_ptrace_is_patched) {
    return 0;
  }

  if(patch_ps4_ptrace_core(fw) || patch_ps4_acmgr_debug_gate(fw)
     || patch_ps4_ptrace_allow_gate(fw) || patch_ps4_ptrace_policy_gate(fw)) {
    return -1;
  }
  patch_ps4_candebug_gate(fw);

  LOG_PUTS("Kernel ptrace patched");
  ps4_ptrace_is_patched = 1;
  return 0;
}

static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  static pthread_mutex_t sys_ptrace_lock = PTHREAD_MUTEX_INITIALIZER;
  const pid_t mypid = getpid();
  unsigned long authid;
  int ret = -1;
  int error = 0;

  pthread_mutex_lock(&sys_ptrace_lock);

  errno = 0;
  if((authid = kernel_get_ucred_authid(mypid))
     && !kernel_set_ucred_authid(mypid, 0x3800000000010003l)) {
    ret = ptrace(request, pid, addr, data);
    error = errno;

    if(kernel_set_ucred_authid(mypid, authid)) {
      ret = -1;
      error = errno;
    }
  } else {
    error = errno;
    if(!error) {
      error = EPERM;
    }
  }

  errno = error;
  pthread_mutex_unlock(&sys_ptrace_lock);

  return ret;
}

#endif

#ifdef __PROSPERO__

#define PT_DETACH_ADDR ((caddr_t)0)
#define PT_STEP_STOPPED(status) 1

static pthread_mutex_t sys_ptrace_lock = PTHREAD_MUTEX_INITIALIZER;

static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  pid_t mypid = getpid();
  uint64_t authid;
  int ret = -1;
  int error = 0;

  pthread_mutex_lock(&sys_ptrace_lock);

  errno = 0;
  if((authid = kernel_get_ucred_authid(mypid))
     && !kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    ret = (int)syscall(SYS_ptrace, request, pid, addr, data);
    error = errno;

    if(kernel_set_ucred_authid(mypid, authid)) {
      ret = -1;
      error = errno;
    }
  } else {
    error = errno;
    if(!error) {
      error = EPERM;
    }
  }

  errno = error;
  pthread_mutex_unlock(&sys_ptrace_lock);

  return ret;
}

#endif

static pid_t
pt_wait(pid_t pid, int *status, int options) {
  pid_t waited;

  do {
    waited = waitpid(pid, status, options);
  } while(waited < 0 && errno == EINTR && !(options & WNOHANG));

  return waited;
}

static int
pt_wait_stopped(pid_t pid, unsigned timeout_ms) {
  for(unsigned waited = 0; waited < timeout_ms; waited += 10) {
    int status = 0;
    pid_t result = pt_wait(pid, &status, WNOHANG);

    if(result == pid) {
      return WIFSTOPPED(status) ? WSTOPSIG(status) : -1;
    }
    if(result < 0 && errno != EINTR) {
      return -1;
    }

    usleep(10000);
  }

  return 0;
}

int
pt_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  for(int poll = 0; poll < 500; ++poll) {
    int status = 0;
    pid_t waited = pt_wait(pid, &status, WNOHANG);

    if(waited == pid && WIFSTOPPED(status)) {
      return 0;
    }
    if(!waited || (waited < 0 && errno == EINTR)) {
      usleep(10000);
      continue;
    }

    int error = waited < 0 ? errno : ESRCH;

    pt_detach(pid, 0);
    errno = error;

    return -1;
  }

  int detached = pt_detach(pid, 0);

  LOG_EPRINTF("Attach timeout: pid=%d detach=%d errno=%d\n", pid, detached,
              detached ? errno : 0);
  errno = ETIMEDOUT;

  return -1;
}

int
pt_detach(pid_t pid, int sig) {
  if(sys_ptrace(PT_DETACH, pid, PT_DETACH_ADDR, sig) != -1) {
    return 0;
  }

  int error = errno;

  for(int poll = 0; poll < 20; ++poll) {
    int status = 0;
    pid_t waited = pt_wait(pid, &status, WNOHANG);

    if(waited == pid && WIFSTOPPED(status)
       && sys_ptrace(PT_DETACH, pid, PT_DETACH_ADDR, sig) != -1) {
      return 0;
    }
    if(waited) {
      break;
    }

    usleep(10000);
  }

  errno = error;

  return -1;
}

int
pt_step(pid_t pid) {
  if(sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  int status = 0;

  if(pt_wait(pid, &status, 0) != pid || !PT_STEP_STOPPED(status)) {
    return -1;
  }

  return 0;
}

int
pt_continue(pid_t pid, int sig) {
  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, sig) == -1) {
    return -1;
  }

  return 0;
}

int
pt_follow_fork(pid_t pid) {
  if(sys_ptrace(PT_FOLLOW_FORK, pid, NULL, 1) == -1) {
    return -1;
  }

#ifdef PT_LWP_EVENTS
  if(sys_ptrace(PT_LWP_EVENTS, pid, NULL, 1) == -1) {
    return -1;
  }
#endif

  return 0;
}

int
pt_follow_exec(pid_t pid) {
#ifdef PT_LWP_EVENTS
  if(sys_ptrace(PT_LWP_EVENTS, pid, NULL, 1) == -1) {
    return -1;
  }
#else
  (void)pid;
#endif

  return 0;
}

static int
pt_await_flag(pid_t pid, int flag, struct ptrace_lwpinfo *lwpinfo,
              const char *what) {
  int status;
  int sig;

  memset(lwpinfo, 0, sizeof(*lwpinfo));
  while(!(lwpinfo->pl_flags & flag)) {
    if(waitpid(pid, &status, 0) == -1) {
      return -1;
    }

    if(!WIFSTOPPED(status)) {
      LOG_PRINTF("[Ptrace] pid %d is gone while waiting for %s\n", pid, what);
      errno = ESRCH;
      return -1;
    }

    if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)lwpinfo, sizeof(*lwpinfo))
       == -1) {
      return -1;
    }

    if(!(lwpinfo->pl_flags & flag)) {
      sig = WSTOPSIG(status);
      LOG_PRINTF("[Ptrace] pid %d stopped by signal %d (flags 0x%x) while "
                 "waiting for %s, resuming\n",
                 pid, sig, lwpinfo->pl_flags, what);
      if(sig == SIGTRAP || sig == SIGSTOP || sig == SIGCONT) {
        sig = 0;
      }
      if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, sig) == -1) {
        return -1;
      }
    }
  }

  return 0;
}

pid_t
pt_await_child(pid_t pid) {
  struct ptrace_lwpinfo lwpinfo;

  LOG_PRINTF("[Ptrace] waiting for pid %d to fork\n", pid);
  if(pt_await_flag(pid, PL_FLAG_FORKED, &lwpinfo, "fork")) {
    return -1;
  }

  LOG_PRINTF("[Ptrace] pid %d forked pid %d, waiting for it to stop\n", pid,
             lwpinfo.pl_child_pid);
  if(waitpid(lwpinfo.pl_child_pid, NULL, 0) == -1) {
    return -1;
  }

  return lwpinfo.pl_child_pid;
}

int
pt_await_exec(pid_t pid) {
  struct ptrace_lwpinfo lwpinfo;

  LOG_PRINTF("[Ptrace] waiting for pid %d to exec\n", pid);

  return pt_await_flag(pid, PL_FLAG_EXEC, &lwpinfo, "exec");
}

intptr_t
pt_getargv(pid_t pid) {
  const uint64_t args[6] = { 0 };
  intptr_t faddr = pt_resolve(pid, "FJmglmTMdr4");
  intptr_t result = 0;

  if(!faddr || pt_call(pid, faddr, args, &result)) {
    return 0;
  }

  return result;
}

int
pt_signal(pid_t pid, int signum, intptr_t handler) {
  const uint64_t args[6] = { signum, handler };
  intptr_t faddr = pt_resolve(pid, "VADc3MNQ3cM");
  intptr_t result = 0;

  if(!faddr || pt_call(pid, faddr, args, &result)) {
    return -1;
  }

  return (int)result;
}

void
pt_perror(pid_t pid, const char *s) {
  fprintf(stderr, "%s: %s\n", s, strerror(pt_errno(pid)));
}

static int pt_make_writable(pid_t pid, intptr_t addr);

int
pt_breakat(pid_t pid, intptr_t brkpoint) {
  uint8_t int3 = 0xcc;
  uint8_t original;
  int stopped;
  int error;

  if(pt_make_writable(pid, brkpoint)) {
    return -1;
  }
  if(pt_copyout(pid, brkpoint, &original, sizeof(original))) {
    return -1;
  }
  if(pt_copyin(pid, &int3, brkpoint, sizeof(int3))) {
    return -1;
  }

  int sig = SIGCONT;

  for(;;) {
    if(pt_continue(pid, sig)) {
      goto fail;
    }

    stopped = pt_wait_stopped(pid, 30000);

    if(stopped == 0) {
      LOG_EPUTS("Breakpoint not reached; requesting stop before "
                "removing it");
      kill(pid, SIGSTOP);

      if(!pt_wait_stopped(pid, 2000)) {
        errno = ETIMEDOUT;
        return -1;
      }

      errno = ETIMEDOUT;
      goto fail;
    }
    if(stopped < 0) {
      errno = ESRCH;
      goto fail;
    }
    if(stopped == SIGTRAP) {
      break;
    }

    sig = stopped;
  }

  return pt_copyin(pid, &original, brkpoint, sizeof(original)) ? -1 : 0;

fail:
  error = errno;
  pt_copyin(pid, &original, brkpoint, sizeof(original));
  errno = error;

  return -1;
}

int
pt_getregs(pid_t pid, struct reg *r) {
  return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

int
pt_setregs(pid_t pid, const struct reg *r) {
#ifdef __ORBIS__
  struct reg now;
  struct reg next = *r;

  if(!sys_ptrace(PT_GETREGS, pid, (caddr_t)&now, 0)) {
    next.r_rflags
        = (next.r_rflags & ~0x10000ULL) | (now.r_rflags & 0x10000ULL);
  }
  return sys_ptrace(PT_SETREGS, pid, (caddr_t)&next, 0);
#else
  return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
#endif
}

static int
pt_io(pid_t pid, int op, intptr_t addr, void *buf, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = op, .piod_offs = (void *)addr, .piod_addr = buf, .piod_len = len
  };

  if(sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0) == -1) {
    return -1;
  }
  if(iod.piod_len != len) {
    errno = EIO;
    return -1;
  }

  return 0;
}

int
pt_copyin(pid_t pid, const void *buf, intptr_t addr, size_t len) {
  return pt_io(pid, PIOD_WRITE_D, addr, (void *)buf, len);
}

int
pt_copyout(pid_t pid, intptr_t addr, void *buf, size_t len) {
  return pt_io(pid, PIOD_READ_D, addr, buf, len);
}

static int
pt_session(pid_t pid, int op, intptr_t addr, void *buf, size_t len) {
  if(pt_attach(pid)) {
    return -1;
  }

  int result = pt_io(pid, op, addr, buf, len);
  int error = errno;

  if(pt_detach(pid, 0)) {
    return -1;
  }

  errno = error;

  return result;
}

int
pt_read_memory(pid_t pid, intptr_t addr, void *buf, size_t len) {
  return pt_session(pid, PIOD_READ_D, addr, buf, len);
}

int
pt_write_memory(pid_t pid, const void *buf, intptr_t addr, size_t len) {
  return pt_session(pid, PIOD_WRITE_D, addr, (void *)buf, len);
}

int
pt_getint(pid_t pid, intptr_t addr) {
  return sys_ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}

int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return sys_ptrace(PT_WRITE_D, pid, (caddr_t)addr, val);
}

int
pt_setchar(pid_t pid, intptr_t addr, char val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

int
pt_setshort(pid_t pid, intptr_t addr, short val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

char
pt_getchar(pid_t pid, intptr_t addr) {
  char val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

short
pt_getshort(pid_t pid, intptr_t addr) {
  short val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

long
pt_getlong(pid_t pid, intptr_t addr) {
  long val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

static long
pt_syscall3(pid_t pid, int sysno, uint64_t a1, uint64_t a2, uint64_t a3) {
  return pt_syscall(pid, sysno, a1, a2, a3, 0ULL, 0ULL, 0ULL);
}

intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd,
        off_t off) {
  return pt_syscall(pid, SYS_mmap, (uint64_t)addr, (uint64_t)len,
                    (uint64_t)prot, (uint64_t)flags, (uint64_t)(int64_t)fd,
                    (uint64_t)off);
}

int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return (int)pt_syscall3(pid, SYS_mprotect, addr, len, (uint64_t)prot);
}

int
pt_msync(pid_t pid, intptr_t addr, size_t len, int flags) {
  return (int)pt_syscall3(pid, SYS_msync, addr, len, (uint64_t)flags);
}

int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return (int)pt_syscall3(pid, SYS_munmap, addr, len, 0);
}

int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall3(pid, SYS_close, (uint64_t)fd, 0, 0);
}

int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall3(pid, SYS_dup2, (uint64_t)oldfd, (uint64_t)newfd, 0);
}

int
pt_rdup(pid_t pid, pid_t other_pid, int fd) {
  return (int)pt_syscall3(pid, 0x25b, (uint64_t)other_pid, (uint64_t)fd, 0);
}

int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall3(pid, SYS_socket, (uint64_t)domain, (uint64_t)type,
                          (uint64_t)protocol);
}

int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
              uint32_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, (uint64_t)fd, (uint64_t)level,
                         (uint64_t)optname, (uint64_t)optval, (uint64_t)optlen,
                         0ULL);
}

int
pt_bind(pid_t pid, int sockfd, intptr_t addr, uint32_t addrlen) {
  return (int)pt_syscall3(pid, SYS_bind, (uint64_t)sockfd, (uint64_t)addr,
                          (uint64_t)addrlen);
}

ssize_t
pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags) {
  return (ssize_t)pt_syscall3(pid, SYS_recvmsg, (uint64_t)fd, (uint64_t)msg,
                              (uint64_t)flags);
}

int
pt_dynlib_get_proc_param(pid_t pid, intptr_t param_ptr, intptr_t size_ptr) {
  return (int)pt_syscall3(pid, 0x256, param_ptr, size_ptr, 0);
}

int
pt_dynlib_process_needed_and_relocate(pid_t pid) {
  return (int)pt_syscall3(pid, 0x257, 0, 0, 0);
}

static int
pt_is_nid(const char *text) {
  size_t length = 0;

  for(; text[length]; ++length) {
    char c = text[length];

    if(!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
         || (c >= '0' && c <= '9') || c == '+' || c == '-')) {
      return 0;
    }
  }

  return length == 11;
}

static intptr_t
pt_dlfind(pid_t pid, const char *name,
          intptr_t (*find)(pid_t, uint32_t, const char *)) {
  static const char *const modules[]
      = { "libkernel.sprx", "libkernel_sys.sprx", "libkernel_web.sprx",
          "libSceLibcInternal.sprx" };

  for(size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) {
    uint32_t handle;

    if(kernel_dynlib_handle(pid, modules[i], &handle)) {
      continue;
    }

    intptr_t address = find(pid, handle, name);

    if(address > 0) {
      return address;
    }
  }

  return 0;
}

static intptr_t
pt_dlsym(pid_t pid, const char *symbol) {
  return pt_dlfind(pid, symbol, kernel_dynlib_dlsym);
}

#ifdef __ORBIS__

static int
pt_make_writable(pid_t pid, intptr_t addr) {
  (void)pid;
  (void)addr;

  return 0;
}

struct ps4_fpregs {
  unsigned char legacy[512];
  unsigned char xstate_header[64];
  unsigned char ymm_upper[256];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct ps4_fpregs) == 832, "PS4 FPU register ABI");

static intptr_t
pt_syscall_address(pid_t pid, unsigned number) {
  unsigned handle = 0;
  dynlib_obj_t module;
  uint8_t expected[12]
      = { 0x48, 0xc7, 0xc0, 0, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05 };
  uint8_t block[4096];

  if((kernel_dynlib_handle(pid, "libkernel_sys.sprx", &handle)
      && kernel_dynlib_handle(pid, "libkernel.sprx", &handle)
      && kernel_dynlib_handle(pid, "libkernel_web.sprx", &handle))
     || kernel_dynlib_obj(pid, handle, &module)) {
    return 0;
  }
  if(!module.textsize || module.textsize > 16 * 1024 * 1024) {
    errno = ENOEXEC;
    return 0;
  }

  memcpy(expected + 3, &number, sizeof(number));

  for(size_t off = 0; off < module.textsize;
      off += sizeof(block) - sizeof(expected)) {
    size_t length = module.textsize - off;

    if(length > sizeof(block)) {
      length = sizeof(block);
    }
    if(pt_copyout(pid, module.mapbase + off, block, length)) {
      return 0;
    }

    for(size_t i = 0; i + sizeof(expected) <= length; ++i) {
      if(!memcmp(block + i, expected, sizeof(expected))) {
        return module.mapbase + off + i + 10;
      }
    }
  }

  errno = ENOSYS;

  return 0;
}

long
pt_syscall(pid_t pid, int sysno, ...) {
#ifdef __ORBIS__
  const pid_t tid = pid;
#else
  struct ptrace_lwpinfo origin = { 0 };
  pid_t tid;
#endif
  struct reg sysc_reg;
  struct reg bak_reg;
  va_list ap;

#ifndef __ORBIS__
  if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&origin, sizeof(origin))
     || origin.pl_lwpid <= 0) {
    return -1;
  }
  tid = origin.pl_lwpid;
#endif

  intptr_t syscall_ip = pt_syscall_address(pid, sysno);
#ifdef __ORBIS__
  if(!syscall_ip && pid != getpid()) {
    syscall_ip = pt_syscall_address(getpid(), sysno);
  }
#endif

  if(!syscall_ip) {
    LOG_PERROR("resolve syscall stub");
    return -1;
  }

  if(pt_getregs(tid, &bak_reg)) {
    LOG_PERROR("syscall: PT_GETREGS before execution");
    return -1;
  }

  memcpy(&sysc_reg, &bak_reg, sizeof(sysc_reg));
  sysc_reg.r_rax = sysno;
  sysc_reg.r_rip = syscall_ip;

  va_start(ap, sysno);
  sysc_reg.r_rdi = va_arg(ap, uint64_t);
  sysc_reg.r_rsi = va_arg(ap, uint64_t);
  sysc_reg.r_rdx = va_arg(ap, uint64_t);
  sysc_reg.r_r10 = va_arg(ap, uint64_t);
  sysc_reg.r_r8 = va_arg(ap, uint64_t);
  sysc_reg.r_r9 = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(tid, &sysc_reg)) {
    LOG_PERROR("syscall: PT_SETREGS before execution");
    return -1;
  }

  int failed = -1;

  for(int attempt = 0; attempt < 16; ++attempt) {
    if(sys_ptrace(PT_STEP, tid, (caddr_t)1, 0)) {
      break;
    }

    int status = 0;

    if(pt_wait(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
      errno = EPROTO;
      break;
    }

#ifdef __ORBIS__
    const int event_lwpid = (int)tid;
    if(pt_getregs(tid, &sysc_reg)) {
      break;
    }
#else
    struct ptrace_lwpinfo event = { 0 };
    if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&event, sizeof(event))
       || pt_getregs(tid, &sysc_reg)) {
      break;
    }
    const int event_lwpid = (int)event.pl_lwpid;
#endif

    int sig = WSTOPSIG(status);

    if((sig == SIGTRAP || sig == SIGSTOP)
       && (uint64_t)sysc_reg.r_rip == (uint64_t)syscall_ip + 2) {
      failed = 0;
      break;
    }

    LOG_EPRINTF("syscall=%d stop=%#x event LWP=%d original=%d "
                "RIP=%#lx expected=%#lx\n",
                sysno, status, event_lwpid, (int)tid,
                (unsigned long)sysc_reg.r_rip,
                (unsigned long)((uint64_t)syscall_ip + 2));

    if(sig != SIGSTOP || (uint64_t)sysc_reg.r_rip != (uint64_t)syscall_ip) {
      errno = EPROTO;
      break;
    }

    errno = EAGAIN;
  }

  if(failed) {
    LOG_PERROR("syscall: PT_STEP/wait");
  } else {
    failed = pt_getregs(tid, &sysc_reg);

    if(failed) {
      LOG_PERROR("syscall: PT_GETREGS after execution");
    }
  }

  int saved_error = failed ? errno : 0;

  if(pt_setregs(tid, &bak_reg)) {

    int restore_error = errno;
    struct reg now;
    int restored = 0;

    if(!pt_getregs(tid, &now)) {
      const uint64_t user_flags = 0x254dd5;
      struct reg merged = bak_reg;

      LOG_EPRINTF("Restore refused (errno=%d): saved rflags=%#lx "
                  "cs=%#lx ss=%#lx, now rflags=%#lx cs=%#lx ss=%#lx\n",
                  restore_error, (unsigned long)bak_reg.r_rflags,
                  (unsigned long)bak_reg.r_cs, (unsigned long)bak_reg.r_ss,
                  (unsigned long)now.r_rflags, (unsigned long)now.r_cs,
                  (unsigned long)now.r_ss);

      merged.r_rflags
          = (bak_reg.r_rflags & user_flags) | (now.r_rflags & ~user_flags);
      merged.r_cs = now.r_cs;
      merged.r_ss = now.r_ss;
      restored = !pt_setregs(tid, &merged);

      LOG_EPRINTF("Restore with the thread's own protected bits %s\n",
                  restored ? "succeeded" : "was refused as well");
    }
    if(!restored) {
      errno = restore_error;
      LOG_PERROR("syscall: restore registers");

      if(!saved_error) {
        saved_error = errno;
      }
      failed = -1;
    }
  }
  if(failed) {
    errno = saved_error;
    return -1;
  }
  if(sysc_reg.r_rflags & 1) {
    errno = (int)sysc_reg.r_rax;
    return -1;
  }

  return sysc_reg.r_rax;
}

static int
pt_call_on(pid_t pid, intptr_t function, intptr_t scratch, size_t scratch_size,
           const uint64_t args[6], intptr_t *result, int *retain) {
  struct ptrace_lwpinfo origin = { 0 };
  struct ps4_fpregs fp = { 0 };
  struct reg saved, call;
  uint8_t trap = 0xcc;
  int failed = 1, stopped = 1;

  if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&origin, sizeof(origin))
     || origin.pl_lwpid <= 0) {
    LOG_PERROR("call: cannot identify stopped LWP");
    return -1;
  }

  pid_t tid = origin.pl_lwpid;

  if(pt_getregs(tid, &saved)
     || sys_ptrace(PT_GETFPREGS, tid, (caddr_t)&fp, 0)) {
    LOG_PERROR("call: save LWP registers");
    return -1;
  }

  call = saved;

  intptr_t stack = ((scratch + scratch_size) & ~(intptr_t)15) - 8;

  if(pt_copyin(pid, &trap, scratch, 1)
     || pt_copyin(pid, &scratch, stack, sizeof(scratch))) {
    return -1;
  }

  call.r_rip = function;
  call.r_rsp = stack;
  call.r_rdi = args[0];
  call.r_rsi = args[1];
  call.r_rdx = args[2];
  call.r_rcx = args[3];
  call.r_r8 = args[4];
  call.r_r9 = args[5];
  call.r_rax = 0;
  call.r_rflags &= ~0x100ULL;

  if(pt_setregs(tid, &call)) {
    return -1;
  }
  if(pt_continue(pid, 0)) {
    goto restore;
  }

  stopped = 0;

  for(int i = 0; i < 1000; ++i) {
    int status = 0;
    pid_t waited = waitpid(pid, &status, WNOHANG);

    if(!waited || (waited < 0 && errno == EINTR)) {
      usleep(10000);
      continue;
    }
    if(waited != pid || !WIFSTOPPED(status)) {
      break;
    }

    stopped = 1;

    struct ptrace_lwpinfo event = { 0 };

    if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&event, sizeof(event))) {
      break;
    }

    if(pt_getregs(tid, &call)) {
      break;
    }

    if((uint64_t)call.r_rip == (uint64_t)scratch + 1) {
      if(result) {
        *result = call.r_rax;
      }
      failed = 0;
      break;
    }
    if(WSTOPSIG(status) == SIGSTOP) {

      if(pt_continue(pid, 0)) {
        break;
      }

      stopped = 0;
      continue;
    }

    LOG_EPRINTF("Call did not return: pid=%d signal=%d RIP=%#lx "
                "RSP=%#lx return=%#lx\n",
                pid, WSTOPSIG(status), (unsigned long)call.r_rip,
                (unsigned long)call.r_rsp, (unsigned long)(scratch + 1));
    break;
  }

  if(!stopped) {
    LOG_EPUTS("Remote call incomplete; requesting stop before LWP "
              "restoration");
    kill(pid, SIGSTOP);

    for(int i = 0; i < 200; ++i) {
      int status = 0;
      pid_t waited = waitpid(pid, &status, WNOHANG);

      if(waited == pid) {
        stopped = WIFSTOPPED(status);
        break;
      }
      if(waited < 0 && errno != EINTR) {
        break;
      }

      usleep(10000);
    }
  }
  if(!stopped) {
    *retain = 1;
    errno = ETIMEDOUT;
    return -1;
  }

restore:
  if(sys_ptrace(PT_SETFPREGS, tid, (caddr_t)&fp, 0)) {
    LOG_PERROR("call: restore FP registers");
    failed = 1;
  }
  if(pt_setregs(tid, &saved)) {
    LOG_PERROR("call: restore registers");
    failed = 1;
  }

  return failed ? -1 : 0;
}

intptr_t
pt_resolve(pid_t pid, const char *symbol) {
  intptr_t address;

  if(pt_is_nid(symbol)
     && (address = pt_dlfind(pid, symbol, kernel_dynlib_resolve))) {
    return address;
  }

  return pt_dlsym(pid, symbol);
}

int
pt_call(pid_t pid, intptr_t function, const uint64_t args[6],
        intptr_t *result) {
  const unsigned char zero = 0;
  int retain = 0;
  intptr_t scratch
      = pt_mmap(pid, 0, PT_SCRATCH_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if(scratch <= 0) {
    return -1;
  }

  for(size_t off = 0; off < PT_SCRATCH_SIZE; off += 0x1000) {
    if(pt_copyin(pid, &zero, scratch + off, 1)) {
      int error = errno;

      pt_munmap(pid, scratch, PT_SCRATCH_SIZE);
      errno = error;

      return -1;
    }
  }

  int status = pt_call_on(pid, function, scratch, PT_SCRATCH_SIZE, args,
                          result, &retain);

  if(!retain) {
    int error = errno;

    pt_munmap(pid, scratch, PT_SCRATCH_SIZE);
    errno = error;
  }

  return status;
}

int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t function = pt_resolve(pid, "pipe");
  const uint64_t args[6] = { (uint64_t)pipefd };
  intptr_t result = -1;

  if(!function || pt_call(pid, function, args, &result)) {
    return -1;
  }

  return (int)result;
}

int
pt_errno(pid_t pid) {
  intptr_t function = pt_resolve(pid, "__error");
  const uint64_t args[6] = { 0 };
  intptr_t address = 0;

  if(!function || pt_call(pid, function, args, &address) || !address) {
    return -1;
  }

  return pt_getint(pid, address);
}

intptr_t
pt_sceKernelGetProcParam(pid_t pid) {
  intptr_t function = pt_resolve(pid, "sceKernelGetProcParam");
  const uint64_t args[6] = { 0 };
  intptr_t param = 0;

  if(!function || pt_call(pid, function, args, &param)) {
    return 0;
  }

  return param;
}

#endif

#ifdef __PROSPERO__

static int
pt_make_writable(pid_t pid, intptr_t addr) {
  return kernel_mprotect(pid, addr, PAGE_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC);
}

static intptr_t
resolve_nid(pid_t pid, const char *nid) {
  intptr_t addr;

  if((addr = kernel_dynlib_resolve(pid, 0x1, nid))) {
    return addr;
  }

  return kernel_dynlib_resolve(pid, 0x2001, nid);
}

intptr_t
pt_resolve(pid_t pid, const char *symbol) {
  char nid[12] = { 0 };
  intptr_t addr;

  if(pt_is_nid(symbol) && (addr = resolve_nid(pid, symbol))) {
    return addr;
  }

  nid_encode(symbol, nid);

  if((addr = resolve_nid(pid, nid))) {
    return addr;
  }

  return pt_dlsym(pid, symbol);
}

static void
pt_arguments(struct reg *r, int kernel_abi, va_list ap) {
  r->r_rdi = va_arg(ap, uint64_t);
  r->r_rsi = va_arg(ap, uint64_t);
  r->r_rdx = va_arg(ap, uint64_t);

  if(kernel_abi) {
    r->r_r10 = va_arg(ap, uint64_t);
  } else {
    r->r_rcx = va_arg(ap, uint64_t);
  }

  r->r_r8 = va_arg(ap, uint64_t);
  r->r_r9 = va_arg(ap, uint64_t);
}

static long
pt_run_stepped(pid_t pid, const struct reg *bak_reg, struct reg *jmp_reg) {
  if(pt_setregs(pid, jmp_reg)) {
    return -1;
  }

  while(jmp_reg->r_rsp <= bak_reg->r_rsp) {
    if(pt_step(pid) || pt_getregs(pid, jmp_reg)) {
      pt_setregs(pid, bak_reg);
      return -1;
    }
  }

  if(pt_setregs(pid, bak_reg)) {
    return -1;
  }

  return jmp_reg->r_rax;
}

long
pt_syscall(pid_t pid, int sysno, ...) {
  intptr_t addr = resolve_nid(pid, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(!addr) {
    return -1;
  }
  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr + 0xa;
  jmp_reg.r_rax = sysno;

  va_start(ap, sysno);
  pt_arguments(&jmp_reg, 1, ap);
  va_end(ap);

  return pt_run_stepped(pid, &bak_reg, &jmp_reg);
}

static long
pt_call_single_step(pid_t pid, intptr_t addr, ...) {
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;

  va_start(ap, addr);
  pt_arguments(&jmp_reg, 0, ap);
  va_end(ap);

  return pt_run_stepped(pid, &bak_reg, &jmp_reg);
}

int
pt_call(pid_t pid, intptr_t function, const uint64_t args[6],
        intptr_t *result) {
  struct reg bak, cur;
  intptr_t tramp = 0;
  uint8_t int3 = 0xCC;
  int stopped, error;

  if(pt_getregs(pid, &bak)) {
    return -1;
  }

  tramp = pt_mmap(pid, 0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if(tramp <= 0) {
    goto fail;
  }
  if(pt_copyin(pid, &int3, tramp, 1)) {
    goto fail;
  }

  cur = bak;
  cur.r_rip = function;

  cur.r_rdi = args[0];
  cur.r_rsi = args[1];
  cur.r_rdx = args[2];
  cur.r_rcx = args[3];
  cur.r_r8 = args[4];
  cur.r_r9 = args[5];

  cur.r_rsp = ((bak.r_rsp - 128) & ~(register_t)15) - 8;

  if(pt_copyin(pid, &tramp, cur.r_rsp, sizeof(tramp))) {
    goto fail;
  }
  if(pt_setregs(pid, &cur)) {
    goto fail;
  }
  if(pt_continue(pid, SIGCONT)) {
    goto fail;
  }

  stopped = pt_wait_stopped(pid, 10000);

  if(!stopped) {
    LOG_EPUTS("Remote call incomplete; requesting stop before "
              "restoring the registers");
    kill(pid, SIGSTOP);

    if(!pt_wait_stopped(pid, 2000)) {
      errno = ETIMEDOUT;
      return -1;
    }

    errno = ETIMEDOUT;
    goto fail;
  }
  if(stopped < 0 || pt_getregs(pid, &cur)) {
    goto fail;
  }

  if(result) {
    *result = cur.r_rax;
  }

  error = 0;
  if(pt_setregs(pid, &bak)) {
    error = errno;
  }
  pt_munmap(pid, tramp, 0x1000);

  if(error) {
    errno = error;
    return -1;
  }

  return 0;

fail:
  error = errno;

  if(tramp > 0) {
    pt_munmap(pid, tramp, 0x1000);
  }

  pt_setregs(pid, &bak);
  errno = error;

  return -1;
}

int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = resolve_nid(pid, "-Jp7F+pXxNg");

  return (int)pt_call_single_step(pid, faddr, pipefd);
}

int
pt_errno(pid_t pid) {
  intptr_t faddr = resolve_nid(pid, "9BcDykPmo1I");
  intptr_t addr = pt_call_single_step(pid, faddr);

  return pt_getint(pid, addr);
}

intptr_t
pt_sceKernelGetProcParam(pid_t pid) {
  intptr_t faddr = resolve_nid(pid, "959qrazPIrg");
  intptr_t param = pt_call_single_step(pid, faddr);

  return param == -1 ? 0 : param;
}

#endif
