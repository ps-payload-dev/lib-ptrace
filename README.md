# lib-ptrace

`lib-ptrace` is a static library for using `ptrace(2)` from PS4 and PS5
payloads. It provides process control, memory access, remote syscalls and
function calls, and symbol lookup through one shared API.

It is based on the `pt_*` helpers of [John Törnblom](https://github.com/john-tornblom)'s
[PS4 elfldr project][ps4-upstream] and [PS5 elfldr project][ps5-upstream], and
builds with the unified [payload SDK][sdk]. The Makefile creates one archive per console:

| Console | Archive |
| --- | --- |
| PS4 | `build/ps4/libptrace.a` |
| PS5 | `build/ps5/libptrace.a` |

## Building

Install the [payload SDK][sdk] for the console you want to build on a
Debian-based POSIX system. Set the matching SDK path, replacing `#` with `4` or
`5`:

```console
export PS#_PAYLOAD_SDK=/opt/ps-payload-sdk/ps#
```

Build one console:

```console
make PLATFORM=ps4
make PLATFORM=ps5
```

Objects go under `build/<console>/objects`, and archives go under
`build/<console>`. Use `make PLATFORM=<console> clean` to remove the build
directory and `make PLATFORM=<console> format` to format the sources. Set `OPT` to change optimization
flags (for example, `OPT=-Oz`) or set `DEBUG=1` to include debug symbols.

The GitHub Actions workflow builds both consoles using the [payload SDK][sdk]
and uploads separate `libptrace-ps4` and `libptrace-ps5` artifacts.

## Install

`make PLATFORM=<console> install` installs the library for that console. The
default destination follows the SDK toolchain. Set `DESTDIR` to stage files elsewhere or `PREFIX`
to change the install prefix:

```console
make PLATFORM=ps5 install DESTDIR=/path/to/stage
```

The install includes `ptrace.h` and `libptrace.a`. Link with
`-lptrace -lkernel_sys`.

To install next to the SDK's own headers and libraries, use an empty prefix:

```console
make PLATFORM=ps5 install PREFIX=
```

## Use

```c
#include <ptrace.h>

int read_u64(pid_t pid, intptr_t address, uint64_t *value) {
  if (pt_attach(pid))
    return -1;

  int result = pt_copyout(pid, address, value, sizeof(*value));
  pt_detach(pid, 0);
  return result;
}
```

Functions return `0` on success and `-1` with `errno` set unless noted. A
process must be attached and stopped before calls that access its registers or
memory. `pt_read_memory` and `pt_write_memory` attach and detach automatically.
The same API is available on both consoles; the library handles kernel
differences internally.

## API

| Functions | Purpose |
| --- | --- |
| `pt_attach`, `pt_detach` | Stop a process (waiting up to about five seconds) or detach and resume it |
| `pt_step`, `pt_continue` | Single-step or resume a stopped process |
| `pt_breakat` | Resume until an address is reached, restore its original byte, and stop there |
| `pt_getregs`, `pt_setregs` | Read or write the stopped thread's registers |
| `pt_copyin`, `pt_copyout` | Write to or read from process memory |
| `pt_read_memory`, `pt_write_memory` | Copy memory while attaching and detaching automatically |
| `pt_getchar`, `pt_getshort`, `pt_getint`, `pt_getlong`, `pt_setchar`, `pt_setshort`, `pt_setint`, `pt_setlong` | Typed memory access |
| `pt_syscall` | Run a syscall inside the target process |
| `pt_mmap`, `pt_mprotect`, `pt_msync`, `pt_munmap` | Memory syscalls inside the target |
| `pt_close`, `pt_dup2`, `pt_rdup` | File descriptor syscalls inside the target |
| `pt_socket`, `pt_setsockopt`, `pt_bind`, `pt_recvmsg` | Socket syscalls inside the target |
| `pt_dynlib_get_proc_param`, `pt_dynlib_process_needed_and_relocate` | Dynamic linker syscalls inside the target |
| `pt_resolve` | Find an exported libkernel function by name or NID; returns `0` if not found |
| `pt_call` | Call a function on the stopped thread with up to six integer arguments and read `rax` |
| `pt_pipe`, `pt_errno`, `pt_sceKernelGetProcParam` | Helpers that call into the target's libkernel |
| `patch_ps4_ptrace` | PS4 only: patch the kernel's ptrace checks (firmware 3.50 to 14.02) so payloads can attach to other processes |

Example: resolve `getpid` and call it in the target process:

```c
intptr_t function = pt_resolve(pid, "getpid");
const uint64_t args[6] = {0};
intptr_t result;

if (function && !pt_call(pid, function, args, &result))
  printf("target pid is %ld\n", (long)result);
```

## Notes

- Payloads on both consoles need permission to use `ptrace`. On PS5, the
  library temporarily raises and restores the caller's authority ID; a lock
  serializes requests across threads. On PS4, call `patch_ps4_ptrace()` once
  before attaching; it fails with `ENOSYS` on unsupported firmware, is safe to
  call repeatedly, and recognizes sites that are already patched.
- `pt_call` restores the thread's registers and waits about ten seconds. On
  PS4, it maps a scratch region for the call; a timed-out call may leave that
  region allocated because the function could still be using it.
- `pt_resolve` accepts symbol names or eleven-character NIDs. NID-like strings
  are tried as NIDs first, then as names. On PS5, names are converted to NIDs
  before lookup.
- `pt_breakat` waits about thirty seconds. It restores the original byte on
  success or failure; it returns `ESRCH` if the process exits and `ETIMEDOUT`
  if the address is not reached. PS5 pages must be made writable through the
  kernel first.
- If a call fails partway through, the library restores the thread's
  registers where possible. Check return values and detach from the process.

## Credits

Based on [John Törnblom](https://github.com/john-tornblom)'s `pt_*` helpers;
his copyright notice remains in the source files. The PS4 backend also uses
the FPU register layout from ps4debug-NG and a remote-call return-address check
from NexusFramework.

## Reporting Bugs

If you encounter problems with lib-ptrace, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of
code, please file an issue before you start to work on your changes. This will
allow us to discuss the solution properly before you commit time and effort.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

[sdk]: https://github.com/ps-payload-dev/sdk
[ps4-upstream]: https://github.com/ps4-payload-dev/elfldr
[ps5-upstream]: https://github.com/ps5-payload-dev/elfldr
[issues]: https://github.com/ps-payload-dev/lib-ptrace/issues/new
