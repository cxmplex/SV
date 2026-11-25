# SV: AMD SVM syscall interception

SV is a small AMD SVM monitor and Windows test harness. It runs **inside a disposable Hyper-V guest** with nested SVM. The `driver/` directory is the kernel and assembly implementation; `lab/` contains the controller and file-open test programs.

The controller launches an unchanged `ntopen_probe.exe` on CPU 0 and obtains its CR3 before starting a bounded monitor window. On this guest build, the current `ntdll!NtOpenFile` stub encodes service `0x33`. The monitor matches that service, the process CR3, and the selected call index. In `ntopen_status` mode it sets guest `RAX` to `0xC0000022` (`STATUS_ACCESS_DENIED`) at LSTAR and resumes through a `SYSRETQ` shim. Windows' normal service handler is skipped for that **one** call.

## Layout

| Path | Purpose |
| --- | --- |
| `driver/svm_probe.c` | WDM device, IOCTL dispatch, and pre-run process CR3 query. |
| `driver/svm_run.c` | VMCB setup, VM-exit loop, entry capture, and one-call policy. |
| `driver/svm_enter.asm` | VMRUN entry/exit, register and FPU handling, LSTAR trap, SYSRETQ return. |
| `driver/svm_probe_ioctl.h` | Shared control ABI and bounded capture records. |
| `lab/` | Controller, worker, and unchanged file-open test app. |
| `docs/` | VMCB offset map and primary references. |

## Build and run in the lab

`build.cmd` uses Visual Studio x64 tools and Windows SDK/WDK 10.0.28000.0, writing unsigned artifacts to `out/`. Adjust the SDK version in the script if necessary. Sign `out/svm_probe.sys` with a test certificate trusted by the disposable guest; no key or certificate is included here. The guest must already have nested SVM and the driver test-signing environment configured.

Copy the signed driver and the four `out/*.exe` programs to `C:\SvmLab` in the guest. Load the driver as the demand-start `SvmProbe` service. From an elevated guest shell:

```text
C:\SvmLab\svmctl.exe ntopen_capture
C:\SvmLab\svmctl.exe ntopen_status 2
```
