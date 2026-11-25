/*
 * AMD SVM VMCB setup and VM-exit loop for the SvmLab guest.
 * The literal byte offsets below are AMD VMCB offsets; see
 * ../docs/VMCB_OFFSETS.md for names, sizes, and the state-area 0x400 base.
 * Only scalar register/VMCB operations run in the mode-5 VM-exit loop.
 */
#include <ntifs.h>
#include <intrin.h>
#include "svm_probe_ioctl.h"

extern VOID SvmSnapshot(PVOID snapshot);
extern VOID SvmEnter(ULONGLONG vmcb_pa);
extern VOID SvmSaveHost(ULONGLONG host_vmcb_pa);
extern VOID SvmEnterLoaded(ULONGLONG guest_vmcb_pa, ULONGLONG host_vmcb_pa,
                           SVM_GPRS *gprs, PVOID host_stack_top, PVOID fx_state,
                           ULONG hold_gif);
extern VOID SvmEnableGlobalInterrupts(VOID);
extern ULONGLONG SvmForwardHypercall(SVM_GPRS *gprs, PVOID fx_state,
                                     ULONGLONG hypercall_rip);
extern VOID SvmGuestStub(VOID);
extern VOID SvmSyscallStub(VOID);
extern VOID SvmGuestKernelDelay(VOID);
extern VOID SvmGuestKernelWindow(VOID);
extern VOID SvmGuestKernelWindowTrap(VOID);
extern VOID SvmSyscallForward(VOID);
extern VOID SvmSyscallForwardTrap(VOID);
extern VOID SvmSyscallReturn(VOID);
volatile LONG g_SvmStopFlag = 0;
static volatile LONG g_SvmStopAllowed = 0;

NTSTATUS SvmRequestStop(VOID)
{
    if (InterlockedCompareExchange(&g_SvmStopAllowed, 0, 0) == 0)
        return STATUS_INVALID_DEVICE_STATE;
    InterlockedExchange(&g_SvmStopFlag, 1);
    return STATUS_SUCCESS;
}
static SVM_DIAG g_svm_diag;

VOID SvmGetDiag(SVM_DIAG *out)
{
    *out = g_svm_diag;
}

ULONGLONG g_OriginalLstar;

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_POINTER {
    USHORT Limit;
    ULONGLONG Base;
} DESCRIPTOR_POINTER;
typedef struct _HOST_SNAPSHOT {
    USHORT Cs, Ss, Ds, Es;
    DESCRIPTOR_POINTER Gdtr, Idtr;
    ULONGLONG Dr6, Dr7, Rsp, Rflags;
} HOST_SNAPSHOT;
typedef struct _SEGMENT {
    USHORT Selector;
    USHORT Attributes;
    ULONG Limit;
    ULONGLONG Base;
} SEGMENT;
#pragma pack(pop)

static VOID Put64(PUCHAR vmcb, ULONG offset, ULONGLONG value)
{
    /* byte offset into the 4 KiB VMCB; state fields start at +0x400 */
    RtlCopyMemory(vmcb + offset, &value, sizeof(value));
}

static VOID Put32(PUCHAR vmcb, ULONG offset, ULONG value)
{
    RtlCopyMemory(vmcb + offset, &value, sizeof(value));
}

static ULONGLONG Get64(PUCHAR vmcb, ULONG offset)
{
    ULONGLONG value;
    RtlCopyMemory(&value, vmcb + offset, sizeof(value));
    return value;
}

static NTSTATUS SegmentFromGdt(const HOST_SNAPSHOT *snap, USHORT selector, SEGMENT *seg)
{
    ULONGLONG descriptor;
    ULONG offset = selector & ~7u;
    RtlZeroMemory(seg, sizeof(*seg));
    seg->Selector = selector;
    if (selector == 0) return STATUS_SUCCESS;
    if ((selector & 4) || offset + 7 > snap->Gdtr.Limit) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&descriptor, (PVOID)(ULONG_PTR)(snap->Gdtr.Base + offset), 8);
    seg->Attributes = (USHORT)(((descriptor >> 40) & 0xff) | ((descriptor >> 44) & 0xf00));
    seg->Limit = (ULONG)((descriptor & 0xffff) | ((descriptor >> 32) & 0xf0000));
    seg->Base = ((descriptor >> 16) & 0xffffff) | ((descriptor >> 32) & 0xff000000);
    return STATUS_SUCCESS;
}

static NTSTATUS PutSegment(PUCHAR vmcb, ULONG offset, const HOST_SNAPSHOT *snap, USHORT selector)
{
    SEGMENT seg;
    NTSTATUS status = SegmentFromGdt(snap, selector, &seg);
    if (NT_SUCCESS(status)) RtlCopyMemory(vmcb + 0x400 + offset, &seg, sizeof(seg));
    return status;
}

static NTSTATUS HandleLabOpen(const SVM_RUN_INPUT *input, const SVM_GPRS *gprs,
                              ULONGLONG guest_rax, SVM_RUN_RESULT *out)
{
    static const UNICODE_STRING alias = RTL_CONSTANT_STRING(L"\\??\\C:\\SvmLab\\alias.txt");
    UNICODE_STRING real = RTL_CONSTANT_STRING(L"\\??\\C:\\SvmLab\\real.txt");
    OBJECT_ATTRIBUTES user_oa, real_oa;
    UNICODE_STRING user_name, local_name;
    IO_STATUS_BLOCK iosb = {0};
    WCHAR name[260];
    HANDLE handle = NULL;
    NTSTATUS status;

    out->ObservedService = (ULONG)guest_rax;
    if (out->ObservedService != input->ExpectedService ||
        out->GuestRip != out->TrapRip ||
        gprs->Rcx != input->ExpectedReturnRip ||
        gprs->R10 != input->OutHandlePointer ||
        gprs->R8 != input->ObjectAttributesPointer ||
        gprs->R9 != input->IoStatusPointer ||
        gprs->Rdx != (FILE_READ_DATA | SYNCHRONIZE))
        return STATUS_INVALID_PARAMETER;
    __try {
        ProbeForRead((PVOID)(ULONG_PTR)gprs->R8, sizeof(user_oa), 1);
        RtlCopyMemory(&user_oa, (PVOID)(ULONG_PTR)gprs->R8, sizeof(user_oa));
        if (!user_oa.ObjectName) return STATUS_INVALID_PARAMETER;
        ProbeForRead(user_oa.ObjectName, sizeof(user_name), 1);
        RtlCopyMemory(&user_name, user_oa.ObjectName, sizeof(user_name));
        if (!user_name.Buffer || user_name.Length == 0 ||
            (user_name.Length & 1) || user_name.Length > sizeof(name) - sizeof(WCHAR))
            return STATUS_INVALID_PARAMETER;
        ProbeForRead(user_name.Buffer, user_name.Length, 1);
        RtlCopyMemory(name, user_name.Buffer, user_name.Length);
        name[user_name.Length / sizeof(WCHAR)] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    local_name.Buffer = name;
    local_name.Length = user_name.Length;
    local_name.MaximumLength = sizeof(name);
    if (!RtlEqualUnicodeString(&local_name, &alias, TRUE))
        return STATUS_OBJECT_NAME_NOT_FOUND;

    InitializeObjectAttributes(&real_oa, &real, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenFile(&handle, FILE_READ_DATA | SYNCHRONIZE, &real_oa, &iosb,
                        FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    __try {
        ProbeForWrite((PVOID)(ULONG_PTR)input->OutHandlePointer, sizeof(HANDLE), 1);
        ProbeForWrite((PVOID)(ULONG_PTR)input->IoStatusPointer, sizeof(iosb), 1);
        RtlCopyMemory((PVOID)(ULONG_PTR)input->OutHandlePointer, &handle, sizeof(handle));
        RtlCopyMemory((PVOID)(ULONG_PTR)input->IoStatusPointer, &iosb, sizeof(iosb));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (handle) ZwClose(handle);
        return GetExceptionCode();
    }
    out->OpenedHandle = (ULONGLONG)(ULONG_PTR)handle;
    out->HostStatus = (ULONG)status;
    return status;
}

NTSTATUS SvmRunOne(const SVM_RUN_INPUT *input, SVM_RUN_RESULT *out)
{
    PHYSICAL_ADDRESS low = {0}, high, boundary = {0};
    PUCHAR vmcb = NULL, host_vmcb = NULL, hsave = NULL, iopm = NULL, msrpm = NULL;
    PUCHAR host_stack = NULL;
    PUCHAR guest_stack = NULL;
    PUCHAR fx_storage = NULL, fx_state = NULL;
    HOST_SNAPSHOT snap;
    SVM_GPRS gprs;
    ULONGLONG old_efer, old_hsave, efer;
    ULONGLONG vmcb_pa = 0, host_vmcb_pa = 0;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    int cpu[4];

    RtlZeroMemory(out, sizeof(*out));
    RtlZeroMemory(&gprs, sizeof(gprs));
    RtlZeroMemory(&g_svm_diag, sizeof(g_svm_diag));
    g_svm_diag.Mode = input->Mode;
    out->DesiredStatus = input->DesiredStatus;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    if (input->Mode > 5) return STATUS_INVALID_PARAMETER;
    if (input->Mode == 5 &&
        (input->DesiredStatus == 0 || input->DesiredStatus > 5000))
        return STATUS_INVALID_PARAMETER;
    if (input->Mode >= 1 && input->Mode <= 3 &&
        (!input->EntryRip || !input->StackPointer || !input->Cs || !input->Ss ||
         (input->Cs & 3) != 3 || (input->Ss & 3) != 3))
        return STATUS_INVALID_PARAMETER;
    __cpuid(cpu, 0x80000001);
    if ((cpu[2] & 4) == 0) return STATUS_NOT_SUPPORTED;
    if (__readmsr(0xC0010114) & 0x10) return STATUS_NOT_SUPPORTED;
    if (input->Mode == 5 && input->TargetProcessId && !input->ExpectedCr3)
        return STATUS_INVALID_PARAMETER;
    high.QuadPart = 0x7fffffffffffffffLL;
    vmcb = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, boundary, MmCached);
    if (input->Mode >= 2)
        host_vmcb = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, boundary, MmCached);
    if (input->Mode >= 2)
        host_stack = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'hMvS');
    if (input->Mode == 5)
        guest_stack = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'gMvS');
    if (input->Mode >= 2) {
        fx_storage = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x420, 'xMvS');
        if (fx_storage) {
            fx_state = (PUCHAR)(((ULONG_PTR)fx_storage + 15) & ~(ULONG_PTR)15);
            RtlZeroMemory(fx_state, 0x404);
        }
    }
    hsave = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, boundary, MmCached);
    iopm = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 3, low, high, boundary, MmCached);
    msrpm = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 2, low, high, boundary, MmCached);
    if (!vmcb || (input->Mode >= 2 && (!host_vmcb || !host_stack || !fx_state)) ||
        (input->Mode == 5 && !guest_stack) ||
        !hsave || !iopm || !msrpm) goto done;
    RtlZeroMemory(vmcb, PAGE_SIZE);
    if (host_vmcb) RtlZeroMemory(host_vmcb, PAGE_SIZE);
    if (guest_stack) RtlZeroMemory(guest_stack, 0x10000);
    RtlZeroMemory(hsave, PAGE_SIZE);
    RtlZeroMemory(iopm, PAGE_SIZE * 3);
    RtlZeroMemory(msrpm, PAGE_SIZE * 2);

    RtlZeroMemory(&snap, sizeof(snap));
    SvmSnapshot(&snap);
    status = PutSegment(vmcb, 0x00, &snap,
                        input->Mode >= 1 && input->Mode <= 3 ? input->Ss : snap.Es);
    if (!NT_SUCCESS(status)) goto done;
    status = PutSegment(vmcb, 0x10, &snap,
                        input->Mode >= 1 && input->Mode <= 3 ? input->Cs : snap.Cs);
    if (!NT_SUCCESS(status)) goto done;
    status = PutSegment(vmcb, 0x20, &snap,
                        input->Mode >= 1 && input->Mode <= 3 ? input->Ss : snap.Ss);
    if (!NT_SUCCESS(status)) goto done;
    status = PutSegment(vmcb, 0x30, &snap,
                        input->Mode >= 1 && input->Mode <= 3 ? input->Ss : snap.Ds);
    if (!NT_SUCCESS(status)) goto done;
    out->EntryRip = input->Mode == 5 ? (ULONGLONG)(ULONG_PTR)SvmGuestKernelWindow :
                    input->Mode == 4 ? (ULONGLONG)(ULONG_PTR)SvmGuestKernelDelay :
                    input->Mode ? input->EntryRip : (ULONGLONG)(ULONG_PTR)SvmGuestStub;
    if (input->Mode == 2 || input->Mode == 3)
        out->TrapRip = (ULONGLONG)(ULONG_PTR)SvmSyscallStub;
    RtlCopyMemory(&out->CsAttributes, vmcb + 0x400 + 0x10 + 2, sizeof(out->CsAttributes));
    if (input->Mode >= 1 && input->Mode <= 3) vmcb[0x400 + 0xCB] = 3;
    Put32(vmcb, 0x400 + 0x60 + 4, snap.Gdtr.Limit);
    Put64(vmcb, 0x400 + 0x60 + 8, snap.Gdtr.Base);
    Put32(vmcb, 0x400 + 0x80 + 4, snap.Idtr.Limit);
    Put64(vmcb, 0x400 + 0x80 + 8, snap.Idtr.Base);
    /* State-save area: EFER.SVME, CR4/CR3/CR0, DR7/DR6, RFLAGS/RIP.
     * The guest uses the current Windows address space and a private stack.
     */
    Put64(vmcb, 0x400 + 0xD0, __readmsr(0xC0000080) | 0x1000);
    Put64(vmcb, 0x400 + 0x148, __readcr4());
    Put64(vmcb, 0x400 + 0x150, __readcr3());
    Put64(vmcb, 0x400 + 0x158, __readcr0());
    Put64(vmcb, 0x400 + 0x160, 0x400);
    Put64(vmcb, 0x400 + 0x168, snap.Dr6);
    Put64(vmcb, 0x400 + 0x170, input->Mode >= 4 ? snap.Rflags : 2);
    Put64(vmcb, 0x400 + 0x178, out->EntryRip);
    if (guest_stack) {
        ULONGLONG top = ((ULONGLONG)(ULONG_PTR)guest_stack + 0x10000 - 0x100) & ~0xFULL;
        g_svm_diag.GuestStackBottom = (ULONGLONG)(ULONG_PTR)guest_stack;
        g_svm_diag.GuestStackTop = top;
        Put64(vmcb, 0x400 + 0x1D8, top);
    } else {
        Put64(vmcb, 0x400 + 0x1D8,
              input->Mode >= 1 && input->Mode <= 3 ? input->StackPointer : snap.Rsp);
    }
    Put64(vmcb, 0x400 + 0x1F8, 0);
    /* Control area +0x08: exception intercepts. Bit 3 catches #BP at the
     * LSTAR shim; bit 14 is only for explicit #PF diagnostics. Normal mode
     * leaves page faults to Windows because faults inside the host VM-exit
     * handler cannot be serviced safely.
     */
    Put32(vmcb, 0x08, input->Mode == 5 ? ((1u << 3) |
           ((input->Reserved & SVM_RUN_FLAG_NO_PF_INTERCEPT) ? 0 : (1u << 14))) :
           input->Mode == 4 ? (1u << 3) : 0xffffffffu);
    Put32(vmcb, 0x0C, input->Mode >= 4 ? 0 : 3);
    Put32(vmcb, 0x10, input->Mode == 4 ? 1 : 3);
    Put64(vmcb, 0x40, MmGetPhysicalAddress(iopm).QuadPart);
    Put64(vmcb, 0x48, MmGetPhysicalAddress(msrpm).QuadPart);
    Put64(vmcb, 0x58, 1 | (3ULL << 32)); /* ASID 1, flush guest TLB */

    old_hsave = __readmsr(0xC0010117);
    old_efer = __readmsr(0xC0000080);
    efer = old_efer | 0x1000;
    out->ProcessorBefore = KeGetCurrentProcessorNumber();
    if (input->Mode >= 4) {
        ULONGLONG start = __rdtsc();
        ULONGLONG ticks;
        KeStallExecutionProcessor(100);
        ticks = __rdtsc() - start;
        gprs.Rbx = ticks *
            (input->Mode == 5 ? (ULONGLONG)input->DesiredStatus * 10 : 100);
    }
    vmcb_pa = MmGetPhysicalAddress(vmcb).QuadPart;
    if (host_vmcb) host_vmcb_pa = MmGetPhysicalAddress(host_vmcb).QuadPart;
    __writemsr(0xC0010117, MmGetPhysicalAddress(hsave).QuadPart);
    __writemsr(0xC0000080, efer);
    if (input->Mode >= 2) {
        SvmSaveHost(host_vmcb_pa);
        RtlCopyMemory(vmcb + 0x400 + 0x40, host_vmcb + 0x400 + 0x40, 0x20);
        RtlCopyMemory(vmcb + 0x400 + 0x70, host_vmcb + 0x400 + 0x70, 0x10);
        RtlCopyMemory(vmcb + 0x400 + 0x90, host_vmcb + 0x400 + 0x90, 0x10);
        RtlCopyMemory(vmcb + 0x400 + 0x200, host_vmcb + 0x400 + 0x200, 0x40);
        if (input->Mode == 2 || input->Mode == 3)
            Put64(vmcb, 0x400 + 0x208, out->TrapRip);
        if (input->Mode == 5) {
            g_OriginalLstar = Get64(host_vmcb, 0x400 + 0x208);
            g_svm_diag.OriginalLstar = g_OriginalLstar;
            out->TrapRip = (ULONGLONG)(ULONG_PTR)SvmSyscallForwardTrap;
            if (input->Reserved & SVM_RUN_FLAG_LSTAR)
                Put64(vmcb, 0x400 + 0x208, (ULONGLONG)(ULONG_PTR)SvmSyscallForward);
        }
        if (input->Mode == 3) {
            gprs.Rcx = input->OutHandlePointer;
            gprs.Rdx = FILE_READ_DATA | SYNCHRONIZE;
            gprs.R8 = input->ObjectAttributesPointer;
            gprs.R9 = input->IoStatusPointer;
        }
        if (input->Mode == 5) {
            InterlockedExchange(&g_SvmStopFlag, 0);
            InterlockedExchange(&g_SvmStopAllowed,
                (input->Reserved & SVM_RUN_FLAG_ALLOW_STOP) ? 1 : 0);
        }
        g_svm_diag.State = 2;
        g_svm_diag.Cpu = KeGetCurrentProcessorNumber();
        KeMemoryBarrier();
        SvmEnterLoaded(vmcb_pa, host_vmcb_pa, &gprs,
                       host_stack + 0x8000, fx_state, input->Mode == 5);
        g_svm_diag.State = 3;
        g_svm_diag.ExitCount++;
        g_svm_diag.ExitCode = Get64(vmcb, 0x70);
        g_svm_diag.Rip = Get64(vmcb, 0x400 + 0x178);
        g_svm_diag.Nrip = Get64(vmcb, 0xC8);
        g_svm_diag.GuestRcx = gprs.Rcx;
        g_svm_diag.GuestR11 = gprs.R11;
        g_svm_diag.ExitInfo1 = Get64(vmcb, 0x78);
        g_svm_diag.ExitInfo2 = Get64(vmcb, 0x80);
        g_svm_diag.Cpl = vmcb[0x400 + 0xCB];
        KeMemoryBarrier();
    } else {
        SvmEnter(MmGetPhysicalAddress(vmcb).QuadPart);
    }
    out->ExitCode = Get64(vmcb, 0x70);
    out->ExitInfo1 = Get64(vmcb, 0x78);
    out->ExitInfo2 = Get64(vmcb, 0x80);
    out->GuestRip = Get64(vmcb, 0x400 + 0x178);
    out->GuestRcx = gprs.Rcx;
    out->GuestR11 = gprs.R11;
    if (input->Mode == 5) {
        ULONG exits;
        for (exits = 0; exits < 10000; ++exits) {
            ULONGLONG code = Get64(vmcb, 0x70);
            ULONGLONG rip = Get64(vmcb, 0x400 + 0x178);
            if (code == 0x43 && rip == (ULONGLONG)(ULONG_PTR)SvmGuestKernelWindowTrap)
                break;
            Put64(vmcb, 0xA8, 0);
            if (code == 0x43 && rip == (ULONGLONG)(ULONG_PTR)SvmSyscallForwardTrap &&
                Get64(vmcb, 0xC8) != 0) {
                ULONGLONG resume_rip = Get64(vmcb, 0xC8);
                out->WindowSyscalls++;
                if (input->TargetProcessId &&
                    (ULONG)Get64(vmcb, 0x400 + 0x1F8) == input->ExpectedService &&
                    Get64(vmcb, 0x400 + 0x150) == input->ExpectedCr3) {
                    out->ProcessCr3Hits++;
                    if (out->OpenTraceCount < SVM_OPEN_TRACE_MAX) {
                        SVM_OPEN_TRACE *trace = &out->OpenTrace[out->OpenTraceCount++];
                        trace->Tsc = __rdtsc();
                        trace->Cr3 = Get64(vmcb, 0x400 + 0x150);
                        trace->ReturnRip = gprs.Rcx;
                        trace->OutHandlePointer = gprs.R10;
                        trace->DesiredAccess = gprs.Rdx;
                        trace->ObjectAttributesPointer = gprs.R8;
                        trace->IoStatusPointer = gprs.R9;
                    } else {
                        out->OpenTraceDropped++;
                    }
                    if ((input->Reserved & SVM_RUN_FLAG_NULL_OBJECT_ATTRIBUTES) &&
                        out->WindowRewrites == 0 &&
                        out->ProcessCr3Hits == input->Reserved2 && gprs.R8 != 0) {
                        gprs.R8 = 0;
                        out->WindowRewrites++;
                        out->RewriteCr3 = Get64(vmcb, 0x400 + 0x150);
                    }
                    /* At LSTAR, SYSCALL has saved the user return RIP in RCX
                     * and flags in R11. Set VMCB.RAX and resume at our
                     * SYSRETQ shim, bypassing the Windows service handler
                     * for exactly this matched call. No guest pointer read.
                     */
                    if ((input->Reserved & SVM_RUN_FLAG_OVERRIDE_OPEN_STATUS) &&
                        out->WindowStatusOverrides == 0 &&
                        out->ProcessCr3Hits == input->Reserved2) {
                        Put64(vmcb, 0x400 + 0x1F8,
                              (ULONGLONG)(LONG)input->OverrideStatus);
                        resume_rip = (ULONGLONG)(ULONG_PTR)SvmSyscallReturn;
                        out->WindowStatusOverrides++;
                        out->AppliedStatus = input->OverrideStatus;
                        out->RewriteCr3 = Get64(vmcb, 0x400 + 0x150);
                    }
                }
                if (input->ReplacementObjectAttributesPointer &&
                    (ULONG)Get64(vmcb, 0x400 + 0x1F8) == input->ExpectedService &&
                    gprs.R10 == input->OutHandlePointer &&
                    gprs.R8 == input->ObjectAttributesPointer &&
                    gprs.R9 == input->IoStatusPointer &&
                    gprs.Rcx == input->ExpectedReturnRip) {
                    gprs.R8 = input->ReplacementObjectAttributesPointer;
                    out->WindowRewrites++;
                    out->RewriteCr3 = Get64(vmcb, 0x400 + 0x150);
                }
                Put64(vmcb, 0x400 + 0x178, resume_rip);
            } else if (code == 0x81 && Get64(vmcb, 0xC8) != 0) {
                ULONGLONG result = SvmForwardHypercall(&gprs, fx_state, rip);
                out->WindowHypercalls++;
                Put64(vmcb, 0x400 + 0x1F8, result);
                Put64(vmcb, 0x400 + 0x178, Get64(vmcb, 0xC8));
            } else if (code == 0x4E) {
                ULONGLONG fault = Get64(vmcb, 0x80);
                if (g_svm_diag.FaultCount == 0) {
                    g_svm_diag.FirstFaultRip = rip;
                    g_svm_diag.FirstFaultAddress = fault;
                    g_svm_diag.FirstFaultError = Get64(vmcb, 0x78);
                    g_svm_diag.FirstFaultRsp = Get64(vmcb, 0x400 + 0x1D8);
                    g_svm_diag.FirstFaultCr3 = Get64(vmcb, 0x400 + 0x150);
                    if (input->Reserved & SVM_RUN_FLAG_STOP_ON_FIRST_PF) {
                        SvmEnableGlobalInterrupts();
                        KeBugCheckEx(0xE2, 0xF1, (ULONG_PTR)rip,
                                     (ULONG_PTR)fault,
                                     (ULONG_PTR)g_svm_diag.FirstFaultRsp);
                    }
                }
                g_svm_diag.FaultCount++;
                if ((fault & ~0xfffULL) ==
                    ((ULONGLONG)(ULONG_PTR)SvmSyscallForward & ~0xfffULL)) {
                    g_svm_diag.LstarFallback++;
                    Put64(vmcb, 0x400 + 0x208, g_OriginalLstar);
                    if (vmcb[0x400 + 0xCB] == 0)
                        Put64(vmcb, 0x400 + 0x178, g_OriginalLstar);
                } else {
                    Put64(vmcb, 0x400 + 0x240, fault);
                    Put64(vmcb, 0xA8, (1ULL << 31) | (1ULL << 11) |
                          (3ULL << 8) | 14ULL | (Get64(vmcb, 0x78) << 32));
                }
            } else {
                out->WindowUnexpected++;
                SvmEnableGlobalInterrupts();
                KeBugCheckEx(0xE2, (ULONG_PTR)code, (ULONG_PTR)rip,
                             (ULONG_PTR)Get64(vmcb, 0xC8), 0);
            }
            g_svm_diag.State = 4;
            KeMemoryBarrier();
            SvmEnterLoaded(vmcb_pa, host_vmcb_pa, &gprs,
                           host_stack + 0x8000, fx_state, 1);
            g_svm_diag.State = 3;
            g_svm_diag.ExitCount++;
            g_svm_diag.ExitCode = Get64(vmcb, 0x70);
            g_svm_diag.Rip = Get64(vmcb, 0x400 + 0x178);
            g_svm_diag.Nrip = Get64(vmcb, 0xC8);
            g_svm_diag.GuestRcx = gprs.Rcx;
            g_svm_diag.GuestR11 = gprs.R11;
            g_svm_diag.ExitInfo1 = Get64(vmcb, 0x78);
            g_svm_diag.ExitInfo2 = Get64(vmcb, 0x80);
            g_svm_diag.Cpl = vmcb[0x400 + 0xCB];
            KeMemoryBarrier();
        }
        if (exits == 10000)
            KeBugCheckEx(0xE2, 10000, (ULONG_PTR)Get64(vmcb, 0x70),
                         (ULONG_PTR)g_svm_diag.FirstFaultRip,
                         (ULONG_PTR)g_svm_diag.FirstFaultAddress);
        SvmEnableGlobalInterrupts();
        out->WindowStoppedBySignal =
            (ULONG)InterlockedCompareExchange(&g_SvmStopFlag, 0, 0);
        InterlockedExchange(&g_SvmStopAllowed, 0);
        out->ExitCode = Get64(vmcb, 0x70);
        out->GuestRip = Get64(vmcb, 0x400 + 0x178);
    }
    if (!input->Mode && out->ExitCode == 0x81 && Get64(vmcb, 0xC8) != 0) {
        out->ResumeRip = Get64(vmcb, 0xC8);
        Put64(vmcb, 0x400 + 0x178, out->ResumeRip);
        Put64(vmcb, 0x400 + 0x1F8, input->DesiredStatus);
        SvmEnter(MmGetPhysicalAddress(vmcb).QuadPart);
        out->SecondExitCode = Get64(vmcb, 0x70);
        out->SecondGuestRip = Get64(vmcb, 0x400 + 0x178);
        out->ReturnedRax = Get64(vmcb, 0x400 + 0x1F8);
    }
    if ((input->Mode == 2 || input->Mode == 3) &&
        out->ExitCode == 0x81 && Get64(vmcb, 0xC8) != 0) {
        ULONG return_status = input->DesiredStatus;
        if (input->Mode == 3) {
            return_status = (ULONG)HandleLabOpen(input, &gprs,
                                                  Get64(vmcb, 0x400 + 0x1F8), out);
        }
        out->ResumeRip = Get64(vmcb, 0xC8);
        Put64(vmcb, 0x400 + 0x178, out->ResumeRip);
        Put64(vmcb, 0x400 + 0x1F8, return_status);
        SvmEnterLoaded(vmcb_pa, host_vmcb_pa, &gprs,
                       host_stack + 0x8000, fx_state, 0);
        out->SecondExitCode = Get64(vmcb, 0x70);
        out->SecondGuestRip = Get64(vmcb, 0x400 + 0x178);
        out->ReturnedRax = Get64(vmcb, 0x400 + 0x1F8);
    }
    __writemsr(0xC0000080, old_efer);
    __writemsr(0xC0010117, old_hsave);
    out->ProcessorAfter = KeGetCurrentProcessorNumber();
    g_svm_diag.State = 5;
    KeMemoryBarrier();
    status = STATUS_SUCCESS;
done:
    if (input->Mode == 5) InterlockedExchange(&g_SvmStopAllowed, 0);
    if (msrpm) MmFreeContiguousMemory(msrpm);
    if (iopm) MmFreeContiguousMemory(iopm);
    if (hsave) MmFreeContiguousMemory(hsave);
    if (host_vmcb) MmFreeContiguousMemory(host_vmcb);
    if (host_stack) ExFreePoolWithTag(host_stack, 'hMvS');
    if (guest_stack) ExFreePoolWithTag(guest_stack, 'gMvS');
    if (fx_storage) ExFreePoolWithTag(fx_storage, 'xMvS');
    if (vmcb) MmFreeContiguousMemory(vmcb);
    return status;
}
