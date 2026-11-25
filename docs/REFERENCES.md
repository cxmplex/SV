# Primary references

- AMD, [AMD64 Architecture Programmer's Manual Volume 2: System Programming, revision 3.44](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2), Chapter 15: SVM, VMCB layout, VMRUN, VMLOAD/VMSAVE, CLGI/STGI, and VM exits.
- Microsoft, [x64 ABI conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions): register use at the Windows x64 call boundary. The guest `ntdll` stub and AMD instruction semantics, rather than this ABI page alone, establish the SYSCALL/SYSRET register path used here.
- Microsoft, [KeStackAttachProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-kestackattachprocess): process attachment requirements and caution. SV attaches only in the pre-run CR3 query, outside the VM-exit loop.
- Microsoft, [PsLookupProcessByProcessId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid): obtains the referenced process object for that query.

`0x33` is an observation from the tested guest's `ntdll!NtOpenFile` bytes, not a published cross-version syscall number.
