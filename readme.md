# Kernel Extended Attributes (EA) — Research and Proof of Concept

A WDM driver plus a user-mode console application that together demonstrate, on Windows 10, how NTFS Extended Attributes behave across the boundary between user mode and kernel mode. The POC focuses on the `$Kernel.` and `$KERNEL.PURGE.` namespaces, on the difference between `ZwSetEaFile` and `FsRtlSetKernelEaFile`, on the `NtSetEaFile` upsert / explicit-delete semantics, and on the purge-on-write behavior of `$KERNEL.PURGE.` EAs.

The repository contains:

- A kernel driver (`EaDemo.sys`) exposing the control device `\Device\EaDemo` and six IOCTLs: set, get, delete, delete-all-kernel, set-via-`ZwSetEaFile` (negative test), and raw `FsRtlSetKernelEaFile` pass-through (mixed-buffer verification).
- A user-mode console application (`EaDemoApp.exe`) that computes MD5 / SHA256, writes them as user or kernel EAs, queries and deletes EAs, and runs a fixed, narrated end-to-end demonstration covering every documented finding.
- A shared header (`ea_ioctl.h`) that defines the IOCTL contract and is safe to include from both kernel and user mode. It uses a private `EA_FILE_FULL_EA_INFORMATION` with the same layout as the OS structure so the caller does not have to drag in `ntddk.h` or `winternl.h` just to compile it.
- A kernel-side allocator and RAII header (`kernel_alloc.h`) providing `Memory::Allocate` / `Memory::Free` with a modern / legacy pool allocation split, plus `KernelFile` and `KernelFileObject` wrappers.

---

## 1. Background: NTFS Extended Attributes

### 1.1 What EAs are

Extended Attributes are `Name = Value` entries attached to an NTFS file's MFT record, independent of the file's `$DATA` stream and independent of Alternate Data Streams (ADS). Each EA has:

- A **name** of up to 255 bytes of ANSI text (the null terminator is not counted in the length field).
- A **value** of up to 65,535 bytes (16-bit `EaValueLength`).

EAs are stored in the NTFS `$EA_INFORMATION` and `$EA` attributes. Small EA sets are resident in the MFT record; larger sets are non-resident. EAs are ordinary file metadata, so they are **persistent across reboots**, **preserved across renames and moves within a volume**, and **lost when the file is deleted**.

The on-wire layout is a singly linked list of `FILE_FULL_EA_INFORMATION` structures:

```c
typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG  NextEntryOffset;    // 0 = last entry; otherwise offset to next
    UCHAR  Flags;              // FILE_NEED_EA = 0x80; 0 for caching EAs
    UCHAR  EaNameLength;       // name length excluding null terminator
    USHORT EaValueLength;      // value length in bytes
    CHAR   EaName[1];          // null-terminated name; value follows
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
```

The value begins at `EaName + EaNameLength + 1`. The size of an entry is `FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + EaNameLength + 1 + EaValueLength`, and `NextEntryOffset` for each non-last entry **must be 4-byte aligned**. NTFS rejects unaligned offsets with `STATUS_EA_LIST_INCONSISTENT`.

### 1.2 User EAs vs Kernel EAs

Windows distinguishes two families of EAs by name prefix:

| Family | Name prefix | Who may write | Purpose |
| --- | --- | --- | --- |
| User EA | any name not starting with `$Kernel.` | user mode and kernel mode | general-purpose application metadata |
| Kernel EA | `$Kernel.` | kernel mode only, and only via `FsRtlSetKernelEaFile` | kernel-managed metadata that user mode must not be able to forge |
| Kernel purge EA | `$KERNEL.PURGE.` | same as kernel EA | kernel-managed cache data that is dropped automatically when the file content changes |

Microsoft documents mixed user + kernel buffers as supported since Windows 10 1803:

> "Starting with Windows 10, version 1803, user EAs and kernel EAs can be intermixed."
>
> Source: `https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes`

### 1.3 The `$Kernel.` namespace

Names beginning with `$Kernel.` form a namespace that user mode cannot write. The protection is enforced at the NTFS layer and depends on two conditions, both of which must be true:

1. `Irp->RequestorMode == KernelMode`.
2. The IRP carries `MinorFunction = IRP_MN_KERNEL_CALL`.

`ZwSetEaFile` sets the first but not the second. As a direct consequence, a kernel-mode call through `ZwSetEaFile` with a `$Kernel.` name returns `STATUS_SUCCESS` and does nothing. The only supported way to write a kernel EA is `FsRtlSetKernelEaFile`, which builds the IRP with `IRP_MN_KERNEL_CALL` set.

### 1.4 The `$KERNEL.PURGE.` namespace

Names beginning with `$KERNEL.PURGE.` behave like other kernel EAs, with one extra property: when the file's `$DATA` stream is modified (write, truncation, memory-mapped dirty write), NTFS removes every `$KERNEL.PURGE.` EA. Metadata-only changes (timestamps, renames, ACL changes) do not trigger the purge.

This is the mechanism System Informer uses to cache file hashes (`$KERNEL.PURGE.SI.MD5`, `$KERNEL.PURGE.SI.SHA256`, and so on) without any separate invalidation protocol: the cache is discarded the moment the file content changes.

---

## 2. The APIs

### 2.1 User mode

| Function | Behavior |
| --- | --- |
| `NtQueryEaFile` | Reads both user and kernel EAs. Requires `FILE_READ_EA` on the handle. |
| `NtSetEaFile` | Applies an EA chain with upsert semantics (see §2.4). Entries with `EaValueLength = 0` are deleted; entries with non-zero value are set or updated; entries omitted from the submitted buffer are preserved. |

### 2.2 Kernel mode — the `Zw` variants (do not work for kernel EAs)

| Function | Behavior |
| --- | --- |
| `ZwQueryEaFile` | Reads both user and kernel EAs. |
| `ZwSetEaFile` | Behaves like `NtSetEaFile` for user EAs. For `$Kernel.` entries it returns `STATUS_SUCCESS` and does nothing (missing `IRP_MN_KERNEL_CALL`). |

### 2.3 Kernel mode — the correct API for kernel EAs: `FsRtlSetKernelEaFile`

```c
NTSTATUS FsRtlSetKernelEaFile(
    _In_ PFILE_OBJECT FileObject,
    _In_reads_bytes_(BufferSize) PVOID EaBuffer,
    _In_ ULONG BufferSize);
```

Declared in `<ntifs.h>`. Semantics:

- **Merge.** Only entries present in the submitted buffer are touched. Existing kernel EAs not mentioned in the buffer are left unchanged.
- **Delete = set with `EaValueLength == 0`.**
- **Mixed buffers are accepted since Windows 10 1803.** The call may include both user EAs and `$Kernel.` EAs in one buffer; the kernel entries are applied with kernel-EA protection, the user entries with normal EA rules.
- **Takes a `PFILE_OBJECT`, not a `HANDLE`.**
- **Does not emit `USN_REASON_EA_CHANGE`.** USN sees only user EA changes.

### 2.4 `NtSetEaFile` — upsert plus explicit-delete

`NtSetEaFile` is often described as "replace the user EA set", but the observable semantics on Windows 10 build 19041 are:

| Input entry | Effect on the named EA |
| --- | --- |
| Present, non-empty value | Set / update |
| Present, `EaValueLength = 0` | **Delete** |
| Not present in buffer | **Preserved** (upsert) |

The buffer as a whole is not a "replace" instruction. The only way to delete a user EA through `NtSetEaFile` is to include that EA in the buffer with `EaValueLength = 0`. Omitting it does not delete it. An entirely empty buffer (length 0) is rejected with `STATUS_EA_LIST_INCONSISTENT` (`0x80000014`).

This is the same convention `FsRtlSetKernelEaFile` uses for kernel EAs. It is worth stating explicitly because the "replace" wording in the documentation leads to incorrect code.

---

## 3. Architecture

### 3.1 Components

```
+---------------------+        +-----------------------+
|   EaDemoApp.exe     |        |      EaDemo.sys       |
|   (user mode)       |        |      (kernel mode)    |
|                     |        |                       |
|  NtSetEaFile   ---------------> (user EAs only)      |
|  NtQueryEaFile ---------------> (reads user and     |
|                                 kernel EAs)          |
|                     |        |                       |
|  NtDeviceIoControlFile ------> IoControl dispatch    |
|   IOCTL_EA_SET      |        |  -> FsRtlSetKernelEaFile
|   IOCTL_EA_GET      |        |  -> ZwQueryEaFile    |
|   IOCTL_EA_DELETE   |        |  -> FsRtlSetKernelEaFile (valueLen = 0)
|   IOCTL_EA_DELETE_ALL_KERNEL |  -> FsRtlSetKernelEaFile (one per existing kernel EA)
|   IOCTL_EA_SET_VIA_ZW |       |  -> ZwSetEaFile (negative test)
|   IOCTL_EA_RAW_FSRTL  |       |  -> FsRtlSetKernelEaFile (raw mixed buffer)
+---------------------+        +-----------------------+
```

### 3.2 IOCTL contract

Defined in `ea_ioctl.h`. All IOCTLs use `METHOD_BUFFERED`. Access rights are enforced by the driver via `IoValidateDeviceIoControlAccess`.

| IOCTL | Function code | Access | Input buffer | Output |
| --- | --- | --- | --- | --- |
| `IOCTL_EA_SET` | `0x800` | `FILE_WRITE_ACCESS` | `EA_IOCTL_SET_INPUT` + WCHAR path + ANSI name + value | none |
| `IOCTL_EA_GET` | `0x801` | `FILE_READ_ACCESS` | `EA_IOCTL_NAME_INPUT` + WCHAR path + ANSI name | `EA_IOCTL_GET_OUTPUT` + value |
| `IOCTL_EA_DELETE` | `0x802` | `FILE_WRITE_ACCESS` | `EA_IOCTL_NAME_INPUT` + WCHAR path + ANSI name | none |
| `IOCTL_EA_DELETE_ALL_KERNEL` | `0x803` | `FILE_WRITE_ACCESS` | `EA_IOCTL_PATH_INPUT` + WCHAR path | none |
| `IOCTL_EA_SET_VIA_ZW` | `0x804` | `FILE_WRITE_ACCESS` | same as `IOCTL_EA_SET` | none |
| `IOCTL_EA_RAW_FSRTL` | `0x805` | `FILE_WRITE_ACCESS` | `EA_IOCTL_RAW_INPUT` + WCHAR path + aligned raw EA buffer | none |

The device name is `\Device\EaDemo`, with the DOS-visible symlink `\??\EaDemo`. The application opens `\\.\EaDemo`.

### 3.3 Device security

The driver uses `IoCreateDeviceSecure` with an explicit SDDL:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

This allows only LocalSystem and Builtin\Administrators to open the device. Without this, `IoCreateSymbolicLink` alone would allow any authenticated user to call the IOCTLs. Additionally, `DispatchDeviceControl` calls `IoValidateDeviceIoControlAccess` for every IOCTL, so even a caller who can open the device cannot invoke a write IOCTL with a read-only handle.

### 3.4 Data flow for `IOCTL_EA_SET`

1. The application computes MD5 and SHA256 of the target file with BCrypt.
2. It marshals `EA_IOCTL_SET_INPUT` followed by the WCHAR path, the ANSI name, and the value bytes into one buffer.
3. `NtDeviceIoControlFile` sends the buffer to `EaDemo.sys`.
4. The driver validates lengths and alignment, opens the file with `ZwOpenFile` (requires `FILE_READ_EA | FILE_WRITE_EA`), and obtains the `PFILE_OBJECT` via `ObReferenceObjectByHandle`.
5. The driver builds a single-entry `FILE_FULL_EA_INFORMATION` with `NextEntryOffset = 0`, 4-byte padded, and calls `FsRtlSetKernelEaFile` with the unpadded entry size.
6. On success the EA is on the file. On failure the NTSTATUS is returned to the caller unchanged.
7. The driver closes the file object and the handle via `KernelFileObject` and `KernelFile`.

---

## 4. Building

Requirements:

- Visual Studio 2019 (v142 toolset).
- Windows 10 WDK, targeting Windows 10 (build 19041 or later).
- Test signing enabled on the target machine.

Project layout:

```
.
├── README.md
├── ea_ioctl.h
├── kernel_alloc.h
├── EaDemoDriver.cpp
├── EaDemoApp.cpp
├── EaDemo.inf          (kept for reference; not used for installation)
```

### 4.1 Driver project (`Driver.vcxproj`)

- Template: `Empty WDM Driver`.
- Platform: `x64`, configuration `Debug` and `Release`.
- Intermediate directory: `$(SolutionDir)build\obj\$(MSBuildProjectName)\$(PlatformShortName)\$(Configuration)\` (must not be shared with the App project).
- Output directory: `$(SolutionDir)build\bin\$(PlatformShortName)\$(Configuration)\`.
- Sources: `EaDemoDriver.cpp`, `ea_ioctl.h`, `kernel_alloc.h`.
- Additional dependency: `Ntoskrnl.lib`, `Wdmsec.lib`.

### 4.2 App project (`App.vcxproj`)

- Template: `Console App` (C++).
- Platform: `x64`, configuration `Debug` and `Release`.
- Intermediate directory: `$(SolutionDir)build\obj\$(MSBuildProjectName)\$(PlatformShortName)\$(Configuration)\`.
- Output directory: `$(SolutionDir)build\bin\$(PlatformShortName)\$(Configuration)\`.
- Sources: `EaDemoApp.cpp`, `ea_ioctl.h`.
- Additional dependency: `bcrypt.lib`.

---

## 5. Installing and Loading

The driver is a legacy WDM driver: it creates `\Device\EaDemo` in `DriverEntry` and does not implement `AddDevice` or `IRP_MJ_PNP`. It is installed and loaded as a legacy kernel service.

### 5.1 Install and start

```cmd
copy EaDemo.sys %SystemRoot%\System32\drivers\
sc create EaDemo type= kernel start= demand ^
    binPath= %SystemRoot%\System32\drivers\EaDemo.sys
sc start EaDemo
```

### 5.2 Verify

```cmd
sc query EaDemo
```

Expected: `STATE : 4 RUNNING`. The driver also creates the `\??\EaDemo` symlink, so `\\.\EaDemo` is openable by the application.

### 5.3 Stop and uninstall

```cmd
sc stop EaDemo
sc delete EaDemo
```

### 5.4 Removing stale artifacts after a rebuild

If you rebuild the driver while the service is running, stop it first:

```cmd
sc stop EaDemo
:: rebuild
sc start EaDemo
```

---

## 6. Running the Demonstration

Start `EaDemoApp.exe` as **Administrator** (the device SDDL in §3.3 allows only SYSTEM and Administrators). The main menu offers:

```
 1) Set EA on file
 2) Get EAs of file
 3) Clear EA of file
 4) Run full demonstration (all findings)
 5) USN tracking test (needs admin)
 6) Reboot persistence test
 7) Exit
```

### 6.1 Menu 1 — Set EA on file

The application asks for a file path, then for what to set:

- **(1) MD5 + SHA256 with prefix** — computes both hashes, then writes them as four EAs (two user, two kernel, or two purge kernel) depending on the answers to the follow-up prompts. The prefix defaults to `MVTest`, so the resulting names are `MVTest.MD5`, `MVTest.SHA256`, `$Kernel.MVTest.MD5`, `$Kernel.MVTest.SHA256`, `$KERNEL.PURGE.MVTest.MD5`, `$KERNEL.PURGE.MVTest.SHA256`.
- **(2) Custom name/value** — writes a single arbitrary EA. The name and value are read as text; the mode and purge prompts behave as above.

### 6.2 Menu 2 — Get EAs of file

Prints every EA on the file, tagged by family:

```
  [USER]         MVTest.MD5                      (16 bytes) = d47b127b...
  [KERNEL]       $Kernel.MVTest.MD5              (16 bytes) = d47b127b...
  [KERNEL-PURGE] $KERNEL.PURGE.MVTest.MD5        (16 bytes) = d47b127b...
```

Kernel and purge entries are read through `NtQueryEaFile`, which returns both user and kernel EAs to both modes.

### 6.3 Menu 3 — Clear EA of file

Lists the EAs, then lets you delete by name, `all-kernel`, or `all-user`.

- Deleting a `$Kernel.` or `$KERNEL.PURGE.` name goes through `IOCTL_EA_DELETE`, which calls `FsRtlSetKernelEaFile` with `EaValueLength = 0`.
- `all-kernel` goes through `IOCTL_EA_DELETE_ALL_KERNEL`, which calls `FsRtlSetKernelEaFile` once with every existing kernel EA set to `EaValueLength = 0`.
- Deleting a user EA goes through `NtSetEaFile` with the target name **present** in the buffer and `EaValueLength = 0` — see finding 7.10.

### 6.4 Menu 4 — Run full demonstration

This is the presentation artifact. It creates `%TEMP%\ea_demo.bin`, computes its MD5 and SHA256, and then executes the fixed sequence below.

| Step | Action | Finding | Expected |
| --- | --- | --- | --- |
| `[0]` | Create demo file, hash it | — | file created, hashes printed |
| `[1]` | Set `MVTest.MD5`, `MVTest.SHA256` via `NtSetEaFile` | — | `STATUS_SUCCESS` |
| `[2]` | Set `$Kernel.MVTest.MD5`, `$Kernel.MVTest.SHA256` via `IOCTL_EA_SET` → `FsRtlSetKernelEaFile` | — | `STATUS_SUCCESS` |
| `[3]` | Set `$KERNEL.PURGE.MVTest.MD5`, `$KERNEL.PURGE.MVTest.SHA256` via `IOCTL_EA_SET` → `FsRtlSetKernelEaFile` | — | `STATUS_SUCCESS` |
| `[4]` | Query all EAs with `NtQueryEaFile` | 7.5 | 6 EAs |
| `[5]` | User-mode `NtSetEaFile` write to `$Kernel.MVTest.MD5` | 7.2 | `STATUS_SUCCESS`, value unchanged |
| `[6]` | User-mode `NtSetEaFile` delete of `$Kernel.MVTest.MD5` | 7.2 | `STATUS_SUCCESS`, EA still present |
| `[7]` | Kernel-mode `IOCTL_EA_SET_VIA_ZW` to `$Kernel.MVTest.ZWTEST` | 7.1 | `STATUS_SUCCESS`, EA not added |
| `[8]` | Two `IOCTL_EA_SET` calls to `$Kernel.MVTest.MERGE` with different values | 7.3 | value updated, other EAs untouched |
| `[9]` | `IOCTL_EA_RAW_FSRTL` with a mixed user + `$Kernel.` buffer | verification | `STATUS_SUCCESS`, both entries added (documented since Win10 1803) |
| `[10]` | `IOCTL_EA_DELETE` for `$Kernel.MVTest.MERGE` | 7.3 | target gone, others still present |
| `[11]` | Update `LastWriteTime` on the file | 7.6 | `$KERNEL.PURGE.` still present |
| `[12]` | Append one byte to the file | 7.6 | `$KERNEL.PURGE.` gone, `$Kernel.` and user EAs present |
| `[13]` | `MoveFileW` within the same directory | 7.11 | all EAs present on the new path |
| `[14]` | `MoveFileW` into a subdirectory of `%TEMP%` | 7.11 | all EAs present on the new path |
| `[15]` | `CopyFileW` to a new path | 7.8 | user EAs present on the copy, kernel EAs absent |
| `[16]` | Query the demo file again | — | 4 EAs |
| `[17]` | Delete all kernel EAs, then delete each user EA by name with `EaValueLength = 0` | 7.10 | final EA count is 0 |

A clean run ends with every verdict `PASS`.

### 6.5 Menu 5 — USN tracking test

Needs Administrator. Creates its own test file, sets a user EA, scans the volume's USN journal for `USN_REASON_EA_CHANGE`, then repeats for a kernel EA and confirms no such record is emitted. See finding 7.7.

### 6.6 Menu 6 — Reboot persistence test

Option 1 prepares a file with a user EA, a non-purge kernel EA, and a purge kernel EA, and records the file path to `%TEMP%\ea_demo_persist_path.txt`. Option 2, run after a reboot, verifies all three are still present (the purge EA remains because no content write has occurred).

---

## 7. Findings

The following observations come from the demonstration on **Windows 10 (build 19041, x64)** with test signing enabled. Each is backed by a specific step in menu 4, cited in the finding.

### 7.1 `ZwSetEaFile` does not set kernel EAs, even from kernel mode

Calling `ZwSetEaFile` from a driver with a `$Kernel.` name in the buffer returns `STATUS_SUCCESS` and does nothing. The reason is `IRP_MN_KERNEL_CALL`: it is set by `FsRtlSetKernelEaFile` and not by `ZwSetEaFile`. Microsoft's documentation states this explicitly:

> "Calling an API like `ZwSetEaFile` or `FltSetEaFile` to set a Kernel EA from kernel mode isn't sufficient. To set a Kernel EA, the caller must also set the `IRP_MN_KERNEL_CALL` value in the `MinorFunction` field of the IRP. Since the only way to set this field is by generating a custom IRP, the routine `FsRtlSetKernelEaFile` is the support function to set up a Kernel EA."

The demo proves this in step `[7]`: `IOCTL_EA_SET_VIA_ZW` rebuilds the file's user EA set plus the requested kernel entry and submits through `ZwSetEaFile`. The call succeeds, and the EA is not on the file afterwards.

### 7.2 User-mode attempts to write or delete `$Kernel.` EAs are silently ignored

Microsoft's documentation states:

> "An attempt to set a Kernel EA from user mode will be silently ignored. The request will return `STATUS_SUCCESS` but no actual EA modification will be made."

The demo proves both directions in steps `[5]` and `[6]`. `NtSetEaFile` with a `$Kernel.` name returns `STATUS_SUCCESS`, the value does not change, and a subsequent submission that omits the kernel EA does not delete it. A verification routine that only checks the return status will falsely conclude success.

### 7.3 `FsRtlSetKernelEaFile` is merge, not replace

`FsRtlSetKernelEaFile` touches only the entries present in the submitted buffer. Existing kernel EAs not mentioned in the buffer are unchanged. To remove a kernel EA, submit its name with `EaValueLength = 0`.

Steps `[8]` and `[10]` demonstrate both properties: setting the same name twice updates the value and leaves other EAs untouched; setting the name with a zero-length value deletes it and leaves every other kernel and user EA in place.

### 7.4 The last entry in an EA buffer must not be padded

When several EAs are submitted in one buffer, `NextEntryOffset` for each non-last entry must be a multiple of 4. NTFS rejects unaligned offsets with `STATUS_EA_LIST_INCONSISTENT` (`0x80000014`).

The last entry must have `NextEntryOffset = 0`, and the buffer length passed to the API must equal the sum of the padded non-last entries plus the unpadded last entry. Padding the last entry (reserving bytes after its real end) is also rejected with the same status.

The POC's `EaBuilder` tracks `lastTrue_` and `lastAligned_` per append and exposes `size() = buf_.size() - (lastAligned_ - lastTrue_)`. The driver's `BuildSingleEa` and `DeleteAllKernelEas` helpers follow the same rule. Every entry the POC builds is validated by `IoCheckEaBufferValidity` in the driver before being submitted.

### 7.5 Query returns both user and kernel EAs

`NtQueryEaFile` (user mode) and `ZwQueryEaFile` (kernel mode) both return every EA on the file, user and kernel alike, regardless of the caller's mode. No filtering is applied by prefix. Step `[4]` shows all six EAs after only the driver has written the kernel ones.

### 7.6 `$KERNEL.PURGE.` EAs are dropped on data write, not on metadata change

The purge trigger is a write to the file's `$DATA` stream. The following changes do not purge `$KERNEL.PURGE.` EAs:

- timestamp or attribute changes (`FileBasicInformation`);
- rename or move within the volume;
- ACL changes;
- creation of a hard link.

The following changes do purge them:

- `NtWriteFile` / `ZwWriteFile` to the data stream;
- truncation (`FileEndOfFileInformation`);
- a dirty memory-mapped write.

Steps `[11]` and `[12]` demonstrate the distinction: updating `LastWriteTime` leaves the purge EAs in place; appending one byte to the file removes them while `$Kernel.` and user EAs remain.

### 7.7 Kernel EAs do not emit `USN_REASON_EA_CHANGE`

The USN Journal records `USN_REASON_EA_CHANGE` for user EA changes but not for kernel EA changes. A monitoring tool that relies on USN to detect EA tampering will therefore not see kernel EA writes. Menu 5 demonstrates this empirically on a volume whose USN journal has been opened or created by the test.

The practical implication is that kernel EAs are the only EAs user mode cannot forge, and are also the EAs that produce no audit trail through USN. A driver that writes kernel EAs must consider this if it is also responsible for audit.

### 7.8 `CopyFileW` carries user EAs but not kernel EAs

`CopyFileW` copies user EAs to the destination file but does not copy kernel EAs (`$Kernel.`, `$KERNEL.PURGE.`). The destination has the source's full user EA set and zero kernel EAs. Step `[15]` demonstrates this for a file that has both kinds.

This is the correct behavior for kernel-EA caches: a cache stored as `$KERNEL.PURGE.SI.` cannot leak into a copy of the file, so the recipient never sees a stale cached hash that did not originate from their own computation. No copy engine propagates kernel EAs, backup-aware or not. Preserving them across a copy requires explicitly reading them with `NtQueryEaFile` and re-applying them with `FsRtlSetKernelEaFile` on the destination.

### 7.9 `FILE_NEED_EA` is not appropriate for caches

The `Flags` field of `FILE_FULL_EA_INFORMATION` can carry `FILE_NEED_EA` (`0x80`), which tells backup-aware tools that the file cannot be correctly interpreted without the EA. For caches (MD5, SHA256, scan results) the flag must be left at 0. Setting it causes copy tools to refuse to strip the EA, which defeats cache invalidation.

### 7.10 `NtSetEaFile` requires an explicit zero-length entry to delete a user EA

`NtSetEaFile` is often described as replacing the user EA set. The observable semantics on this build are upsert plus explicit-delete:

| Input entry | Effect |
| --- | --- |
| Present, non-empty value | Set / update |
| Present, `EaValueLength = 0` | Delete |
| Not present | Preserved |
| Empty buffer of length 0 | `STATUS_EA_LIST_INCONSISTENT` (`0x80000014`) |

The consequence for user EA deletion is that you cannot simply omit the target from the buffer. You must include it with `EaValueLength = 0`. Step `[17]` demonstrates this by removing every user EA from the demo file individually and reaching `final EA count: 0`.

The same convention applies to `FsRtlSetKernelEaFile` (finding 7.3). Both APIs are best understood as upsert-plus-explicit-delete rather than as set-replace.

### 7.11 Persistence across rename and move within a volume

EAs are ordinary file metadata. Steps `[13]` and `[14]` rename and then move the demo file (same volume, subdirectory of `%TEMP%`) and re-query each time. User EAs and non-purge kernel EAs survive both operations. The purge kernel EAs are already gone at that point in the demo because `[12]` has appended a byte; if the sequence were reordered so `[13]` and `[14]` ran before `[12]`, the purge EAs would also survive the rename and move.

Reboot persistence is covered separately by menu 6: option 1 prepares a file, option 2 verifies after reboot. Reboot alone does not purge `$KERNEL.PURGE.` EAs; only content writes do.

---

## 8. Reference: the correct kernel-EA write

A minimal, correct, single-entry kernel-EA write, suitable for embedding in any WDM or KMDF driver:

```c
#include <ntifs.h>   /* FsRtlSetKernelEaFile lives here */

NTSTATUS SetOneKernelEa(PFILE_OBJECT fileObject,
                        PCSTR name,            /* "$Kernel.Xxx" */
                        const UCHAR* value, ULONG valueLen)
{
    ULONG nameLen  = (ULONG)strlen(name);
    ULONG entryLen = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName)
                     + nameLen + 1 + valueLen;
    ULONG aligned  = (entryLen + 3u) & ~3u;

    UCHAR* buf = (UCHAR*)ExAllocatePoolWithTag(PagedPool, aligned, 'aEdM');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    PFILE_FULL_EA_INFORMATION ea = (PFILE_FULL_EA_INFORMATION)buf;
    RtlZeroMemory(ea, aligned);
    ea->NextEntryOffset = 0;
    ea->Flags           = 0;
    ea->EaNameLength    = (UCHAR)nameLen;
    ea->EaValueLength   = (USHORT)valueLen;
    RtlCopyMemory(ea->EaName, name, nameLen);
    ea->EaName[nameLen] = '\0';
    if (valueLen)
        RtlCopyMemory(ea->EaName + nameLen + 1, value, valueLen);

    NTSTATUS st = FsRtlSetKernelEaFile(fileObject, buf, entryLen);
    ExFreePoolWithTag(buf, 'aEdM');
    return st;
}
```

Three non-obvious points:

1. `FsRtlSetKernelEaFile`, not `ZwSetEaFile`.
2. `PFILE_OBJECT`, not `HANDLE`.
3. The unpadded `entryLen` is the buffer size; the last entry is not padded.

---

## 9. Known Limitations

- **MD5 is used only for demonstration.** Production integrity checks should use SHA-256 or stronger. The application computes both; the driver does not hash anything, it only stores the values it is given.
- **No cache invalidation beyond `$KERNEL.PURGE.`.** A hash stored under `$Kernel.` (non-purge) becomes stale on content write. Callers that need cache semantics must use `$KERNEL.PURGE.`.
- **No on-copy persistence.** Kernel EAs are not carried by `CopyFileW` (see finding 7.8).
- **No USN audit trail for kernel EAs.** See finding 7.7.
- **NTFS only.** FAT32 and exFAT do not support EAs; `NtQueryEaFile` returns `STATUS_EAS_NOT_SUPPORTED` (`0xC0000101`).
- **Local volumes only.** The driver normalises a Win32 path to `\??\C:\...`. UNC paths are not handled.
- **PASSIVE_LEVEL only.** `ZwSetEaFile`, `ZwQueryEaFile`, `FsRtlSetKernelEaFile`, and `ObReferenceObjectByHandle` all require `PASSIVE_LEVEL`. The driver asserts this in `DispatchDeviceControl`.
- **No transaction support.** EA operations are not transacted; do not assume rollback semantics if the caller is inside a TxF transaction.
- **The driver's device security is SYSTEM + Administrators only.** A regular user process cannot open `\\.\EaDemo` at all. Menu 4 must be run elevated for the kernel-EA steps to succeed.

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Kernel EA write returns `STATUS_SUCCESS` but the EA does not appear | Driver is calling `ZwSetEaFile` instead of `FsRtlSetKernelEaFile` | Use `FsRtlSetKernelEaFile` with a `PFILE_OBJECT` |
| `STATUS_INVALID_HANDLE` from `FsRtlSetKernelEaFile` | `ObReferenceObjectByHandle` failed, or the handle was closed before the call | Use the `KernelFileObject` RAII wrapper; verify `Attach` returns `STATUS_SUCCESS` |
| `STATUS_EA_LIST_INCONSISTENT` (`0x80000014`) on a multi-entry buffer | `NextEntryOffset` not 4-byte aligned, or last entry padded, or buffer contains trailing bytes | Pad non-last entries to a 4-byte multiple; leave the last entry unpadded; pass the exact sum of entry sizes |
| `STATUS_EA_LIST_INCONSISTENT` on an *empty* buffer | `NtSetEaFile` does not accept a zero-length buffer as "delete all" | Delete EAs one at a time by including each name with `EaValueLength = 0` |
| `NtQueryEaFile` returns `STATUS_BUFFER_OVERFLOW` | Query buffer too small | Grow the buffer and retry |
| `EaDemo.sys` fails to load with `sc start` | Test signing disabled or driver not signed | See §4.3; `bcdedit /set testsigning on` then reboot |
| `NtSetEaFile` delete returns `STATUS_SUCCESS` but the user EA survives | The name was omitted from the submitted buffer | Include the name with `EaValueLength = 0` (finding 7.10) |
| User-mode `NtSetEaFile` to `$Kernel.` returns `STATUS_SUCCESS` and does nothing | Documented silent no-op | Correct behavior; do not treat it as failure |

---

## 11. License and Attribution

This POC was developed as an internal research artifact. The API semantics documented here are drawn from Microsoft's public documentation on Kernel Extended Attributes and verified empirically against Windows 10 version `22H2` (build `19045.4412`). The `$KERNEL.PURGE.SI.` naming convention referenced in §1.4 is used by the open-source System Informer project and is mentioned here only for context.