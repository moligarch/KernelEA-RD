
#pragma once

/*
 * ea_ioctl.h — shared IOCTL contract for EaDemo.
 *
 * Included from BOTH kernel and user mode. It must therefore be:
 *   - free of kernel-only headers (no <ntddk.h>, <ntifs.h>, <wdm.h>)
 *   - free of user-only headers in kernel mode (no <winioctl.h> when _KERNEL_MODE)
 *   - self-sufficient in user mode, since FILE_FULL_EA_INFORMATION is not
 *     exposed by <winternl.h> in all SDK versions.
 */
#ifdef _KERNEL_MODE
// Include ntddk.h or ntifs.h before this header.
#else
#include <Windows.h>
#include <winioctl.h>
#endif

// Private representation of FILE_FULL_EA_INFORMATION.
// Layout is identical to the Windows structure.
typedef struct _EA_FILE_FULL_EA_INFORMATION {
    ULONG  NextEntryOffset;
    UCHAR  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[1];
} EA_FILE_FULL_EA_INFORMATION, * PEA_FILE_FULL_EA_INFORMATION;

#define EA_IOCTL_DEVICE_TYPE  0x8010

#define IOCTL_EA_SET                CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EA_GET                CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_EA_DELETE             CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EA_DELETE_ALL_KERNEL  CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EA_SET_VIA_ZW         CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EA_RAW_FSRTL          CTL_CODE(EA_IOCTL_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _EA_IOCTL_SET_INPUT {
    ULONG PathBytes;
    ULONG NameBytes;
    ULONG ValueBytes;
} EA_IOCTL_SET_INPUT, * PEA_IOCTL_SET_INPUT;

typedef struct _EA_IOCTL_NAME_INPUT {
    ULONG PathBytes;
    ULONG NameBytes;
} EA_IOCTL_NAME_INPUT, * PEA_IOCTL_NAME_INPUT;

typedef struct _EA_IOCTL_GET_OUTPUT {
    ULONG ValueBytes;
} EA_IOCTL_GET_OUTPUT, * PEA_IOCTL_GET_OUTPUT;

typedef struct _EA_IOCTL_PATH_INPUT {
    ULONG PathBytes;
} EA_IOCTL_PATH_INPUT, * PEA_IOCTL_PATH_INPUT;

// EaOffset is measured from the beginning of the IOCTL input buffer.
// It must be 4-byte aligned.
typedef struct _EA_IOCTL_RAW_INPUT {
    ULONG PathBytes;
    ULONG EaBufferBytes;
    ULONG EaOffset;
} EA_IOCTL_RAW_INPUT, * PEA_IOCTL_RAW_INPUT;
