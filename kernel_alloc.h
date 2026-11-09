
#pragma once

#include <ntddk.h>

#ifndef DRIVER_TAG
#define DRIVER_TAG 'eAdM'
#endif

namespace Memory {

    enum class PoolType : ULONG {
        Paged,
        NonPaged
    };

    inline PVOID Allocate(
        SIZE_T size,
        PoolType pool = PoolType::Paged,
        ULONG tag = DRIVER_TAG)
    {
        if (size == 0) {
            return nullptr;
        }

#if defined(NTDDI_VERSION) && defined(NTDDI_WIN10_VB) && \
    (NTDDI_VERSION >= NTDDI_WIN10_VB)

        const POOL_FLAGS flags =
            pool == PoolType::Paged
            ? POOL_FLAG_PAGED
            : POOL_FLAG_NON_PAGED;

        return ExAllocatePool2(flags, size, tag);

#else

        const POOL_TYPE type =
            pool == PoolType::Paged
            ? PagedPool
            : NonPagedPool;

        return ExAllocatePoolWithTag(type, size, tag);

#endif
    }

    inline VOID Free(
        PVOID ptr,
        ULONG tag = DRIVER_TAG)
    {
        if (ptr) {
            ExFreePoolWithTag(ptr, tag);
        }
    }
}


// ------------------------------------------------------------------
// KernelFile: owning HANDLE for ZwCreateFile / ZwOpenFile.
// ------------------------------------------------------------------
class KernelFile {
public:
    KernelFile() = default;
    explicit KernelFile(HANDLE h) : handle_(h) {}
    ~KernelFile() { if (handle_) ZwClose(handle_); }

    KernelFile(KernelFile&& o) noexcept : handle_(o.handle_) { o.handle_ = nullptr; }
    KernelFile& operator=(KernelFile&& o) noexcept {
        if (this != &o) {
            if (handle_) ZwClose(handle_);
            handle_ = o.handle_;
            o.handle_ = nullptr;
        }
        return *this;
    }
    KernelFile(const KernelFile&) = delete;
    KernelFile& operator=(const KernelFile&) = delete;

    HANDLE  get() const { return handle_; }
    HANDLE* AddressOf() { return &handle_; }
    HANDLE  release() { auto h = handle_; handle_ = nullptr; return h; }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    HANDLE handle_ = nullptr;
};

// ------------------------------------------------------------------
// KernelFileObject: owning PFILE_OBJECT obtained from a HANDLE.
// ------------------------------------------------------------------
class KernelFileObject {
public:
    KernelFileObject() = default;
    ~KernelFileObject() { if (obj_) ObDereferenceObject(obj_); }

    KernelFileObject(KernelFileObject&& o) noexcept : obj_(o.obj_) { o.obj_ = nullptr; }
    KernelFileObject& operator=(KernelFileObject&& o) noexcept {
        if (this != &o) {
            if (obj_) ObDereferenceObject(obj_);
            obj_ = o.obj_;
            o.obj_ = nullptr;
        }
        return *this;
    }
    KernelFileObject(const KernelFileObject&) = delete;
    KernelFileObject& operator=(const KernelFileObject&) = delete;

    NTSTATUS Attach(HANDLE h)
    {
        if (obj_) {
            ObDereferenceObject(obj_);
            obj_ = nullptr;
        }

        return ObReferenceObjectByHandle(
            h,
            FILE_READ_EA | FILE_WRITE_EA,
            *IoFileObjectType,
            KernelMode,
            reinterpret_cast<PVOID*>(&obj_),
            nullptr);
    }

    PFILE_OBJECT get() const { return obj_; }
    explicit operator bool() const { return obj_ != nullptr; }

private:
    PFILE_OBJECT obj_ = nullptr;
};