#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <ntstatus.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include "ea_ioctl.h"

#pragma comment(lib, "bcrypt.lib")

// =====================================================================
// RAII handle wrapper
// =====================================================================
class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) : h_(h) {}
    ~ScopedHandle() { if (valid()) CloseHandle(h_); }

    ScopedHandle(ScopedHandle&& o) noexcept : h_(o.h_) { o.h_ = INVALID_HANDLE_VALUE; }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) {
            if (valid()) CloseHandle(h_);
            h_ = o.h_;
            o.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    HANDLE get() const { return h_; }
    bool   valid() const { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    explicit operator bool() const { return valid(); }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// =====================================================================
// NTDLL symbols
// =====================================================================
using NtQueryEaFile_t = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
    BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
using NtSetEaFile_t = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
using NtDeviceIoControlFile_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

static NtQueryEaFile_t          g_NtQueryEaFile = nullptr;
static NtSetEaFile_t            g_NtSetEaFile = nullptr;
static NtDeviceIoControlFile_t  g_NtDeviceIoControlFile = nullptr;
static ScopedHandle             g_hDevice;

// =====================================================================
// EA entry
// =====================================================================
struct EaEntry {
    std::string        name;
    std::vector<UCHAR> value;
    bool               is_kernel = false;
    bool               is_purge = false;
};

static bool IsKernelPrefix(const std::string& n) {
    return n.size() >= 8 && _strnicmp(n.c_str(), "$Kernel.", 8) == 0;
}
static bool IsPurgePrefix(const std::string& n) {
    return n.size() >= 14 && _strnicmp(n.c_str(), "$KERNEL.PURGE.", 14) == 0;
}
static bool IsValidEaName(const std::string& name)
{
    if (name.empty() || name.size() >= 255) {
        return false;
    }

    static const char invalidChars[] = "\\/:*?\"<>|,+=[];";

    for (unsigned char c : name) {

        if (c < 0x20 || c > 0x7E) {
            return false;
        }

        if (strchr(invalidChars, c) != nullptr) {
            return false;
        }
    }

    return true;
}
static void Verdict(const char* name, bool pass)
{
    printf("  %-58s : %s\n", name, pass ? "PASS" : "FAIL");
}
static bool AddIoctlSize(size_t& total, size_t amount) {
    if (amount > MAXDWORD - total) {
        return false;
    }

    total += amount;
    return true;
}
static bool GetPathByteCount(const std::wstring& path, ULONG& result) {
    result = 0;

    if (path.empty() || path.size() >= (MAXDWORD / sizeof(WCHAR)) - 1) {
        return false;
    }

    result = static_cast<ULONG>((path.size() + 1) * sizeof(WCHAR));
    return true;
}

// =====================================================================
// Misc helpers
// =====================================================================
static void PrintStatus(NTSTATUS st)
{
    switch ((ULONG)st) {
    case 0:          printf("STATUS_SUCCESS"); break;
    case 0xC0000022: printf("STATUS_ACCESS_DENIED (0x%08X)",        (ULONG)st); break;
    case 0xC0000034: printf("STATUS_OBJECT_NAME_NOT_FOUND (0x%08X)",(ULONG)st); break;
    case 0xC000003A: printf("STATUS_OBJECT_PATH_NOT_FOUND (0x%08X)",(ULONG)st); break;
    case 0xC0000043: printf("STATUS_SHARING_VIOLATION (0x%08X)",    (ULONG)st); break;
    case 0xC0000100: printf("STATUS_NO_EAS_ON_FILE (0x%08X)",       (ULONG)st); break;
    case 0xC0000101: printf("STATUS_EAS_NOT_SUPPORTED (0x%08X)",    (ULONG)st); break;
    case 0xC0000102: printf("STATUS_EA_TOO_LARGE (0x%08X)",         (ULONG)st); break;
    case 0x80000005: printf("STATUS_BUFFER_OVERFLOW (0x%08X)",      (ULONG)st); break;
    case 0x80000013: printf("STATUS_INVALID_EA_NAME (0x%08X)",      (ULONG)st); break;
    case 0x80000014: printf("STATUS_EA_LIST_INCONSISTENT (0x%08X)", (ULONG)st); break;
    case 0x80000015: printf("STATUS_INVALID_EA_FLAG (0x%08X)",      (ULONG)st); break;
    case 0xC0000008: printf("STATUS_INVALID_HANDLE (0x%08X)",       (ULONG)st); break;
    case 0xC000000D: printf("STATUS_INVALID_PARAMETER (0x%08X)",    (ULONG)st); break;
    case 0xC0000023: printf("STATUS_BUFFER_TOO_SMALL (0x%08X)",     (ULONG)st); break;
    case 0xC0000225: printf("STATUS_NOT_FOUND (0x%08X)",            (ULONG)st); break;
    case 0x80000002: printf("STATUS_DATATYPE_MISALIGNMENT (0x%08X)",(ULONG)st); break;
    default:         printf("0x%08X", (ULONG)st); break;
    }
}

static void PrintValue(const std::vector<UCHAR>& v)
{
    if (v.empty()) { printf("\"\""); return; }
    bool printable = std::all_of(v.begin(), v.end(),
        [](UCHAR c) { return c >= 0x20 && c <= 0x7E; });
    if (printable) {
        printf("\"%.*s\"", (int)v.size(), (const char*)v.data());
    }
    else {
        size_t lim = std::min<size_t>(v.size(), 32);
        for (size_t i = 0; i < lim; ++i) printf("%02x", v[i]);
        if (v.size() > lim) printf("...");
    }
}

static std::wstring NarrowToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string ReadLine(const std::string& prompt)
{
    std::string line;
    printf("%s", prompt.c_str());
    fflush(stdout);
    if (!std::getline(std::cin, line)) return "";
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    return line;
}

// =====================================================================
// Hashing (BCrypt, user mode)
// =====================================================================
static bool HashFile(const std::wstring& path, LPCWSTR alg,
    std::vector<UCHAR>& out, ULONG outLen)
{
    ScopedHandle h(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<UCHAR> obj, buf(64 * 1024);
    ULONG objLen = 0, res = 0, got = 0;
    bool ok = false;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&objLen, sizeof(objLen), &res, 0)))
        goto done;
    obj.resize(objLen);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0)))
        goto done;
    for (;;) {
        if (!ReadFile(h.get(), buf.data(), (DWORD)buf.size(), &got, nullptr)) goto done;
        if (got == 0) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf.data(), got, 0))) goto done;
    }
    out.resize(outLen);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, out.data(), outLen, 0))) goto done;
    ok = true;

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// =====================================================================
// EA chain builder (for NtSetEaFile)
// =====================================================================

class EaBuilder {
public:

    bool Append(const std::string& name, const std::vector<UCHAR>& value)
    {
        if (!IsValidEaName(name) || value.size() > USHRT_MAX) {
            return false;
        }

        SIZE_T nameLen = name.size();

        SIZE_T entrySize =
            FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName) + nameLen + 1 + value.size();

        SIZE_T alignedSize = (entrySize + 3u) & ~(SIZE_T)3u;
        SIZE_T offset = buf_.size();

        if (alignedSize > SIZE_MAX - offset) {
            return false;
        }

        buf_.resize(offset + alignedSize, 0);
        auto* ea = reinterpret_cast<
            EA_FILE_FULL_EA_INFORMATION*>(buf_.data() + offset);

        ea->NextEntryOffset = 0;
        ea->Flags = 0;
        ea->EaNameLength = static_cast<UCHAR>(nameLen);
        ea->EaValueLength = static_cast<USHORT>(value.size());

        memcpy(ea->EaName, name.data(), nameLen);
        ea->EaName[nameLen] = '\0';

        if (!value.empty()) {
            memcpy(ea->EaName + nameLen + 1, value.data(), value.size());
        }

        if (lastOff_ != NO_OFFSET) {
            auto* previous = reinterpret_cast<
                EA_FILE_FULL_EA_INFORMATION*>(buf_.data() + lastOff_);

            previous->NextEntryOffset = static_cast<ULONG>(offset - lastOff_);
        }

        lastOff_ = offset;
        lastTrue_ = entrySize;
        lastAligned_ = alignedSize;

        return true;
    }

    bool Append(const std::string& name, const std::string& asciiValue)
    {
        std::vector<UCHAR> value(asciiValue.begin(), asciiValue.end());
        return Append(name, value);
    }

    UCHAR* data()
    {
        return buf_.empty() ? nullptr : buf_.data();
    }

    size_t size() const
    {
        if (lastOff_ == NO_OFFSET) {
            return 0;
        }

        return buf_.size() - (lastAligned_ - lastTrue_);
    }

    bool empty() const
    {
        return buf_.empty();
    }

private:

    static constexpr size_t NO_OFFSET = static_cast<size_t>(-1);

    std::vector<UCHAR> buf_;

    size_t lastOff_ = NO_OFFSET;
    size_t lastTrue_ = 0;
    size_t lastAligned_ = 0;
};

static std::vector<UCHAR> BuildTwoEntryEaBuffer(
    const std::string& name1, const std::vector<UCHAR>& val1,
    const std::string& name2, const std::vector<UCHAR>& val2)
{
    if (!IsValidEaName(name1) || !IsValidEaName(name2) ||
        val1.size() > USHRT_MAX || val2.size() > USHRT_MAX) {
        return {};
    }

    auto A4 = [](size_t n) { return (n + 3u) & ~(size_t)3u; };
    size_t e1 = FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
        + name1.size() + 1 + val1.size();
    size_t a1 = A4(e1);
    size_t e2 = FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
        + name2.size() + 1 + val2.size();
    std::vector<UCHAR> buf(a1 + e2, 0);

    auto* ea1 = reinterpret_cast<EA_FILE_FULL_EA_INFORMATION*>(buf.data());
    ea1->NextEntryOffset = (ULONG)a1;
    ea1->EaNameLength = (UCHAR)name1.size();
    ea1->EaValueLength = (USHORT)val1.size();
    memcpy(ea1->EaName, name1.c_str(), name1.size());
    ea1->EaName[name1.size()] = '\0';
    if (!val1.empty())
        memcpy(ea1->EaName + name1.size() + 1, val1.data(), val1.size());

    auto* ea2 = reinterpret_cast<EA_FILE_FULL_EA_INFORMATION*>(buf.data() + a1);
    ea2->NextEntryOffset = 0;
    ea2->EaNameLength = (UCHAR)name2.size();
    ea2->EaValueLength = (USHORT)val2.size();
    memcpy(ea2->EaName, name2.c_str(), name2.size());
    ea2->EaName[name2.size()] = '\0';
    if (!val2.empty())
        memcpy(ea2->EaName + name2.size() + 1, val2.data(), val2.size());

    return buf;
}

// =====================================================================
// Query / set / delete EAs
// =====================================================================

static NTSTATUS ParseEaBuffer(const UCHAR* buffer, ULONG length, std::vector<EaEntry>& result)
{
    result.clear();

    if (length == 0) {
        return STATUS_SUCCESS;
    }

    if (!buffer ||
        (reinterpret_cast<ULONG_PTR>(buffer) & 3u) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    ULONG offset = 0;

    while (offset < length) {

        ULONG remaining = length - offset;

        if (remaining <
            FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName) + 1) {
            return STATUS_EA_LIST_INCONSISTENT;
        }

        auto* ea = reinterpret_cast<
            const EA_FILE_FULL_EA_INFORMATION*>(
                buffer + offset);

        SIZE_T entrySize =
            FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
            + ea->EaNameLength + 1
            + ea->EaValueLength;

        if (entrySize > remaining) {
            return STATUS_EA_LIST_INCONSISTENT;
        }

        if (ea->EaName[ea->EaNameLength] != '\0') {
            return STATUS_EA_LIST_INCONSISTENT;
        }

        EaEntry entry;
        entry.name.assign(ea->EaName, ea->EaNameLength);
        entry.value.assign(
            reinterpret_cast<const UCHAR*>(ea->EaName + ea->EaNameLength + 1),
            reinterpret_cast<const UCHAR*>(ea->EaName + ea->EaNameLength + 1) + ea->EaValueLength);

        entry.is_kernel = IsKernelPrefix(entry.name);
        entry.is_purge = IsPurgePrefix(entry.name);

        if (!IsValidEaName(entry.name)) {
            return STATUS_INVALID_EA_NAME;
        }

        result.push_back(std::move(entry));

        if (ea->NextEntryOffset == 0) {
            break;
        }

        if (ea->NextEntryOffset < entrySize ||
            (ea->NextEntryOffset & 3u) != 0 ||
            ea->NextEntryOffset > remaining) {
            return STATUS_EA_LIST_INCONSISTENT;
        }

        offset += ea->NextEntryOffset;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS QueryAllEas(HANDLE hFile, std::vector<EaEntry>& result)
{
    result.clear();

    size_t capacity = 0x10000;
    const size_t maxCapacity = 0x100000;

    while (capacity <= maxCapacity) {

        std::vector<UCHAR> buffer(capacity, 0);

        IO_STATUS_BLOCK iosb{};

        NTSTATUS st = g_NtQueryEaFile(
            hFile,
            &iosb,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            FALSE,
            nullptr,
            0,
            nullptr,
            TRUE);

        if (static_cast<ULONG>(st) == 0xC0000052) {
            // STATUS_NO_EAS_ON_FILE
            return STATUS_SUCCESS;
        }

        if (static_cast<ULONG>(st) == 0x80000005 ||
            static_cast<ULONG>(st) == 0xC0000023) {

            // STATUS_BUFFER_OVERFLOW / STATUS_BUFFER_TOO_SMALL
            if (capacity == maxCapacity) {
                return st;
            }

            capacity *= 2;
            continue;
        }

        if (!NT_SUCCESS(st)) {
            return st;
        }

        if (iosb.Information > buffer.size()) {
            return STATUS_DATA_ERROR;
        }

        return ParseEaBuffer(
            buffer.data(),
            static_cast<ULONG>(iosb.Information),
            result);
    }

    return static_cast<NTSTATUS>(0x80000005);
}

static NTSTATUS SetUserEa(const std::wstring& path, const std::string& name, const std::vector<UCHAR>& value)
{
    if (name.empty() || name.size() >= 255 || value.size() > USHRT_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    ScopedHandle h(CreateFileW(
        path.c_str(),
        FILE_READ_EA | FILE_WRITE_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!h) {
        return static_cast<NTSTATUS>(0xC0000022);
    }

    IO_STATUS_BLOCK iosb{};

    // Retain the negative test: user-mode attempts to modify
    // a kernel EA are submitted directly.
    if (IsKernelPrefix(name)) {

        EaBuilder direct;
        if (!direct.Append(name, value)) {
            return STATUS_INVALID_PARAMETER;
        }

        return g_NtSetEaFile(h.get(), &iosb, direct.data(), static_cast<ULONG>(direct.size()));
    }

    std::vector<EaEntry> existing;
    NTSTATUS st = QueryAllEas(h.get(), existing);

    if (!NT_SUCCESS(st)) {
        return st;
    }

    EaBuilder builder;
    for (const auto& e : existing) {

        if (e.is_kernel) {
            continue;
        }

        if (_stricmp(e.name.c_str(), name.c_str()) == 0) {
            continue;
        }

        if (!builder.Append(e.name, e.value)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (!builder.Append(name, value)) {
        return STATUS_INVALID_PARAMETER;
    }

    return g_NtSetEaFile(h.get(), &iosb, builder.data(), static_cast<ULONG>(builder.size()));
}

static NTSTATUS DeleteUserEa(const std::wstring& path, const std::string& name)
{
    if (name.empty() || name.size() >= 255) {
        return STATUS_INVALID_PARAMETER;
    }

    ScopedHandle h(CreateFileW(
        path.c_str(),
        FILE_READ_EA | FILE_WRITE_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!h) {
        return static_cast<NTSTATUS>(0xC0000022);
    }

    // Keep the user-mode kernel-EA deletion experiment.
    if (IsKernelPrefix(name)) {

        EaBuilder direct;

        if (!direct.Append(name, std::vector<UCHAR>{})) {
            return STATUS_INVALID_PARAMETER;
        }

        IO_STATUS_BLOCK iosb{};

        return g_NtSetEaFile(h.get(), &iosb, direct.data(), static_cast<ULONG>(direct.size()));
    }

    std::vector<EaEntry> existing;
    NTSTATUS st = QueryAllEas(h.get(), existing);

    if (!NT_SUCCESS(st)) {
        return st;
    }

    EaBuilder builder;
    bool found = false;

    for (const auto& e : existing) {

        if (e.is_kernel) {
            continue;
        }

        if (_stricmp(e.name.c_str(), name.c_str()) == 0) {

            // Explicit deletion record.
            if (!builder.Append(e.name, std::vector<UCHAR>{})) {
                return STATUS_INVALID_PARAMETER;
            }

            found = true;
            continue;
        }

        // Preserve all unrelated user EAs.
        if (!builder.Append(e.name, e.value)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (!found) {
        return static_cast<NTSTATUS>(0xC0000225);
    }

    IO_STATUS_BLOCK iosb{};

    return g_NtSetEaFile(h.get(), &iosb, builder.data(), static_cast<ULONG>(builder.size()));
}

static NTSTATUS GetEaValue(const std::wstring& path, const std::string& name, std::vector<UCHAR>& out)
{
    out.clear();

    ScopedHandle h(CreateFileW(
        path.c_str(),
        FILE_READ_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!h) {
        return static_cast<NTSTATUS>(0xC0000022);
    }

    std::vector<EaEntry> eas;
    NTSTATUS st = QueryAllEas(h.get(), eas);

    if (!NT_SUCCESS(st)) {
        return st;
    }

    for (const auto& e : eas) {
        if (_stricmp(e.name.c_str(), name.c_str()) == 0) {
            out = e.value;
            return STATUS_SUCCESS;
        }
    }

    return static_cast<NTSTATUS>(0xC0000225);
}


// =====================================================================
// Driver IOCTL wrappers
// =====================================================================

static NTSTATUS RawIoctl(HANDLE dev, DWORD code, PVOID in, DWORD inLen) {
    if (!dev || dev == INVALID_HANDLE_VALUE) {
        return static_cast<NTSTATUS>(0xC0000008);
    }

    IO_STATUS_BLOCK iosb{};
    NTSTATUS st = g_NtDeviceIoControlFile(
        dev, nullptr, nullptr, nullptr, &iosb,
        code, in, inLen, nullptr, 0);

    // This handle is opened without FILE_FLAG_OVERLAPPED.
    // Nevertheless, handle pending completion defensively.
    if (static_cast<ULONG>(st) == 0x00000103) {

        DWORD wait = WaitForSingleObject(dev, INFINITE);

        if (wait != WAIT_OBJECT_0) {
            return static_cast<NTSTATUS>(0xC0000001);
        }

        st = iosb.Status;
    }
    else if (NT_SUCCESS(st)) {
        st = iosb.Status;
    }

    return st;
}

static NTSTATUS IoctlSet(const std::wstring& path, const std::string& name, const std::vector<UCHAR>& value) {
    ULONG pathBytes = 0;

    if (!GetPathByteCount(path, pathBytes) || 
        !IsValidEaName(name) ||
        value.size() > USHRT_MAX) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    ULONG nameBytes = static_cast<ULONG>(name.size());
    SIZE_T total = sizeof(EA_IOCTL_SET_INPUT);

    if (!AddIoctlSize(total, pathBytes) ||
        !AddIoctlSize(total, nameBytes) ||
        !AddIoctlSize(total, value.size())) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    std::vector<UCHAR> buf(total, 0);
    auto* h = reinterpret_cast<EA_IOCTL_SET_INPUT*>(buf.data());

    h->PathBytes = pathBytes;
    h->NameBytes = nameBytes;
    h->ValueBytes = static_cast<ULONG>(value.size());

    UCHAR* p = buf.data() + sizeof(*h);
    memcpy(p, path.c_str(), pathBytes);
    p += pathBytes;

    memcpy(p, name.data(), nameBytes);
    p += nameBytes;

    if (!value.empty()) {
        memcpy(p, value.data(), value.size());
    }

    return RawIoctl(g_hDevice.get(), IOCTL_EA_SET, buf.data(), static_cast<DWORD>(buf.size()));
}

static NTSTATUS IoctlDelete(const std::wstring& path, const std::string& name)
{
    ULONG pathBytes = 0;

    if (!GetPathByteCount(path, pathBytes) ||
        !IsValidEaName(name)) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    ULONG nameBytes = static_cast<ULONG>(name.size());
    SIZE_T total = sizeof(EA_IOCTL_NAME_INPUT);
    if (!AddIoctlSize(total, pathBytes) ||
        !AddIoctlSize(total, nameBytes)) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    std::vector<UCHAR> buf(total, 0);
    auto* h = reinterpret_cast<EA_IOCTL_NAME_INPUT*>(buf.data());
    h->PathBytes = pathBytes;
    h->NameBytes = nameBytes;

    UCHAR* p = buf.data() + sizeof(EA_IOCTL_NAME_INPUT);
    memcpy(p, path.c_str(), pathBytes); p += pathBytes;
    memcpy(p, name.c_str(), nameBytes);

    return RawIoctl(g_hDevice.get(), IOCTL_EA_DELETE, buf.data(), (DWORD)buf.size());
}

static NTSTATUS IoctlDeleteAllKernel(const std::wstring& path)
{
    ULONG pathBytes = 0;

    if (!GetPathByteCount(path, pathBytes)) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    SIZE_T total = sizeof(EA_IOCTL_PATH_INPUT);
    if (!AddIoctlSize(total, pathBytes)) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    std::vector<UCHAR> buf(total, 0);
    auto* h = reinterpret_cast<EA_IOCTL_PATH_INPUT*>(buf.data());
    h->PathBytes = pathBytes;
    memcpy(buf.data() + sizeof(EA_IOCTL_PATH_INPUT), path.c_str(), pathBytes);

    return RawIoctl(g_hDevice.get(), IOCTL_EA_DELETE_ALL_KERNEL, buf.data(), (DWORD)buf.size());
}

static NTSTATUS IoctlSetViaZw(const std::wstring& path, const std::string& name, const std::vector<UCHAR>& value)
{
    ULONG pathBytes = 0;

    if (!GetPathByteCount(path, pathBytes) ||
        !IsValidEaName(name) ||
        value.size() > USHRT_MAX) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    ULONG nameBytes = static_cast<ULONG>(name.size());
    SIZE_T total = sizeof(EA_IOCTL_SET_INPUT);

    if (!AddIoctlSize(total, pathBytes) ||
        !AddIoctlSize(total, nameBytes) ||
        !AddIoctlSize(total, value.size())) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    std::vector<UCHAR> buf(total, 0);
    auto* h = reinterpret_cast<EA_IOCTL_SET_INPUT*>(buf.data());

    h->PathBytes = pathBytes;
    h->NameBytes = nameBytes;
    h->ValueBytes = static_cast<ULONG>(value.size());

    UCHAR* p = buf.data() + sizeof(*h);
    memcpy(p, path.c_str(), pathBytes);
    p += pathBytes;

    memcpy(p, name.data(), nameBytes);
    p += nameBytes;

    if (!value.empty()) {
        memcpy(p, value.data(), value.size());
    }

    return RawIoctl(g_hDevice.get(), IOCTL_EA_SET_VIA_ZW, buf.data(), (DWORD)buf.size());
}

static NTSTATUS IoctlRawFsRtl(const std::wstring& path, const std::vector<UCHAR>& eaBuffer)
{
    if (path.empty() || path.size() >= (MAXDWORD / sizeof(WCHAR)) ||
        eaBuffer.empty() || eaBuffer.size() > MAXDWORD) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    ULONG pathBytes = static_cast<ULONG>((path.size() + 1) * sizeof(WCHAR));
    SIZE_T pathEnd = sizeof(EA_IOCTL_RAW_INPUT) + pathBytes;
    SIZE_T eaOffset = (pathEnd + 3u) & ~(SIZE_T)3u;

    if (eaOffset > MAXDWORD || eaBuffer.size() > MAXDWORD - eaOffset) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    SIZE_T total = eaOffset + eaBuffer.size();
    std::vector<UCHAR> buf(total, 0);
    auto* h = reinterpret_cast<EA_IOCTL_RAW_INPUT*>(buf.data());

    h->PathBytes = pathBytes;
    h->EaBufferBytes = static_cast<ULONG>(eaBuffer.size());
    h->EaOffset = static_cast<ULONG>(eaOffset);

    memcpy(buf.data() + sizeof(*h), path.c_str(), pathBytes);
    memcpy(buf.data() + eaOffset, eaBuffer.data(), eaBuffer.size());

    return RawIoctl(g_hDevice.get(), IOCTL_EA_RAW_FSRTL, buf.data(), static_cast<DWORD>(buf.size()));
}


// =====================================================================
// Print / test EAs
// =====================================================================
static void PrintEaList(const std::wstring& path)
{
    ScopedHandle h(CreateFileW(
        path.c_str(),
        FILE_READ_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!h) {
        printf("  Cannot open for FILE_READ_EA: %lu\n", GetLastError());
        return;
    }

    std::vector<EaEntry> eas;
    NTSTATUS st = QueryAllEas(h.get(), eas);

    if (!NT_SUCCESS(st)) {
        printf("  EA query failed: ");
        PrintStatus(st);
        printf("\n");
        return;
    }

    if (eas.empty()) {
        printf("  (no EAs)\n");
        return;
    }

    for (const auto& e : eas) {

        const char* tag =
            e.is_purge ? "[KERNEL-PURGE]" :
            e.is_kernel ? "[KERNEL]" : "[USER]";

        printf(
            "  %-14s %-32s (%u bytes) = ",
            tag,
            e.name.c_str(),
            static_cast<unsigned>(e.value.size()));

        PrintValue(e.value);
        printf("\n");
    }

    printf(
        "  -> %u EA%s total\n",
        static_cast<unsigned>(eas.size()),
        eas.size() == 1 ? "" : "s");
}

static bool EaPresent(const std::wstring& path, const std::string& name)
{
    ScopedHandle h(CreateFileW(
        path.c_str(),
        FILE_READ_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!h) {
        printf("  EA presence query: open failed (%lu)\n", GetLastError());
        return false;
    }

    std::vector<EaEntry> eas;

    NTSTATUS st = QueryAllEas(h.get(), eas);

    if (!NT_SUCCESS(st)) {
        printf("  EA presence query failed: ");
        PrintStatus(st);
        printf("\n");
        return false;
    }

    for (const auto& e : eas) {
        if (_stricmp(e.name.c_str(), name.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

// =====================================================================
// File modification helpers (for purge test)
// =====================================================================
static bool DemoAppendByte(const std::wstring& path)
{
    ScopedHandle h(CreateFileW(path.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h) return false;
    DWORD w;
    return WriteFile(h.get(), "X", 1, &w, nullptr) && w == 1;
}

static bool DemoTruncateLastByte(const std::wstring& path)
{
    ScopedHandle h(CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h) return false;
    SetFilePointer(h.get(), -1, nullptr, FILE_END);
    return SetEndOfFile(h.get()) != 0;
} 

// =====================================================================
// Menu: option 1
// =====================================================================
static void OptionSetEa()
{
    std::wstring path = NarrowToWide(ReadLine("File path: "));
    if (path.empty()) { printf("  Empty path\n"); return; }

    printf("What to set?\n"
        "  (1) MD5 + SHA256 with prefix\n"
        "  (2) Custom name/value\n"
        "Choice: ");
    fflush(stdout);
    std::string kind;
    if (!std::getline(std::cin, kind) || kind.empty()) return;

    if (kind[0] == '1') {
        std::string prefix = ReadLine("Prefix (default MVTest): ");
        if (prefix.empty()) prefix = "MVTest";

        std::string mode = ReadLine("Mode (U)ser or (K)ernel: ");
        bool isKernel = !mode.empty() && (mode[0] == 'K' || mode[0] == 'k');

        std::string purge;
        if (isKernel) purge = ReadLine("Purge? (P)urge or (N)on-purge: ");
        bool isPurge = !purge.empty() && (purge[0] == 'P' || purge[0] == 'p');

        std::vector<UCHAR> md5, sha;
        if (!HashFile(path, BCRYPT_MD5_ALGORITHM, md5, 16)) {
            printf("  MD5 hashing failed\n"); return;
        }
        if (!HashFile(path, BCRYPT_SHA256_ALGORITHM, sha, 32)) {
            printf("  SHA256 hashing failed\n"); return;
        }

        std::string n1, n2;
        if (isKernel) {
            if (isPurge) {
                n1 = "$KERNEL.PURGE." + prefix + ".MD5";
                n2 = "$KERNEL.PURGE." + prefix + ".SHA256";
            }
            else {
                n1 = "$Kernel." + prefix + ".MD5";
                n2 = "$Kernel." + prefix + ".SHA256";
            }
            printf("  %-32s ", n1.c_str());
            PrintStatus(IoctlSet(path, n1, md5)); printf("\n");
            printf("  %-32s ", n2.c_str());
            PrintStatus(IoctlSet(path, n2, sha)); printf("\n");
        }
        else {
            n1 = prefix + ".MD5";
            n2 = prefix + ".SHA256";
            printf("  %-32s ", n1.c_str());
            PrintStatus(SetUserEa(path, n1, md5)); printf("\n");
            printf("  %-32s ", n2.c_str());
            PrintStatus(SetUserEa(path, n2, sha)); printf("\n");
        }
    }
    else if (kind[0] == '2') {
        std::string name = ReadLine("EA name (no $Kernel. prefix): ");
        if (name.empty()) { printf("  Empty name\n"); return; }
        std::string value = ReadLine("Value (text): ");

        std::string mode = ReadLine("Mode (U)ser or (K)ernel: ");
        bool isKernel = !mode.empty() && (mode[0] == 'K' || mode[0] == 'k');

        std::vector<UCHAR> v(value.begin(), value.end());

        if (isKernel) {
            std::string purge = ReadLine("Purge? (P)urge or (N)on-purge: ");
            bool isPurge = !purge.empty() && (purge[0] == 'P' || purge[0] == 'p');
            std::string full = isPurge
                ? ("$KERNEL.PURGE." + name)
                : ("$Kernel." + name);
            printf("  %-32s ", full.c_str());
            PrintStatus(IoctlSet(path, full, v)); printf("\n");
        }
        else {
            printf("  %-32s ", name.c_str());
            PrintStatus(SetUserEa(path, name, v)); printf("\n");
        }
    }
    else {
        printf("  Invalid choice\n");
    }
}

// =====================================================================
// Menu: option 2
// =====================================================================
static void OptionGetEa()
{
    std::wstring path = NarrowToWide(ReadLine("File path: "));
    if (path.empty()) { printf("  Empty path\n"); return; }
    printf("EAs:\n");
    PrintEaList(path);
}

// =====================================================================
// Menu: option 3
// =====================================================================
static void OptionClearEa()
{
    std::wstring path = NarrowToWide(ReadLine("File path: "));
    if (path.empty()) { printf("  Empty path\n"); return; }

    ScopedHandle h(CreateFileW(path.c_str(), FILE_READ_EA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h) { 
        printf("  Cannot open (GetLastError=%lu)\n", GetLastError());
        return; 
    }

    std::vector<EaEntry> eas;
    NTSTATUS queryStatus = QueryAllEas(h.get(), eas);
    if (!NT_SUCCESS(queryStatus)) {
        printf("  EA query failed: ");
        PrintStatus(queryStatus);
        printf("\n");
        return;
    }

    if (eas.empty()) {
        printf("  (no EAs)\n");
        return;
    }

    printf("Current EAs:\n");
    for (size_t i = 0; i < eas.size(); ++i) {
        const char* tag =
            eas[i].is_purge ? "[KERNEL-PURGE]" :
            eas[i].is_kernel ? "[KERNEL]" : "[USER]";
        printf("  %zu) %-14s %s\n", i, tag, eas[i].name.c_str());
    }

    std::string what = ReadLine("Delete by name, 'all-kernel', or 'all-user': ");
    if (what.empty()) return;

    if (_stricmp(what.c_str(), "all-kernel") == 0) {
        printf("  IOCTL_EA_DELETE_ALL_KERNEL -> ");
        PrintStatus(IoctlDeleteAllKernel(path)); printf("\n");
    }
    else if (_stricmp(what.c_str(), "all-user") == 0) {
        NTSTATUS last = STATUS_SUCCESS;
        for (const auto& e : eas) {
            if (e.is_kernel) {
                continue;
            }

            last = DeleteUserEa(path, e.name);
            if (!NT_SUCCESS(last)) {
                break;
            }
        }
        printf("  Delete all user EAs -> ");
        PrintStatus(last); 
        printf("\n");

        std::vector<EaEntry> remaining;
        NTSTATUS verify = QueryAllEas(h.get(), remaining);

        if (NT_SUCCESS(verify)) {
            
            bool noUserEas = true;
            for (const auto& e : remaining) {
                if (!e.is_kernel) {
                    noUserEas = false;
                    break;
                }
            }

            Verdict("all user EAs deleted", NT_SUCCESS(last) && noUserEas);
        }
        else {
            printf("  Verification failed: ");
            PrintStatus(verify);
            printf("\n");
        }
    }
    else if (IsKernelPrefix(what)) {
        printf("  IOCTL_EA_DELETE -> ");
        PrintStatus(IoctlDelete(path, what)); printf("\n");
    }
    else {
        printf("  Delete user EA -> ");
        PrintStatus(DeleteUserEa(path, what)); printf("\n");
    }
}

// =====================================================================
// Menu: option 4 — full demonstration
// =====================================================================
static void OptionFullDemo()
{
    printf("\n=== Full EA Demonstration ===\n\n");

    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    std::wstring demoPath = std::wstring(tempDir) + L"ea_demo.bin";
    std::wstring demoRenamed = std::wstring(tempDir) + L"ea_demo_renamed.bin";
    std::wstring demoSubDir = std::wstring(tempDir) + L"ea_demo_sub";
    std::wstring demoInSub = demoSubDir + L"\\ea_demo_moved.bin";
    std::wstring demoCopy = std::wstring(tempDir) + L"ea_demo_copy.bin";

    auto cleanup = [&]() {
        DeleteFileW(demoPath.c_str());
        DeleteFileW(demoRenamed.c_str());
        DeleteFileW(demoInSub.c_str());
        DeleteFileW(demoCopy.c_str());
        RemoveDirectoryW(demoSubDir.c_str());
    };
    cleanup();

    // ---- [0] Setup ----
    printf("[0] Setup\n");
    printf("  Demo file: %ls\n", demoPath.c_str());
    {
        ScopedHandle h(CreateFileW(demoPath.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) { printf("  Cannot create file: %lu\n", GetLastError()); return; }
        std::vector<char> content(1024, 'A');
        DWORD w = 0;
        WriteFile(h.get(), content.data(), (DWORD)content.size(), &w, nullptr);
    }
    std::vector<UCHAR> md5, sha;
    if (!HashFile(demoPath, BCRYPT_MD5_ALGORITHM, md5, 16) ||
        !HashFile(demoPath, BCRYPT_SHA256_ALGORITHM, sha, 32)) {
        printf("  hashing failed\n"); return;
    }
    printf("  MD5    = "); PrintValue(md5);    printf("\n");
    printf("  SHA256 = "); PrintValue(sha);    printf("\n\n");

    // ---- [1] User EAs ----
    printf("[1] Set user EAs (NtSetEaFile)\n");
    printf("  MVTest.MD5     -> "); PrintStatus(SetUserEa(demoPath, "MVTest.MD5", md5));    printf("\n");
    printf("  MVTest.SHA256  -> "); PrintStatus(SetUserEa(demoPath, "MVTest.SHA256", sha)); printf("\n\n");

    // ---- [2] Kernel non-purge EAs ----
    printf("[2] Set kernel non-purge EAs (IOCTL -> FsRtlSetKernelEaFile)\n");
    printf("  $Kernel.MVTest.MD5     -> ");
    PrintStatus(IoctlSet(demoPath, "$Kernel.MVTest.MD5", md5));    printf("\n");
    printf("  $Kernel.MVTest.SHA256  -> ");
    PrintStatus(IoctlSet(demoPath, "$Kernel.MVTest.SHA256", sha)); printf("\n\n");

    // ---- [3] Kernel purge EAs ----
    printf("[3] Set kernel purge EAs (IOCTL -> FsRtlSetKernelEaFile)\n");
    printf("  $KERNEL.PURGE.MVTest.MD5     -> ");
    PrintStatus(IoctlSet(demoPath, "$KERNEL.PURGE.MVTest.MD5", md5));    printf("\n");
    printf("  $KERNEL.PURGE.MVTest.SHA256  -> ");
    PrintStatus(IoctlSet(demoPath, "$KERNEL.PURGE.MVTest.SHA256", sha)); printf("\n\n");

    // ---- [4] Query ----
    printf("[4] Query all - expect 6 EAs\n");
    PrintEaList(demoPath);
    {
        size_t n = 0;
        NTSTATUS queryStatus = STATUS_ACCESS_DENIED;
        {
            ScopedHandle h(CreateFileW(
                demoPath.c_str(), FILE_READ_EA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                nullptr));

            if (h) {
                std::vector<EaEntry> eas;
                queryStatus = QueryAllEas(h.get(), eas);

                if (NT_SUCCESS(queryStatus)) {
                    n = eas.size();
                }
            }
        }

        Verdict("6 EAs after [1]+[2]+[3]", NT_SUCCESS(queryStatus) && n == 6);
    }
    printf("\n");

    // ---- [5] User-mode write to $Kernel.* — silent no-op ----
    printf("[5] User-mode write to $Kernel.* (finding 7.2)\n");
    {
        std::vector<UCHAR> before, after;
        NTSTATUS q1 = GetEaValue(demoPath, "$Kernel.MVTest.MD5", before);

        std::vector<UCHAR> fake(16, 0xAA);
        NTSTATUS setStatus = SetUserEa(demoPath, "$Kernel.MVTest.MD5", fake);
        NTSTATUS q2 = GetEaValue(demoPath, "$Kernel.MVTest.MD5", after);

        printf("  NtSetEaFile -> ");
        PrintStatus(setStatus);
        printf("\n");

        Verdict("kernel EA remained unchanged",
            NT_SUCCESS(q1) &&
            NT_SUCCESS(setStatus) &&
            NT_SUCCESS(q2) &&
            before == after);
    }
    printf("\n");

    // ---- [6] User-mode delete of $Kernel.* — silent no-op ----
    printf("[6] User-mode delete of $Kernel.* (finding 7.2)\n");
    {
        bool before = EaPresent(demoPath, "$Kernel.MVTest.MD5"); 
        NTSTATUS st = DeleteUserEa(demoPath, "$Kernel.MVTest.MD5");
        bool after = EaPresent(demoPath, "$Kernel.MVTest.MD5");

        printf("  NtSetEaFile -> ");
        PrintStatus(st);
        printf("\n");

        Verdict("user mode cannot delete kernel EA", before && NT_SUCCESS(st) && after);
    }
    printf("\n");

    // ---- [7] Kernel-mode ZwSetEaFile cannot set $Kernel.* ----
    printf("[7] Kernel-mode ZwSetEaFile to $Kernel.* (finding 7.1)\n");
    {
        std::vector<UCHAR> val(16, 0x77);
        NTSTATUS st = IoctlSetViaZw(demoPath, "$Kernel.MVTest.ZWTEST", val);
        printf("  IOCTL_EA_SET_VIA_ZW -> "); PrintStatus(st); printf("\n");
        Verdict("status SUCCESS and EA not added",
            st == 0 && !EaPresent(demoPath, "$Kernel.MVTest.ZWTEST"));
    }
    printf("\n");

    // ---- [8] FsRtl merge semantics ----
    printf("[8] FsRtlSetKernelEaFile is merge, not replace (finding 7.3)\n");
    {
        std::vector<UCHAR> v1(16, 0x11);
        std::vector<UCHAR> v2(16, 0x22);
        std::vector<UCHAR> got;

        NTSTATUS s1 = IoctlSet(demoPath, "$Kernel.MVTest.MERGE", v1);
        NTSTATUS s2 = IoctlSet(demoPath, "$Kernel.MVTest.MERGE", v2);
        NTSTATUS q = GetEaValue(demoPath, "$Kernel.MVTest.MERGE", got);

        Verdict(
            "merge/update of existing kernel EA",
            NT_SUCCESS(s1) &&
            NT_SUCCESS(s2) &&
            NT_SUCCESS(q) &&
            got == v2);

        Verdict(
            "other EAs untouched",
            EaPresent(demoPath, "$Kernel.MVTest.MD5") &&
            EaPresent(demoPath, "$Kernel.MVTest.SHA256") &&
            EaPresent(demoPath, "MVTest.MD5"));
    }
    printf("\n");

    // ---- [9] Mixed user+kernel buffer ----
    printf("[9] Mixed user+kernel buffer in FsRtlSetKernelEaFile (documented since Win10 1803)\n");
    {
        auto buf = BuildTwoEntryEaBuffer(
            "$Kernel.MVTest.MIXK",  std::vector<UCHAR>{'k', 'v'},
            "MVTest.MIXU",          std::vector<UCHAR>{'u', 'v'}
        );
        NTSTATUS st = IoctlRawFsRtl(demoPath, buf);
        printf("  FsRtlSetKernelEaFile -> "); PrintStatus(st); printf("\n");

        bool kernelAdded = EaPresent(demoPath, "$Kernel.MVTest.MIXK");
        bool userAdded = EaPresent(demoPath, "MVTest.MIXU");
        printf("  kernel EA added: %s\n", kernelAdded ? "YES" : "no");
        printf("  user EA added:   %s\n", userAdded ? "YES" : "no");

        if (static_cast<ULONG>(st) == 0xC0000493) {
            Verdict("mixed kernel/normal operation rejected", !kernelAdded && !userAdded);
        }
        else if (NT_SUCCESS(st)) {
            printf("  WARNING: mixed EA operation accepted on this build\n");
            Verdict("mixed operation produced both expected entries", kernelAdded && userAdded);
        }
        else {
            printf("  Unexpected mixed-operation status: ");
            PrintStatus(st);
            printf("\n");

            Verdict("mixed operation", false);
        }

        // Clean up regardless of which path was taken, and print what happened.
        printf("  cleanup:\n");

        NTSTATUS sc1 = IoctlDelete(demoPath, "$Kernel.MVTest.MIXK");
        printf("    IoctlDelete($Kernel.MVTest.MIXK) -> ");
        PrintStatus(sc1); printf("\n");

        NTSTATUS sc2 = DeleteUserEa(demoPath, "MVTest.MIXU");
        printf("    DeleteUserEa(MVTest.MIXU)         -> ");
        PrintStatus(sc2); printf("\n");

        printf("    MIXK still present: %s\n",
            EaPresent(demoPath, "$Kernel.MVTest.MIXK") ? "YES" : "no");
        printf("    MIXU still present: %s\n",
            EaPresent(demoPath, "MVTest.MIXU") ? "YES" : "no");

        Verdict("MIXK and MIXU cleaned up",
            !EaPresent(demoPath, "$Kernel.MVTest.MIXK") &&
            !EaPresent(demoPath, "MVTest.MIXU"));
    }
    printf("\n");

    // ---- [10] FsRtl delete-one ----
    printf("[10] FsRtlSetKernelEaFile delete-one via valueLen=0 (finding 7.3)\n");
    {
        NTSTATUS st = IoctlDelete(demoPath, "$Kernel.MVTest.MERGE");
        printf("  IOCTL_EA_DELETE -> "); PrintStatus(st); printf("\n");
        Verdict("target gone", !EaPresent(demoPath, "$Kernel.MVTest.MERGE"));
        Verdict("others still present",
            EaPresent(demoPath, "$Kernel.MVTest.MD5") &&
            EaPresent(demoPath, "$Kernel.MVTest.SHA256") &&
            EaPresent(demoPath, "MVTest.MD5") &&
            EaPresent(demoPath, "MVTest.SHA256"));
    }
    printf("\n");

    // ---- [11] Metadata change does NOT purge ----
    printf("[11] Metadata change does not purge $KERNEL.PURGE.* (finding 7.6)\n");
    {
        ScopedHandle h(CreateFileW(demoPath.c_str(), FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) { 
            printf("  open failed: %lu\n", GetLastError()); 
            goto after_11; 
        }

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        if (!SetFileTime(h.get(), nullptr, nullptr, &ft)) {
            printf("  SetFileTime failed: %lu\n", GetLastError());
            goto after_11;
        }

        printf("  LastWriteTime updated\n");

        Verdict("$KERNEL.PURGE.MVTest.MD5 still present",
            EaPresent(demoPath, "$KERNEL.PURGE.MVTest.MD5"));
        Verdict("$KERNEL.PURGE.MVTest.SHA256 still present",
            EaPresent(demoPath, "$KERNEL.PURGE.MVTest.SHA256"));
    }
after_11:
    printf("\n");

    // ---- [12] Data write DOES purge ----
    printf("[12] Data write purges $KERNEL.PURGE.* (finding 7.6)\n");
    {
        ScopedHandle h(CreateFileW(demoPath.c_str(), FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) { 
            printf("  open failed\n"); 
            goto after_12; 
        }

        DWORD w = 0;
        if (!WriteFile(h.get(), "X", 1, &w, nullptr) || w != 1) {
            printf("  WriteFile failed: %lu, bytes=%lu\n", GetLastError(), w);
            goto after_12;
        }

        printf("  appended 1 byte\n");

        Verdict("$KERNEL.PURGE.MVTest.MD5 gone",
            !EaPresent(demoPath, "$KERNEL.PURGE.MVTest.MD5"));
        Verdict("$KERNEL.PURGE.MVTest.SHA256 gone",
            !EaPresent(demoPath, "$KERNEL.PURGE.MVTest.SHA256"));
        Verdict("$Kernel.* survived",
            EaPresent(demoPath, "$Kernel.MVTest.MD5") &&
            EaPresent(demoPath, "$Kernel.MVTest.SHA256"));
        Verdict("user EAs survived",
            EaPresent(demoPath, "MVTest.MD5") &&
            EaPresent(demoPath, "MVTest.SHA256"));
    }
after_12:
    printf("\n");

    // ---- [13] Rename preserves EAs ----
    printf("[13] Rename within same directory preserves EAs (finding 7.11)\n");
    {
        if (!MoveFileW(demoPath.c_str(), demoRenamed.c_str())) {
            printf("  rename failed: %lu\n", GetLastError()); goto after_13;
        }
        Verdict("user EAs present after rename",
            EaPresent(demoRenamed, "MVTest.MD5") &&
            EaPresent(demoRenamed, "MVTest.SHA256"));
        Verdict("kernel EAs present after rename",
            EaPresent(demoRenamed, "$Kernel.MVTest.MD5") &&
            EaPresent(demoRenamed, "$Kernel.MVTest.SHA256"));
        if (!MoveFileW(demoRenamed.c_str(), demoPath.c_str())) {

            printf("  Restore after rename failed: %lu\n", GetLastError());
        }
    }
after_13:
    printf("\n");

    // ---- [14] Move across directories preserves EAs ----
    printf("[14] Move across directories preserves EAs (finding 7.11)\n");
    {
        CreateDirectoryW(demoSubDir.c_str(), nullptr);
        if (!MoveFileW(demoPath.c_str(), demoInSub.c_str())) {
            printf("  move failed: %lu\n", GetLastError()); goto after_14;
        }
        Verdict("user EAs present after move",
            EaPresent(demoInSub, "MVTest.MD5") &&
            EaPresent(demoInSub, "MVTest.SHA256"));
        Verdict("kernel EAs present after move",
            EaPresent(demoInSub, "$Kernel.MVTest.MD5") &&
            EaPresent(demoInSub, "$Kernel.MVTest.SHA256"));
        if (!MoveFileW(demoInSub.c_str(), demoPath.c_str())) {

            printf("  Restore after directory move failed: %lu\n", GetLastError());
        }
    }
after_14:
    printf("\n");

    // ---- [15] CopyFileW semantics ----
    printf("[15] CopyFileW EA propagation semantics (finding 7.8)\n");
    {
        if (!CopyFileW(demoPath.c_str(), demoCopy.c_str(), FALSE)) {
            printf("  CopyFileW failed: %lu\n", GetLastError());
            goto after_15;
        }
        else {
            bool userMd5 = EaPresent(demoCopy, "MVTest.MD5");
            bool userSha = EaPresent(demoCopy, "MVTest.SHA256");

            bool kernelMd5 = EaPresent(demoCopy, "$Kernel.MVTest.MD5");
            bool kernelSha = EaPresent(demoCopy, "$Kernel.MVTest.SHA256");

            printf("  user MD5:    %s\n", userMd5 ? "PRESENT" : "absent");
            printf("  user SHA256: %s\n", userSha ? "PRESENT" : "absent");

            printf("  kernel MD5:    %s\n", kernelMd5 ? "PRESENT" : "absent");
            printf("  kernel SHA256: %s\n", kernelSha ? "PRESENT" : "absent");

            Verdict("both user EAs observed on copy", userMd5&& userSha);
            Verdict("both kernel EAs absent from copy", !kernelMd5 && !kernelSha);

            DeleteFileW(demoCopy.c_str());
        }
    }
after_15:
    printf("\n");

    // ---- [16] Final query ----
    printf("[16] Final query\n");
    PrintEaList(demoPath);
    printf("\n");

    // ---- [17] Cleanup ----

    printf("[17] EA cleanup using explicit deletion records\n");
    {
        auto snapshot = [&](std::vector<EaEntry>& result) -> NTSTATUS
        {
            result.clear();

            ScopedHandle h(CreateFileW(
                demoPath.c_str(),
                FILE_READ_EA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));

            if (!h) {
                return static_cast<NTSTATUS>(0xC0000022);
            }

            return QueryAllEas(h.get(), result);
        };

        std::vector<EaEntry> before;
        NTSTATUS q = snapshot(before);

        if (!NT_SUCCESS(q)) {
            printf("  Initial query failed: ");
            PrintStatus(q);
            printf("\n");
        }
        else {
            printf("  pre-cleanup EA count: %zu\n", before.size());
            // Step 1: remove kernel EAs.
            NTSTATUS sk = IoctlDeleteAllKernel(demoPath);

            printf("  DeleteAllKernel -> ");
            PrintStatus(sk);
            printf("\n");

            if (NT_SUCCESS(sk)) {
                // Query again after kernel deletion.
                std::vector<EaEntry> afterKernel;
                q = snapshot(afterKernel);

                if (!NT_SUCCESS(q)) {
                    printf("  Query after kernel deletion failed: ");
                    PrintStatus(q);
                    printf("\n");
                }
                else {
                    // Step 2: explicitly delete each remaining user EA.
                    for (const auto& e : afterKernel) {

                        if (e.is_kernel) {
                            continue;
                        }

                        NTSTATUS s = DeleteUserEa(demoPath, e.name);

                        printf("  DeleteUserEa(%s) -> ", e.name.c_str());
                        PrintStatus(s);
                        printf("\n");

                        if (!NT_SUCCESS(s)) {
                            break;
                        }
                    }

                    // Step 3: verify the actual final state.
                    std::vector<EaEntry> finalState;
                    q = snapshot(finalState);

                    if (!NT_SUCCESS(q)) {
                        printf("  Final query failed: ");
                        PrintStatus(q);
                        printf("\n");
                    }
                    else {
                        printf("  final EA count: %zu\n", finalState.size());
                        for (const auto& e : finalState) {

                            printf(
                                "    leftover: %s %s\n",
                                e.is_kernel ? "[KERNEL]" : "[USER]",
                                e.name.c_str());
                        }

                        Verdict("all EAs explicitly removed", finalState.empty());
                    }
                }
            }
        }
    }


    printf("\n=== Demonstration complete ===\n");
}

static bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION elev = {};
    DWORD ret = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &ret);
    CloseHandle(tok);
    return ok && elev.TokenIsElevated;
}

static NTSTATUS UsnScanFor(HANDLE hVol, DWORDLONG journalId, USN startUsn,
    USN endUsn, DWORDLONG fileRef, DWORD reasonBit, bool& found)
{
    found = false;
    READ_USN_JOURNAL_DATA_V0 rd{};

    rd.ReasonMask = 0xFFFFFFFF;
    rd.UsnJournalID = journalId;
    rd.ReturnOnlyOnClose = FALSE;
    rd.Timeout = 0;
    rd.BytesToWaitFor = 0;

    std::vector<BYTE> buffer(0x10000);

    while (startUsn < endUsn) {

        rd.StartUsn = startUsn;

        DWORD bytes = 0;

        if (!DeviceIoControl(
            hVol,
            FSCTL_READ_USN_JOURNAL,
            &rd,
            sizeof(rd),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes,
            nullptr)) {

            return static_cast<NTSTATUS>(0xC0000001);
        }

        if (bytes < sizeof(USN)) {
            return STATUS_DATA_ERROR;
        }

        USN nextUsn = *reinterpret_cast<const USN*>(buffer.data());

        BYTE* p = buffer.data() + sizeof(USN);
        BYTE* end = buffer.data() + bytes;

        while (p < end) {

            SIZE_T remaining = static_cast<SIZE_T>(end - p);

            if (remaining < FIELD_OFFSET(USN_RECORD_V2, FileName)) {
                return STATUS_DATA_ERROR;
            }

            auto* record = reinterpret_cast<USN_RECORD_V2*>(p);

            if (record->RecordLength < FIELD_OFFSET(USN_RECORD_V2, FileName) ||
                record->RecordLength > remaining) {
                return STATUS_DATA_ERROR;
            }

            if (record->MajorVersion == 2 &&
                record->FileReferenceNumber == fileRef &&
                (record->Reason & reasonBit) != 0) {

                found = true;
                return STATUS_SUCCESS;
            }

            if (record->MajorVersion != 2) {
                return STATUS_NOT_SUPPORTED;
            }

            p += record->RecordLength;
        }

        // Prevent an infinite loop if the journal doesn't advance.
        if (nextUsn <= startUsn) {
            return STATUS_DATA_ERROR;
        }

        startUsn = nextUsn;
    }

    return STATUS_SUCCESS;
}


static void OptionUsnTest()
{
    printf("\n=== USN Tracking Test ===\n\n");

    if (!IsElevated()) {
        printf("  Requires administrator privileges.\n");
        return;
    }

    wchar_t tempDir[MAX_PATH] = {};
    DWORD tempLength = GetTempPathW(MAX_PATH, tempDir);
    if (tempLength == 0 || tempLength >= MAX_PATH) {
        printf("  GetTempPathW failed: %lu\n", GetLastError());
        return;
    }

    std::wstring demoPath = std::wstring(tempDir) + L"ea_usn_demo.bin";

    {
        ScopedHandle h(CreateFileW(
            demoPath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));

        if (!h) {
            printf("  File creation failed: %lu\n", GetLastError());
            return;
        }

        DWORD written = 0;
        if (!WriteFile(h.get(), "USN", 3, &written, nullptr) ||
            written != 3) {
            printf("  Initial write failed: %lu\n", GetLastError());
            DeleteFileW(demoPath.c_str());
            return;
        }
    }

    USN_JOURNAL_DATA_V0 initialJournal{};
    DWORD ret = 0;
    DWORDLONG fileRef = 0;
    bool testReady = false;

    // Open the volume.
    ScopedHandle hVol;

    do {
        if (demoPath.size() < 2 || demoPath[1] != L':') {
            printf("  Test requires a drive-letter path.\n");
            break;
        }

        wchar_t volumeName[16] = {};

        _snwprintf_s(
            volumeName,
            _countof(volumeName),
            _TRUNCATE,
            L"\\\\.\\%c:",
            towupper(demoPath[0]));

        hVol = ScopedHandle(CreateFileW(
            volumeName,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr));

        if (!hVol) {
            printf("  Cannot open volume: %lu\n", GetLastError());
            break;
        }

        // Query existing journal.
        if (!DeviceIoControl(
            hVol.get(),
            FSCTL_QUERY_USN_JOURNAL,
            nullptr,
            0,
            &initialJournal,
            sizeof(initialJournal),
            &ret,
            nullptr)) {

            DWORD error = GetLastError();

            if (error != ERROR_JOURNAL_NOT_ACTIVE) {
                printf("  Cannot query USN journal: %lu\n", error);
                break;
            }

            // Create journal if absent.
            CREATE_USN_JOURNAL_DATA createData{};

            createData.MaximumSize = 16 * 1024 * 1024;
            createData.AllocationDelta = 4 * 1024 * 1024;

            if (!DeviceIoControl(
                hVol.get(),
                FSCTL_CREATE_USN_JOURNAL,
                &createData,
                sizeof(createData),
                nullptr,
                0,
                &ret,
                nullptr)) {

                printf("  Journal creation failed: %lu\n", GetLastError());
                break;
            }

            // Query again after creation.
            if (!DeviceIoControl(
                hVol.get(),
                FSCTL_QUERY_USN_JOURNAL,
                nullptr,
                0,
                &initialJournal,
                sizeof(initialJournal),
                &ret,
                nullptr)) {

                printf("  Journal query after creation failed: %lu\n", GetLastError());
                break;
            }
        }

        // Obtain the file reference number.
        {
            ScopedHandle h(CreateFileW(
                demoPath.c_str(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));

            if (!h) {
                printf("  Cannot open test file: %lu\n", GetLastError());
                break;
            }

            BY_HANDLE_FILE_INFORMATION info{};

            if (!GetFileInformationByHandle(
                h.get(), &info)) {

                printf("  File information query failed: %lu\n", GetLastError());
                break;
            }

            fileRef = (static_cast<DWORDLONG>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
        }

        testReady = true;

    } while (false);

    if (testReady) {

        // --------------------------------------------------
        // USER EA
        // --------------------------------------------------

        USN userStart = initialJournal.NextUsn;
        NTSTATUS userSet = SetUserEa(demoPath, "MVTest.USNUser", std::vector<UCHAR>{'u'});

        printf("  User EA set -> ");
        PrintStatus(userSet);
        printf("\n");

        if (NT_SUCCESS(userSet)) {

            USN_JOURNAL_DATA_V0 userEnd{};
            if (DeviceIoControl(
                hVol.get(),
                FSCTL_QUERY_USN_JOURNAL,
                nullptr,
                0,
                &userEnd,
                sizeof(userEnd),
                &ret,
                nullptr)) {

                bool found = false;

                NTSTATUS scan = UsnScanFor(
                    hVol.get(),
                    userEnd.UsnJournalID,
                    userStart,
                    userEnd.NextUsn,
                    fileRef,
                    USN_REASON_EA_CHANGE,
                    found);

                printf("  User EA USN scan -> ");
                PrintStatus(scan);
                printf("\n");

                Verdict("user EA change found in USN", NT_SUCCESS(scan) && found);
            }
            else {
                printf("  User journal refresh failed: %lu\n", GetLastError());
            }
        }

        // --------------------------------------------------
        // KERNEL EA
        // --------------------------------------------------

        USN_JOURNAL_DATA_V0 kernelStartData{};

        if (DeviceIoControl(
            hVol.get(),
            FSCTL_QUERY_USN_JOURNAL,
            nullptr,
            0,
            &kernelStartData,
            sizeof(kernelStartData),
            &ret,
            nullptr)) {

            USN kernelStart = kernelStartData.NextUsn;

            NTSTATUS kernelSet = IoctlSet(demoPath, "$Kernel.MVTest.USNKernel", std::vector<UCHAR>{'k'});

            printf("  Kernel EA set -> ");
            PrintStatus(kernelSet);
            printf("\n");

            if (NT_SUCCESS(kernelSet)) {

                USN_JOURNAL_DATA_V0 kernelEnd{};

                if (DeviceIoControl(
                    hVol.get(),
                    FSCTL_QUERY_USN_JOURNAL,
                    nullptr,
                    0,
                    &kernelEnd,
                    sizeof(kernelEnd),
                    &ret,
                    nullptr)) {

                    bool found = false;

                    NTSTATUS scan = UsnScanFor(
                        hVol.get(),
                        kernelEnd.UsnJournalID,
                        kernelStart,
                        kernelEnd.NextUsn,
                        fileRef,
                        USN_REASON_EA_CHANGE,
                        found);

                    printf("  Kernel EA USN scan -> ");
                    PrintStatus(scan);
                    printf("\n");

                    Verdict("kernel EA change absent from USN", NT_SUCCESS(scan) && !found);
                }
                else {
                    printf("  Kernel journal refresh failed: %lu\n", GetLastError());
                }
            }
        }
        else {
            printf("  Kernel journal query failed: %lu\n", GetLastError());
        }
    }

    // Cleanup regardless of experiment outcome.
    IoctlDeleteAllKernel(demoPath);
    DeleteUserEa(demoPath, "MVTest.USNUser");
    DeleteFileW(demoPath.c_str());
}


static void OptionPersistenceTest()
{
    printf("\n=== Reboot Persistence Test ===\n\n");
    printf("  (1) Prepare — set EAs and instruct to reboot\n");
    printf("  (2) Verify  — after reboot, check EAs are still present\n");
    std::string choice = ReadLine("Choice: ");
    if (choice.empty()) return;

    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    std::wstring markerPath = std::wstring(tempDir) + L"ea_demo_persist_path.txt";

    if (choice[0] == '1') {
        std::wstring path = NarrowToWide(
            ReadLine("File path (will be created/overwritten): "));
        if (path.empty()) return;
        {
            ScopedHandle h(CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!h) { printf("  Cannot create: %lu\n", GetLastError()); return; }
            DWORD w = 0; WriteFile(h.get(), "PERSIST", 7, &w, nullptr);
        }
        std::vector<UCHAR> v(16, 0x5A);
        NTSTATUS s1 = SetUserEa(path, "MVTest.PERSIST.USER", v);
        NTSTATUS s2 = IoctlSet(path, "$Kernel.MVTest.PERSIST.KERNEL", v);
        NTSTATUS s3 = IoctlSet(path, "$KERNEL.PURGE.MVTest.PERSIST.PURGE", v);
        printf("  user    -> "); PrintStatus(s1); printf("\n");
        printf("  kernel  -> "); PrintStatus(s2); printf("\n");
        printf("  purge   -> "); PrintStatus(s3); printf("\n");

        FILE* f = _wfopen(markerPath.c_str(), L"w");
        if (f) { fwprintf(f, L"%ls\n", path.c_str()); fclose(f); }
        printf("\n  Now reboot and run this menu, option (2) to verify.\n");
    }
    else if (choice[0] == '2') {
        FILE* f = _wfopen(markerPath.c_str(), L"r");
        if (!f) { printf("  No prepared file; run (1) first.\n"); return; }
        wchar_t wpath[MAX_PATH] = {};
        fgetws(wpath, MAX_PATH, f);
        fclose(f);
        std::wstring path = wpath;
        while (!path.empty() && (path.back() == L'\n' || path.back() == L'\r'))
            path.pop_back();
        if (path.empty() || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("  File missing: %ls\n", path.c_str()); return;
        }
        printf("  Checking %ls\n", path.c_str());
        Verdict("user EA present after reboot",
            EaPresent(path, "MVTest.PERSIST.USER"));
        Verdict("kernel EA present after reboot",
            EaPresent(path, "$Kernel.MVTest.PERSIST.KERNEL"));
        // purge EA is expected gone only if data was written; a reboot alone
        // does not purge. It should still be present unless the file was written.
        Verdict("purge EA present after reboot",
            EaPresent(path, "$KERNEL.PURGE.MVTest.PERSIST.PURGE"));
    }
}

// =====================================================================
// main
// =====================================================================
int main()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_NtQueryEaFile = (NtQueryEaFile_t)GetProcAddress(ntdll, "NtQueryEaFile");
    g_NtSetEaFile = (NtSetEaFile_t)GetProcAddress(ntdll, "NtSetEaFile");
    g_NtDeviceIoControlFile = (NtDeviceIoControlFile_t)GetProcAddress(ntdll, "NtDeviceIoControlFile");

    if (!g_NtQueryEaFile || !g_NtSetEaFile || !g_NtDeviceIoControlFile) {
        printf("Failed to resolve NTDLL exports\n");
        return 1;
    }

    g_hDevice = ScopedHandle(CreateFileW(
        L"\\\\.\\EaDemo",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!g_hDevice) {
        printf("Warning: cannot open \\\\.\\EaDemo (%lu). "
            "Kernel-EA operations will fail.\n", GetLastError());
    }

    bool running = true;
    while (running) {
        printf("\n=== Kernel EA Demo ===\n");
        printf(" 1) Set EA on file\n");
        printf(" 2) Get EAs of file\n");
        printf(" 3) Clear EA of file\n");
        printf(" 4) Run full demonstration (all findings)\n");
        printf(" 5) USN tracking test (needs admin)\n");
        printf(" 6) Reboot persistence test\n");
        printf(" 7) Exit\n");

        std::string choice = ReadLine("Choice: ");
        char c = choice.empty() ? '\0' : choice[0];
        switch (c) {
        case '1': OptionSetEa();            break;
        case '2': OptionGetEa();            break;
        case '3': OptionClearEa();          break;
        case '4': OptionFullDemo();         break;
        case '5': OptionUsnTest();          break;
        case '6': OptionPersistenceTest();  break;
        case '7': running = false;          break;
        default:  printf("Invalid\n");      break;
        }
    }
    return 0;
}