#include <ntifs.h>
#include <wdmsec.h>

#include "ea_ioctl.h"
#include "kernel_alloc.h"

#pragma comment(lib, "Wdmsec.lib")

#define DEVICE_NAME   L"\\Device\\EaDemo"
#define SYMLINK_NAME  L"\\??\\EaDemo"

#define EA_BUF_SIZE        0x10000
#define EA_MAX_QUERY_SIZE  0x100000
#define EA_NAME_MAX        255
#define EA_VALUE_MAX       65535

namespace {

	bool IsValidEaName(const CHAR* name, ULONG length)
	{
		if (!name || length == 0 || length >= 255) {
			return false;
		}

		static const CHAR invalidChars[] = "\\/:*?\"<>|,+=[];";

		for (ULONG i = 0; i < length; ++i) {

			UCHAR c = static_cast<UCHAR>(name[i]);

			if (c < 0x20 || c > 0x7E) {
				return false;
			}

			for (ULONG j = 0;
				j < sizeof(invalidChars) - 1;
				++j) {

				if (c == static_cast<UCHAR>(invalidChars[j])) {
					return false;
				}
			}
		}

		return true;
	}

	NTSTATUS ValidatePathBuffer(PCWSTR path, ULONG pathBytes)
	{
		if (!path ||
			pathBytes < sizeof(WCHAR) ||
			(pathBytes % sizeof(WCHAR)) != 0) {
			return STATUS_INVALID_PARAMETER;
		}

		SIZE_T chars = pathBytes / sizeof(WCHAR);

		// Require exactly one terminating NUL.
		if (path[chars - 1] != L'\0') {
			return STATUS_INVALID_PARAMETER;
		}

		for (SIZE_T i = 0; i + 1 < chars; ++i) {
			if (path[i] == L'\0') {
				return STATUS_INVALID_PARAMETER;
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ValidatePayloadLength(
		ULONG bufferLength,
		SIZE_T headerSize,
		const ULONG* fields,
		ULONG fieldCount)
	{
		if (bufferLength < headerSize) {
			return STATUS_BUFFER_TOO_SMALL;
		}

		SIZE_T remaining = bufferLength - headerSize;

		for (ULONG i = 0; i < fieldCount; ++i) {
			if (fields[i] > remaining) {
				return STATUS_BUFFER_TOO_SMALL;
			}

			remaining -= fields[i];
		}

		// This IOCTL contract does not permit trailing payload.
		if (remaining != 0) {
			return STATUS_INVALID_PARAMETER;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ValidateEaBuffer(
		PVOID buffer,
		ULONG length)
	{
		if (!buffer || length == 0) {
			return STATUS_INVALID_PARAMETER;
		}

		if ((reinterpret_cast<ULONG_PTR>(buffer) & 3u) != 0) {
			return STATUS_DATATYPE_MISALIGNMENT;
		}

		ULONG errorOffset = 0;

		return IoCheckEaBufferValidity(
			reinterpret_cast<PFILE_FULL_EA_INFORMATION>(buffer),
			length,
			&errorOffset);
	}

	static const GUID EADEMO_DEVICE_CLASS_GUID = {
		0x2ddba8c2, 0x7c13, 0x4e83, { 0xa1, 0x27, 0xb1, 0x5f, 0x9e, 0x23, 0x6d, 0x41 }
	};
}

namespace {

	// ---------- case-insensitive helpers ----------
	bool StartsWithICase(const char* s, ULONG len, const char* prefix) {
		ULONG pl = (ULONG)strlen(prefix);
		if (len < pl) return false;
		for (ULONG i = 0; i < pl; ++i) {
			char a = s[i], b = prefix[i];
			if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
			if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
			if (a != b) return false;
		}
		return true;
	}
	bool IsKernelPrefix(const char* n, ULONG len) {
		return StartsWithICase(n, len, "$Kernel.");
	}
	bool NameEqICase(const char* a, ULONG aLen, const char* b, ULONG bLen) {
		if (aLen != bLen) return false;
		for (ULONG i = 0; i < aLen; ++i) {
			char ca = a[i], cb = b[i];
			if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
			if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
			if (ca != cb) return false;
		}
		return true;
	}
	bool WideStartsWithICase(PCWSTR s, SIZE_T sLen, PCWSTR prefix) {
		SIZE_T pl = wcslen(prefix);
		if (sLen < pl) return false;
		for (SIZE_T i = 0; i < pl; ++i) {
			WCHAR a = s[i], b = prefix[i];
			if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
			if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
			if (a != b) return false;
		}
		return true;
	}

	// ---------- open file for EA work ----------

	NTSTATUS OpenFileForEa(
		PCWSTR path,
		ULONG pathBytes,
		KernelFile& outFile,
		KernelFileObject& outObj)
	{
		NTSTATUS st = ValidatePathBuffer(path, pathBytes);
		if (!NT_SUCCESS(st)) {
			return st;
		}

		SIZE_T n = pathBytes / sizeof(WCHAR) - 1;

		PCWSTR body = path;
		SIZE_T bodyChars = n;
		bool needPrefix = true;

		if (n >= 4 && WideStartsWithICase(path, n, L"\\\\?\\")) {

			body = path + 4;
			bodyChars = n - 4;
			needPrefix = true;
		}
		else if (n >= 4 && WideStartsWithICase(path, n, L"\\??\\")) {

			needPrefix = false;
		}
		else if (n >= 8 && WideStartsWithICase(path, n, L"\\Device\\")) {

			needPrefix = false;
		}

		SIZE_T prefixChars = needPrefix ? 4 : 0;

		if (bodyChars > (MAXUSHORT / sizeof(WCHAR)) - prefixChars - 1) {
			return STATUS_NAME_TOO_LONG;
		}

		SIZE_T totalChars = bodyChars + prefixChars;
		SIZE_T allocBytes = (totalChars + 1) * sizeof(WCHAR);

		if (allocBytes > MAXUSHORT) {
			return STATUS_NAME_TOO_LONG;
		}

		PWSTR w = static_cast<PWSTR>(Memory::Allocate(allocBytes, Memory::PoolType::Paged));

		if (!w) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		if (needPrefix) {
			RtlCopyMemory(w, L"\\??\\", 4 * sizeof(WCHAR));

			RtlCopyMemory(w + 4, body, bodyChars * sizeof(WCHAR));
		}
		else {
			RtlCopyMemory(w, body, bodyChars * sizeof(WCHAR));
		}

		w[totalChars] = L'\0';

		UNICODE_STRING us{};
		us.Buffer = w;
		us.Length = static_cast<USHORT>(totalChars * sizeof(WCHAR));
		us.MaximumLength = static_cast<USHORT>(allocBytes);

		OBJECT_ATTRIBUTES oa;

		InitializeObjectAttributes(
			&oa,
			&us,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			nullptr,
			nullptr);

		HANDLE h = nullptr;
		IO_STATUS_BLOCK iosb{};

		st = ZwOpenFile(
			&h,
			FILE_READ_EA | FILE_WRITE_EA | SYNCHRONIZE,
			&oa,
			&iosb,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_SYNCHRONOUS_IO_NONALERT);

		Memory::Free(w);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		outFile = KernelFile(h);

		st = outObj.Attach(h);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		return STATUS_SUCCESS;
	}


	// ---------- query / rebuild / set ----------

	NTSTATUS QueryAll(
		HANDLE file,
		UCHAR** outBuf,
		PULONG outLen)
	{
		if (!outBuf || !outLen) {
			return STATUS_INVALID_PARAMETER;
		}

		*outBuf = nullptr;
		*outLen = 0;

		ULONG capacity = EA_BUF_SIZE;

		while (capacity <= EA_MAX_QUERY_SIZE) {

			UCHAR* buf = static_cast<UCHAR*>(
				Memory::Allocate(capacity, Memory::PoolType::Paged));

			if (!buf) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IO_STATUS_BLOCK iosb{};

			NTSTATUS st = ZwQueryEaFile(
				file,
				&iosb,
				buf,
				capacity,
				FALSE,
				nullptr,
				0,
				nullptr,
				TRUE);

			if (st == STATUS_NO_EAS_ON_FILE) {
				Memory::Free(buf);
				return STATUS_SUCCESS;
			}

			if (st == STATUS_BUFFER_OVERFLOW ||
				st == STATUS_BUFFER_TOO_SMALL) {

				Memory::Free(buf);

				if (capacity == EA_MAX_QUERY_SIZE) {
					return st;
				}

				capacity *= 2;
				continue;
			}

			if (!NT_SUCCESS(st)) {
				Memory::Free(buf);
				return st;
			}

			if (iosb.Information > capacity) {
				Memory::Free(buf);
				return STATUS_DATA_ERROR;
			}

			ULONG actualLength = static_cast<ULONG>(iosb.Information);

			if (actualLength != 0) {
				NTSTATUS validation = ValidateEaBuffer(buf, actualLength);

				if (!NT_SUCCESS(validation)) {
					Memory::Free(buf);
					return validation;
				}
			}

			*outBuf = buf;
			*outLen = actualLength;

			return STATUS_SUCCESS;
		}

		return STATUS_BUFFER_OVERFLOW;
	}


	// Non-owning pointer into eaBuf.
	UCHAR* FindValue(
		const UCHAR* eaBuf,
		ULONG eaLen,
		const char* name,
		PULONG outValueLen)
	{
		if (!outValueLen) {
			return nullptr;
		}

		*outValueLen = 0;

		if (!eaBuf || !name || eaLen == 0) {
			return nullptr;
		}

		const ULONG nameLength = static_cast<ULONG>(strlen(name));

		ULONG offset = 0;

		while (offset < eaLen) {

			ULONG remaining = eaLen - offset;

			if (remaining < FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName) + 1) {
				return nullptr;
			}

			auto* ea = reinterpret_cast<const EA_FILE_FULL_EA_INFORMATION*>(eaBuf + offset);

			if (NameEqICase(ea->EaName, ea->EaNameLength, name, nameLength)) {
				*outValueLen = ea->EaValueLength;
				return const_cast<UCHAR*>(reinterpret_cast<const UCHAR*>(ea->EaName) + ea->EaNameLength + 1);
			}

			if (ea->NextEntryOffset == 0) {
				break;
			}

			if (ea->NextEntryOffset > remaining) {
				return nullptr;
			}

			offset += ea->NextEntryOffset;
		}

		return nullptr;
	}

	// Build a single FILE_FULL_EA_INFORMATION entry. Caller frees with delete[].
	// Returns nullptr on allocation failure; *trueLen is the unpadded entry size.
	static UCHAR* BuildSingleEa(
		const char* name,
		const UCHAR* value,
		ULONG valueLen,
		PULONG trueLen)
	{
		if (!trueLen) {
			return nullptr;
		}

		*trueLen = 0;

		if (!name || valueLen > EA_VALUE_MAX ||
			(valueLen != 0 && !value)) {
			return nullptr;
		}

		ULONG nameLen = static_cast<ULONG>(strlen(name));

		if (!IsValidEaName(name, nameLen)) {
			return nullptr;
		}

		const SIZE_T headerSize = static_cast<SIZE_T>(
			FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName));

		const SIZE_T nameSize = static_cast<SIZE_T>(nameLen);
		const SIZE_T valueSize = static_cast<SIZE_T>(valueLen);
		const SIZE_T maxSize = static_cast<SIZE_T>(MAXULONG);

		if (nameSize > maxSize - headerSize - 1 || valueSize > maxSize - headerSize - nameSize - 1) {
			return nullptr;
		}

		const SIZE_T entrySize = headerSize + nameSize + 1u + valueSize;

		if (entrySize > maxSize - 3u) {
			return nullptr;
		}

		const SIZE_T allocationSize = (entrySize + 3u) & ~static_cast<SIZE_T>(3u);

		UCHAR* buf = static_cast<UCHAR*>(
			Memory::Allocate(allocationSize, Memory::PoolType::Paged));

		if (!buf) {
			return nullptr;
		}
		*trueLen = static_cast<ULONG>(entrySize);

		RtlZeroMemory(buf, allocationSize);

		auto* ea = reinterpret_cast<EA_FILE_FULL_EA_INFORMATION*>(buf);

		ea->NextEntryOffset = 0;
		ea->Flags = 0;
		ea->EaNameLength = static_cast<UCHAR>(nameLen);
		ea->EaValueLength = static_cast<USHORT>(valueLen);

		RtlCopyMemory(ea->EaName, name, nameLen);

		ea->EaName[nameLen] = '\0';

		if (valueLen) {
			RtlCopyMemory(ea->EaName + nameLen + 1, value, valueLen);
		}

		return buf;
	}

	// Set or delete ONE kernel EA. Merge semantics: only `name` is touched.
	// value == nullptr && valueLen == 0  -> delete.
	static NTSTATUS KernelEaSetOrDelete(
		PFILE_OBJECT fileObj,
		const char* name,
		const UCHAR* value,
		ULONG valueLen)
	{
		if (!fileObj || !name) {
			return STATUS_INVALID_PARAMETER;
		}

		ULONG trueLen = 0;
		UCHAR* buf = BuildSingleEa(name, value, valueLen, &trueLen);

		if (!buf) {
			return STATUS_INVALID_PARAMETER;
		}

		NTSTATUS st = FsRtlSetKernelEaFile(
			fileObj,
			reinterpret_cast<PFILE_FULL_EA_INFORMATION>(buf),
			trueLen);

		DbgPrint("EaDemo: FsRtlSetKernelEaFile(%s) -> 0x%08X\n", name, st);

		Memory::Free(buf);
		return st;
	}

	// Delete every existing $Kernel.* EA on the file.

	static NTSTATUS DeleteAllKernelEas(
		PFILE_OBJECT fileObj,
		HANDLE fileHandle)
	{
		UCHAR* src = nullptr;
		ULONG srcLen = 0;

		NTSTATUS st = QueryAll(fileHandle, &src, &srcLen);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		if (srcLen == 0) {
			Memory::Free(src);
			return STATUS_SUCCESS;
		}

		SIZE_T total = 0;
		ULONG count = 0;

		// Pass 1: calculate the size of all kernel EA deletion records.
		ULONG offset = 0;

		while (offset < srcLen) {

			auto* ea = reinterpret_cast<EA_FILE_FULL_EA_INFORMATION*>(src + offset);

			if (IsKernelPrefix(ea->EaName, ea->EaNameLength)) {

				SIZE_T entrySize =
					FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName) + ea->EaNameLength + 1;

				SIZE_T aligned = (entrySize + 3u) & ~(SIZE_T)3u;

				if (aligned > MAXULONG - total) {
					Memory::Free(src);
					return STATUS_INTEGER_OVERFLOW;
				}

				total += aligned;
				++count;
			}

			if (ea->NextEntryOffset == 0) {
				break;
			}

			offset += ea->NextEntryOffset;
		}

		if (count == 0) {
			Memory::Free(src);
			return STATUS_SUCCESS;
		}

		UCHAR* dst = static_cast<UCHAR*>(
			Memory::Allocate(total, Memory::PoolType::Paged));

		if (!dst) {
			Memory::Free(src);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(dst, total);

		ULONG outOffset = 0;
		ULONG lastStart = MAXULONG;
		ULONG lastTrue = 0;

		offset = 0;

		// Pass 2: build explicit zero-value deletion records.
		while (offset < srcLen) {

			auto* ea = reinterpret_cast<
				EA_FILE_FULL_EA_INFORMATION*>(src + offset);

			if (IsKernelPrefix(ea->EaName, ea->EaNameLength)) {

				ULONG entrySize =
					FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName) + ea->EaNameLength + 1;

				ULONG aligned = (entrySize + 3u) & ~3u;

				if (lastStart != MAXULONG) {
					reinterpret_cast<
						EA_FILE_FULL_EA_INFORMATION*>(dst + lastStart)->NextEntryOffset = outOffset - lastStart;
				}

				lastStart = outOffset;
				lastTrue = entrySize;

				auto* next = reinterpret_cast<EA_FILE_FULL_EA_INFORMATION*>(dst + outOffset);

				next->NextEntryOffset = 0;
				next->Flags = 0;
				next->EaNameLength = ea->EaNameLength;
				next->EaValueLength = 0;

				RtlCopyMemory(next->EaName, ea->EaName, ea->EaNameLength);

				next->EaName[ea->EaNameLength] = '\0';

				outOffset += aligned;
			}

			if (ea->NextEntryOffset == 0) {
				break;
			}

			offset += ea->NextEntryOffset;
		}

		ULONG trueLen = lastStart + lastTrue;
		st = ValidateEaBuffer(dst, trueLen);

		if (NT_SUCCESS(st)) {
			st = FsRtlSetKernelEaFile(
				fileObj,
				reinterpret_cast<PFILE_FULL_EA_INFORMATION>(dst),
				trueLen);
		}

		DbgPrint("EaDemo: DeleteAllKernelEas(%lu) -> 0x%08X\n", count, st);

		Memory::Free(dst);
		Memory::Free(src);

		return st;
	}


	// ---------- IOCTL handlers ----------
	NTSTATUS HandleSet(PVOID buf, ULONG len)
	{
		if (!buf) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* in = static_cast<EA_IOCTL_SET_INPUT*>(buf);

		ULONG fields[] = {
			in->PathBytes,
			in->NameBytes,
			in->ValueBytes
		};

		NTSTATUS st = ValidatePayloadLength(
			len, sizeof(*in), fields, RTL_NUMBER_OF(fields));

		if (!NT_SUCCESS(st)) {
			return st;
		}

		if (in->NameBytes >= EA_NAME_MAX ||
			in->ValueBytes > EA_VALUE_MAX) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto* name = reinterpret_cast<PCHAR>(
			reinterpret_cast<UCHAR*>(path) + in->PathBytes);

		auto* value = reinterpret_cast<UCHAR*>(name) + in->NameBytes;

		if (!IsValidEaName(name, in->NameBytes)) {
			return STATUS_INVALID_EA_NAME;
		}

		char localName[EA_NAME_MAX] = {};

		RtlCopyMemory(localName, name, in->NameBytes);

		if (!IsKernelPrefix(localName, in->NameBytes)) {
			return STATUS_INVALID_PARAMETER;
		}

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		return KernelEaSetOrDelete(
			fileObj.get(),
			localName,
			value,
			in->ValueBytes);
	}

	NTSTATUS HandleGet(PVOID buf, ULONG len, PULONG outLen, ULONG outBufCap)
	{
		if (!buf || !outLen) {
			return STATUS_INVALID_PARAMETER;
		}

		*outLen = 0;

		auto* in = static_cast<EA_IOCTL_NAME_INPUT*>(buf);

		ULONG fields[] = {
			in->PathBytes,
			in->NameBytes
		};

		NTSTATUS st = ValidatePayloadLength(
			len, sizeof(*in), fields, RTL_NUMBER_OF(fields));

		if (!NT_SUCCESS(st)) {
			return st;
		}

		if (in->NameBytes >= EA_NAME_MAX) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto* name = reinterpret_cast<PCHAR>(
			reinterpret_cast<UCHAR*>(path) + in->PathBytes);

		if (!IsValidEaName(name, in->NameBytes)) {
			return STATUS_INVALID_EA_NAME;
		}

		char localName[EA_NAME_MAX] = {};

		RtlCopyMemory(localName, name, in->NameBytes);

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		UCHAR* eaBuf = nullptr;
		ULONG eaLen = 0;

		st = QueryAll(file.get(), &eaBuf, &eaLen);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		ULONG foundLen = 0;

		UCHAR* foundVal = FindValue(
			eaBuf, eaLen, localName, &foundLen);

		if (!foundVal) {
			Memory::Free(eaBuf);
			return STATUS_NOT_FOUND;
		}

		SIZE_T needed =
			sizeof(EA_IOCTL_GET_OUTPUT) + foundLen;

		if (needed > outBufCap) {
			Memory::Free(eaBuf);
			return STATUS_BUFFER_TOO_SMALL;
		}

		auto* out = static_cast<EA_IOCTL_GET_OUTPUT*>(buf);

		out->ValueBytes = foundLen;

		if (foundLen) {
			RtlCopyMemory(
				static_cast<UCHAR*>(buf) + sizeof(*out),
				foundVal,
				foundLen);
		}

		*outLen = static_cast<ULONG>(needed);

		Memory::Free(eaBuf);

		return STATUS_SUCCESS;
	}

	NTSTATUS HandleDelete(PVOID buf, ULONG len)
	{
		if (!buf) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* in = static_cast<EA_IOCTL_NAME_INPUT*>(buf);

		ULONG fields[] = {
			in->PathBytes,
			in->NameBytes
		};

		NTSTATUS st = ValidatePayloadLength(
			len, sizeof(*in), fields, RTL_NUMBER_OF(fields));

		if (!NT_SUCCESS(st)) {
			return st;
		}

		if (in->NameBytes >= EA_NAME_MAX) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto* name = reinterpret_cast<PCHAR>(
			reinterpret_cast<UCHAR*>(path) + in->PathBytes);

		if (!IsValidEaName(name, in->NameBytes)) {
			return STATUS_INVALID_EA_NAME;
		}

		char localName[EA_NAME_MAX] = {};

		RtlCopyMemory(localName, name, in->NameBytes);

		// This IOCTL deliberately manages kernel EAs only.
		if (!IsKernelPrefix(localName, in->NameBytes)) {
			return STATUS_INVALID_PARAMETER;
		}

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		return KernelEaSetOrDelete(
			fileObj.get(),
			localName,
			nullptr,
			0);
	}

	NTSTATUS HandleDeleteAllKernel(PVOID buf, ULONG len)
	{
		if (!buf) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* in = static_cast<EA_IOCTL_PATH_INPUT*>(buf);

		ULONG fields[] = {
			in->PathBytes
		};

		NTSTATUS st = ValidatePayloadLength(
			len, sizeof(*in), fields, RTL_NUMBER_OF(fields));

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		return DeleteAllKernelEas(
			fileObj.get(), file.get());
	}

	NTSTATUS HandleSetViaZw(PVOID buf, ULONG len)
	{
		if (!buf) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* in = static_cast<EA_IOCTL_SET_INPUT*>(buf);

		ULONG fields[] = {
			in->PathBytes,
			in->NameBytes,
			in->ValueBytes
		};

		NTSTATUS st = ValidatePayloadLength(
			len, sizeof(*in), fields, RTL_NUMBER_OF(fields));

		if (!NT_SUCCESS(st)) {
			return st;
		}

		if (in->NameBytes >= EA_NAME_MAX ||
			in->ValueBytes > EA_VALUE_MAX) {
			return STATUS_INVALID_PARAMETER;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto* name = reinterpret_cast<PCHAR>(
			reinterpret_cast<UCHAR*>(path) + in->PathBytes);

		auto* value = reinterpret_cast<UCHAR*>(name) + in->NameBytes;

		if (!IsValidEaName(name, in->NameBytes)) {
			return STATUS_INVALID_EA_NAME;
		}

		char localName[EA_NAME_MAX] = {};

		RtlCopyMemory(localName, name, in->NameBytes);

		if (!IsKernelPrefix(localName, in->NameBytes)) {
			return STATUS_INVALID_PARAMETER;
		}

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		UCHAR* oldBuf = nullptr;
		ULONG oldLen = 0;

		st = QueryAll(file.get(), &oldBuf, &oldLen);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		auto Align4 = [](SIZE_T n) -> SIZE_T {
			return (n + 3u) & ~(SIZE_T)3u;
		};

		SIZE_T nameLen = in->NameBytes;

		SIZE_T entryLen =
			FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
			+ nameLen + 1 + in->ValueBytes;

		SIZE_T capacity = Align4(entryLen);

		// Calculate the capacity of retained user EA entries.
		ULONG offset = 0;

		while (offset < oldLen) {

			auto* ea = reinterpret_cast<
				EA_FILE_FULL_EA_INFORMATION*>(oldBuf + offset);

			if (!IsKernelPrefix(ea->EaName, ea->EaNameLength)) {

				SIZE_T e =
					FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
					+ ea->EaNameLength + 1
					+ ea->EaValueLength;

				SIZE_T aligned = Align4(e);

				if (aligned > MAXULONG - capacity) {
					Memory::Free(oldBuf);
					return STATUS_INTEGER_OVERFLOW;
				}

				capacity += aligned;
			}

			if (ea->NextEntryOffset == 0) {
				break;
			}

			offset += ea->NextEntryOffset;
		}

		UCHAR* newBuf = static_cast<UCHAR*>(
			Memory::Allocate(
				capacity,
				Memory::PoolType::Paged));

		if (!newBuf) {
			Memory::Free(oldBuf);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(newBuf, capacity);

		ULONG outOffset = 0;
		ULONG lastStart = MAXULONG;

		offset = 0;

		// Copy existing user EAs.
		while (offset < oldLen) {

			auto* ea = reinterpret_cast<
				EA_FILE_FULL_EA_INFORMATION*>(oldBuf + offset);

			if (!IsKernelPrefix(ea->EaName, ea->EaNameLength)) {

				ULONG e =
					FIELD_OFFSET(EA_FILE_FULL_EA_INFORMATION, EaName)
					+ ea->EaNameLength + 1
					+ ea->EaValueLength;

				ULONG aligned = static_cast<ULONG>(Align4(e));

				if (lastStart != MAXULONG) {
					reinterpret_cast<
						EA_FILE_FULL_EA_INFORMATION*>(
							newBuf + lastStart)
						->NextEntryOffset = outOffset - lastStart;
				}

				lastStart = outOffset;

				RtlCopyMemory(newBuf + outOffset, ea, e);

				if (aligned > e) {
					RtlZeroMemory(
						newBuf + outOffset + e,
						aligned - e);
				}

				outOffset += aligned;
			}

			if (ea->NextEntryOffset == 0) {
				break;
			}

			offset += ea->NextEntryOffset;
		}

		// Append requested kernel EA.
		auto* next = reinterpret_cast<
			EA_FILE_FULL_EA_INFORMATION*>(newBuf + outOffset);

		if (lastStart != MAXULONG) {
			reinterpret_cast<
				EA_FILE_FULL_EA_INFORMATION*>(newBuf + lastStart)
				->NextEntryOffset = outOffset - lastStart;
		}

		next->NextEntryOffset = 0;
		next->Flags = 0;
		next->EaNameLength = static_cast<UCHAR>(nameLen);
		next->EaValueLength = static_cast<USHORT>(in->ValueBytes);

		RtlCopyMemory(next->EaName, localName, nameLen);
		next->EaName[nameLen] = '\0';

		if (in->ValueBytes) {
			RtlCopyMemory(
				next->EaName + nameLen + 1,
				value,
				in->ValueBytes);
		}

		ULONG finalLength = outOffset + static_cast<ULONG>(entryLen);

		st = ValidateEaBuffer(newBuf, finalLength);

		if (NT_SUCCESS(st)) {
			IO_STATUS_BLOCK iosb{};

			st = ZwSetEaFile(
				file.get(),
				&iosb,
				newBuf,
				finalLength);

			if (st == STATUS_SUCCESS && !NT_SUCCESS(iosb.Status)) {
				st = iosb.Status;
			}
		}

		Memory::Free(newBuf);
		Memory::Free(oldBuf);

		return st;
	}

	NTSTATUS HandleRawFsRtl(PVOID buf, ULONG len)
	{
		if (!buf || len < sizeof(EA_IOCTL_RAW_INPUT)) {
			return STATUS_BUFFER_TOO_SMALL;
		}

		auto* in = static_cast<EA_IOCTL_RAW_INPUT*>(buf);

		if (in->PathBytes > len - sizeof(*in)) {
			return STATUS_BUFFER_TOO_SMALL;
		}

		auto* path = reinterpret_cast<PWSTR>(
			static_cast<UCHAR*>(buf) + sizeof(*in));

		NTSTATUS st = ValidatePathBuffer(path, in->PathBytes);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		SIZE_T pathEnd = sizeof(*in) + in->PathBytes;
		SIZE_T expectedOffset = (pathEnd + 3u) & ~(SIZE_T)3u;

		if (expectedOffset > MAXULONG ||
			in->EaOffset != expectedOffset) {
			return STATUS_INVALID_PARAMETER;
		}

		if (in->EaOffset > len ||
			in->EaBufferBytes > len - in->EaOffset) {
			return STATUS_BUFFER_TOO_SMALL;
		}

		if (in->EaBufferBytes == 0 ||
			in->EaOffset + in->EaBufferBytes != len) {
			return STATUS_INVALID_PARAMETER;
		}

		UCHAR* rawEa = static_cast<UCHAR*>(buf) + in->EaOffset;

		if ((reinterpret_cast<ULONG_PTR>(rawEa) & 3u) != 0) {
			return STATUS_DATATYPE_MISALIGNMENT;
		}

		// Copy the input to a stable, aligned kernel allocation.
		UCHAR* validatedEa = static_cast<UCHAR*>(
			Memory::Allocate(
				in->EaBufferBytes,
				Memory::PoolType::Paged));

		if (!validatedEa) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory(
			validatedEa,
			rawEa,
			in->EaBufferBytes);

		st = ValidateEaBuffer(
			validatedEa,
			in->EaBufferBytes);

		if (!NT_SUCCESS(st)) {
			Memory::Free(validatedEa);
			return st;
		}

		KernelFile file;
		KernelFileObject fileObj;

		st = OpenFileForEa(
			path, in->PathBytes, file, fileObj);

		if (!NT_SUCCESS(st)) {
			Memory::Free(validatedEa);
			return st;
		}

		st = FsRtlSetKernelEaFile(
			fileObj.get(),
			reinterpret_cast<PFILE_FULL_EA_INFORMATION>(
				validatedEa),
			in->EaBufferBytes);

		Memory::Free(validatedEa);

		return st;
	}


	// ---------- driver plumbing ----------
	NTSTATUS DispatchCreateClose(PDEVICE_OBJECT, PIRP Irp)
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT, PIRP Irp)
	{
		PAGED_CODE();

		auto* sp = IoGetCurrentIrpStackLocation(Irp);

		ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;

		PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;

		ULONG inLen =
			sp->Parameters.DeviceIoControl.InputBufferLength;

		ULONG outCap =
			sp->Parameters.DeviceIoControl.OutputBufferLength;

		ULONG outLen = 0;

		NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
			st = STATUS_INVALID_DEVICE_STATE;
			goto complete;
		}

		if ((inLen != 0 || outCap != 0) && !sysBuf) {
			st = STATUS_INVALID_PARAMETER;
			goto complete;
		}

		ULONG requiredAccess = 0;

		switch (code) {

		case IOCTL_EA_GET:
			requiredAccess = FILE_READ_ACCESS;
			break;

		case IOCTL_EA_SET:
		case IOCTL_EA_DELETE:
		case IOCTL_EA_DELETE_ALL_KERNEL:
		case IOCTL_EA_SET_VIA_ZW:
		case IOCTL_EA_RAW_FSRTL:
			requiredAccess = FILE_WRITE_ACCESS;
			break;

		default:
			st = STATUS_INVALID_DEVICE_REQUEST;
			goto complete;
		}

		st = IoValidateDeviceIoControlAccess(
			Irp,
			requiredAccess);

		if (!NT_SUCCESS(st)) {
			goto complete;
		}

		switch (code) {

		case IOCTL_EA_SET:
			st = HandleSet(sysBuf, inLen);
			break;

		case IOCTL_EA_GET:
			st = HandleGet(
				sysBuf,
				inLen,
				&outLen,
				outCap);
			break;

		case IOCTL_EA_DELETE:
			st = HandleDelete(sysBuf, inLen);
			break;

		case IOCTL_EA_DELETE_ALL_KERNEL:
			st = HandleDeleteAllKernel(sysBuf, inLen);
			break;

		case IOCTL_EA_SET_VIA_ZW:
			st = HandleSetViaZw(sysBuf, inLen);
			break;

		case IOCTL_EA_RAW_FSRTL:
			st = HandleRawFsRtl(sysBuf, inLen);
			break;
		}

	complete:

		Irp->IoStatus.Status = st;
		Irp->IoStatus.Information =
			NT_SUCCESS(st) ? outLen : 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return st;
	}

	void DriverUnload(PDRIVER_OBJECT drv)
	{
		UNICODE_STRING sl;
		RtlInitUnicodeString(&sl, SYMLINK_NAME);
		IoDeleteSymbolicLink(&sl);
		IoDeleteDevice(drv->DeviceObject);
	}

} // namespace


	extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING)
	{
		UNICODE_STRING devName;
		UNICODE_STRING symLink;
		UNICODE_STRING sddl;

		PDEVICE_OBJECT devObj = nullptr;

		RtlInitUnicodeString(&devName, DEVICE_NAME);
		RtlInitUnicodeString(&symLink, SYMLINK_NAME);

		// SYSTEM and Administrators only.
		RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

		NTSTATUS st = IoCreateDeviceSecure(
			drv,
			0,
			&devName,
			static_cast<DEVICE_TYPE>(EA_IOCTL_DEVICE_TYPE),
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&sddl,
			&EADEMO_DEVICE_CLASS_GUID,
			&devObj);

		if (!NT_SUCCESS(st)) {
			return st;
		}

		st = IoCreateSymbolicLink(&symLink, &devName);

		if (!NT_SUCCESS(st)) {
			IoDeleteDevice(devObj);
			return st;
		}

		drv->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
		drv->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
		drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
		drv->DriverUnload = DriverUnload;

		// Make the device available only after initialization.
		devObj->Flags &= ~DO_DEVICE_INITIALIZING;

		return STATUS_SUCCESS;
	}
