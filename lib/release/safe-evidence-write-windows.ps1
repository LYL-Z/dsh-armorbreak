param(
  [Parameter(Mandatory = $true)][string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

$source = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class ArmorBreakSafeEvidenceWriter
{
    const uint FILE_READ_DATA = 0x0001;
    const uint FILE_WRITE_DATA = 0x0002;
    const uint FILE_LIST_DIRECTORY = 0x0001;
    const uint FILE_READ_ATTRIBUTES = 0x0080;
    const uint DELETE = 0x00010000;
    const uint SYNCHRONIZE = 0x00100000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint OPEN_EXISTING = 3;
    const uint FILE_OPEN = 1;
    const uint FILE_CREATE = 2;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_DIRECTORY_FILE = 0x00000001;
    const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
    const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    const int FileDispositionInfo = 4;

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    static extern SafeFileHandle CreateFile(
        string name, uint access, uint share, IntPtr security, uint creation,
        uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle, System.Text.StringBuilder path, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle handle, byte[] buffer, uint count, out uint written, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, IntPtr info, uint size);

    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(
        out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attributes,
        out IO_STATUS_BLOCK status, IntPtr allocationSize, uint fileAttributes,
        uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(int status);

    [DllImport("ntdll.dll")]
    static extern int NtSetInformationFile(
        SafeFileHandle handle, out IO_STATUS_BLOCK status, IntPtr information,
        uint length, int informationClass);

    static string NormalizeFinalPath(string value)
    {
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + value.Substring(8);
        if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            return value.Substring(4);
        return value;
    }

    static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new System.Text.StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not identify opened evidence path");
        return NormalizeFinalPath(buffer.ToString()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    static BY_HANDLE_FILE_INFORMATION Info(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not inspect opened evidence object");
        if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new IOException("evidence path contains a reparse point");
        return info;
    }

    static bool IsDirectory(BY_HANDLE_FILE_INFORMATION info)
    {
        return (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    static bool IsUnder(string root, string candidate)
    {
        var normalizedRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var prefix = normalizedRoot + Path.DirectorySeparatorChar;
        return candidate.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    static string[] Components(string relative)
    {
        if (String.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(":") || relative.Contains("\\"))
            throw new IOException("evidence path is not a safe repository-relative path");
        var parts = relative.Split('/');
        foreach (var part in parts)
            if (String.IsNullOrWhiteSpace(part) || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" "))
                throw new IOException("evidence path contains an unsafe component");
        return parts;
    }

    static SafeFileHandle OpenRelative(SafeFileHandle parent, string name, bool directory, uint access, uint disposition)
    {
        if (String.IsNullOrWhiteSpace(name) || name.Contains("\\") || name.Contains("/") || name == "." || name == "..")
            throw new IOException("evidence path component is invalid");
        var nameBuffer = Marshal.StringToHGlobalUni(name);
        var unicode = new UNICODE_STRING {
            Length = checked((ushort)(name.Length * 2)),
            MaximumLength = checked((ushort)(name.Length * 2)),
            Buffer = nameBuffer
        };
        var unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        try
        {
            Marshal.StructureToPtr(unicode, unicodePointer, false);
            var attributes = new OBJECT_ATTRIBUTES {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodePointer,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK status;
            IntPtr raw;
            uint options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
                (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
            var result = NtCreateFile(out raw, access | FILE_READ_ATTRIBUTES | SYNCHRONIZE, ref attributes,
                out status, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                disposition, options, IntPtr.Zero, 0);
            if (result < 0)
            {
                var error = (int)RtlNtStatusToDosError(result);
                throw new Win32Exception(error, "handle-relative evidence operation for '" + name + "' was refused (Win32=" + error.ToString() + ", NTSTATUS=0x" + result.ToString("X8") + ")");
            }
            var handle = new SafeFileHandle(raw, true);
            try
            {
                var info = Info(handle);
                if (directory != IsDirectory(info)) throw new IOException("evidence object has an unexpected type");
                if (!directory && info.NumberOfLinks != 1) throw new IOException("evidence file has multiple hard links");
                return handle;
            }
            catch { handle.Dispose(); throw; }
        }
        finally
        {
            Marshal.FreeHGlobal(unicodePointer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    static SafeFileHandle OpenRootChain(string fullRoot, List<SafeFileHandle> held)
    {
        var volumeRoot = Path.GetPathRoot(fullRoot);
        if (String.IsNullOrWhiteSpace(volumeRoot)) throw new IOException("repository root has no supported volume root");
        var current = CreateFile(volumeRoot, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (current == null || current.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not open evidence volume root");
        held.Add(current);
        var rootInfo = Info(current);
        if (!IsDirectory(rootInfo)) throw new IOException("evidence volume root is not a directory");
        var parentFinal = FinalPath(current);
        var volumePrefix = volumeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var relative = fullRoot.StartsWith(volumePrefix, StringComparison.OrdinalIgnoreCase)
            ? fullRoot.Substring(volumePrefix.Length).Trim(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : String.Empty;
        if (relative.Length > 0)
        {
            foreach (var part in relative.Split(Path.DirectorySeparatorChar))
            {
                current = OpenRelative(current, part, true, FILE_LIST_DIRECTORY | FILE_WRITE_DATA, FILE_OPEN);
                held.Add(current);
                var final = FinalPath(current);
                if (!IsUnder(parentFinal, final))
                    throw new IOException("evidence root path escaped while opening components");
                parentFinal = final;
            }
        }
        if (!FinalPath(current).Equals(fullRoot, StringComparison.OrdinalIgnoreCase))
            throw new IOException("evidence root identity changed while opening");
        return current;
    }

    static void RenameHandleRelative(SafeFileHandle file, SafeFileHandle parent, string name)
    {
        // NtSetInformationFile's FileRenameInformation accepts a directory
        // handle in RootDirectory, so no path is re-resolved during replacement.
        var nameBytes = System.Text.Encoding.Unicode.GetBytes(name);
        var rootOffset = IntPtr.Size == 8 ? 8 : 4;
        var lengthOffset = rootOffset + IntPtr.Size;
        var nameOffset = lengthOffset + 4;
        var buffer = Marshal.AllocHGlobal(nameOffset + nameBytes.Length);
        try
        {
            for (int i = 0; i < nameOffset + nameBytes.Length; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteByte(buffer, 0, 1); // ReplaceIfExists
            Marshal.WriteIntPtr(buffer, rootOffset, parent.DangerousGetHandle());
            Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
            IO_STATUS_BLOCK status;
            var result = NtSetInformationFile(file, out status, buffer, (uint)(nameOffset + nameBytes.Length), 10);
            if (result < 0)
            {
                var error = (int)RtlNtStatusToDosError(result);
                throw new Win32Exception(error, "handle-relative evidence replacement failed (NTSTATUS=0x" + result.ToString("X8") + ")");
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static void MarkForDelete(SafeFileHandle file)
    {
        var buffer = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(buffer, 0, 1);
            if (!SetFileInformationByHandle(file, FileDispositionInfo, buffer, 1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "could not remove temporary evidence file by handle");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static void WriteBytes(SafeFileHandle file, byte[] bytes)
    {
        int offset = 0;
        while (offset < bytes.Length)
        {
            uint count = (uint)Math.Min(bytes.Length - offset, 1024 * 1024);
            byte[] chunk = new byte[count];
            Buffer.BlockCopy(bytes, offset, chunk, 0, (int)count);
            uint written;
            if (!WriteFile(file, chunk, count, out written, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "could not write temporary evidence file");
            if (written == 0) throw new IOException("evidence write made no progress");
            offset += (int)written;
        }
        if (!FlushFileBuffers(file)) throw new Win32Exception(Marshal.GetLastWin32Error(), "could not flush temporary evidence file");
    }

    public static void Run(string repoRoot, string relativePath, string base64)
    {
        var fullRoot = Path.GetFullPath(repoRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var parts = Components(relativePath);
        var held = new List<SafeFileHandle>();
        SafeFileHandle temporary = null;
        bool renamed = false;
        try
        {
            var parent = OpenRootChain(fullRoot, held);
            var rootFinal = FinalPath(parent);
            for (int i = 0; i < parts.Length - 1; i++)
            {
                var next = OpenRelative(parent, parts[i], true, FILE_LIST_DIRECTORY | FILE_WRITE_DATA, FILE_OPEN);
                held.Add(next);
                var final = FinalPath(next);
                if (!IsUnder(rootFinal, final) || !IsUnder(FinalPath(parent), final))
                    throw new IOException("evidence parent escaped the repository root");
                parent = next;
            }

            var targetName = parts[parts.Length - 1];
            try
            {
                using (var existing = OpenRelative(parent, targetName, false, 0, FILE_OPEN)) { }
            }
            catch (Win32Exception error)
            {
                if (error.NativeErrorCode != 2 && error.NativeErrorCode != 3) throw;
            }

            var temporaryName = "." + targetName + "." + Guid.NewGuid().ToString("N") + ".tmp";
            temporary = OpenRelative(parent, temporaryName, false, FILE_WRITE_DATA | DELETE, FILE_CREATE);
            var bytes = Convert.FromBase64String(base64);
            WriteBytes(temporary, bytes);
            var tempInfo = Info(temporary);
            ulong tempSize = ((ulong)tempInfo.FileSizeHigh << 32) | tempInfo.FileSizeLow;
            if (tempSize != (ulong)bytes.Length || tempInfo.NumberOfLinks != 1)
                throw new IOException("temporary evidence file identity or size changed");

            RenameHandleRelative(temporary, parent, targetName);
            renamed = true;
            using (var written = OpenRelative(parent, targetName, false, 0, FILE_OPEN))
            {
                var writtenInfo = Info(written);
                ulong writtenSize = ((ulong)writtenInfo.FileSizeHigh << 32) | writtenInfo.FileSizeLow;
                if (writtenSize != (ulong)bytes.Length || writtenInfo.NumberOfLinks != 1)
                    throw new IOException("evidence output size or link count changed after replacement (expected=" + bytes.Length.ToString() + ", actual=" + writtenSize.ToString() + ", links=" + writtenInfo.NumberOfLinks.ToString() + ")");
            }
            Console.Out.WriteLine("SAFE_EVIDENCE_WRITE_OK");
        }
        finally
        {
            if (!renamed && temporary != null && !temporary.IsInvalid && !temporary.IsClosed)
            {
                try { MarkForDelete(temporary); } catch { }
            }
            if (temporary != null) temporary.Dispose();
            for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose();
        }
    }
}
"@

try {
  Add-Type -TypeDefinition $source
  $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
  [ArmorBreakSafeEvidenceWriter]::Run(
    $RepoRoot,
    [string]$payload.relativePath,
    [string]$payload.base64
  )
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
