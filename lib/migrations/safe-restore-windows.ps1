param(
  [Parameter(Mandatory = $true)][string]$WorkspaceRoot
)

$ErrorActionPreference = 'Stop'

$source = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class ArmorBreakSafeMigrationRestore
{
    const uint FILE_READ_DATA = 0x0001;
    const uint FILE_WRITE_DATA = 0x0002;
    const uint FILE_LIST_DIRECTORY = 0x0001;
    const uint FILE_READ_ATTRIBUTES = 0x0080;
    const uint SYNCHRONIZE = 0x00100000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_OPEN = 1;
    const uint FILE_DIRECTORY_FILE = 0x00000001;
    const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
    const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    const uint OBJ_DONT_REPARSE = 0x00001000;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

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

    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(
        out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attributes,
        out IO_STATUS_BLOCK status, IntPtr allocationSize, uint fileAttributes,
        uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(int status);

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
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not identify opened migration object");
        return NormalizeFinalPath(buffer.ToString());
    }

    static BY_HANDLE_FILE_INFORMATION Info(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not inspect opened migration object");
        if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new IOException("migration path contains a reparse point");
        return info;
    }

    static bool IsUnder(string root, string candidate)
    {
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    static string[] Components(string relative)
    {
        if (String.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(":"))
            throw new IOException("migration path is not relative to the workspace");
        var parts = relative.Replace('/', '\\').Split('\\');
        foreach (var part in parts)
            if (String.IsNullOrWhiteSpace(part) || part == "." || part == "..")
                throw new IOException("migration path contains an unsafe component");
        return parts;
    }

    static SafeFileHandle OpenRelative(SafeFileHandle parent, string name, bool directory, bool writable)
    {
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
                Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK status;
            IntPtr raw;
            uint access = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            uint options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
                (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
            if (directory) access |= FILE_LIST_DIRECTORY;
            else access |= FILE_READ_DATA | (writable ? FILE_WRITE_DATA : 0);
            uint share = directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ;
            var result = NtCreateFile(out raw, access, ref attributes, out status, IntPtr.Zero, 0, share, FILE_OPEN, options, IntPtr.Zero, 0);
            if (result < 0)
            {
                var error = (int)RtlNtStatusToDosError(result);
                throw new Win32Exception(error, "safe handle-relative migration open was refused (NTSTATUS=0x" + result.ToString("X8") + ")");
            }
            var handle = new SafeFileHandle(raw, true);
            var info = Info(handle);
            if (directory && (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                handle.Dispose();
                throw new IOException("migration path component is not a directory");
            }
            if (!directory && ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1))
            {
                handle.Dispose();
                throw new IOException("migration target is not a single-link regular file");
            }
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(unicodePointer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    static SafeFileHandle OpenAbsoluteRoot(string path)
    {
        var handle = CreateFile(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "could not securely open migration workspace root");
        var info = Info(handle);
        if ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            handle.Dispose();
            throw new IOException("migration workspace root is not a directory");
        }
        return handle;
    }

    static SafeFileHandle OpenFileUnderRoot(
        SafeFileHandle rootHandle, string rootFinal, string relative, bool writable, List<SafeFileHandle> held)
    {
        var parts = Components(relative);
        var parent = rootHandle;
        string parentFinal = rootFinal;
        for (int i = 0; i < parts.Length - 1; i++)
        {
            var directory = OpenRelative(parent, parts[i], true, false);
            held.Add(directory);
            var final = FinalPath(directory);
            if (!IsUnder(rootFinal, final) || !IsUnder(parentFinal, final))
                throw new IOException("migration directory escaped the bound workspace root");
            parentFinal = final;
            parent = directory;
        }
        var file = OpenRelative(parent, parts[parts.Length - 1], false, writable);
        held.Add(file);
        var fileFinal = FinalPath(file);
        if (!IsUnder(rootFinal, fileFinal) || !IsUnder(parentFinal, fileFinal))
            throw new IOException("migration file escaped the bound workspace root");
        return file;
    }

    public static void Run(string workspaceRoot, string targetRelative, string backupRelative, string expectedHash, string action)
    {
        var fullRoot = Path.GetFullPath(workspaceRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = OpenAbsoluteRoot(fullRoot);
        var held = new List<SafeFileHandle>();
        try
        {
            var rootFinal = FinalPath(root);
            if (!rootFinal.Equals(fullRoot, StringComparison.OrdinalIgnoreCase))
                throw new IOException("migration workspace root identity changed");
            var source = OpenFileUnderRoot(root, rootFinal, backupRelative, false, held);
            var target = OpenFileUnderRoot(root, rootFinal, targetRelative, true, held);
            byte[] bytes;
            using (var sourceStream = new FileStream(source, FileAccess.Read, 65536, false))
            using (var memory = new MemoryStream())
            {
                sourceStream.CopyTo(memory);
                bytes = memory.ToArray();
            }
            using (var sha = SHA256.Create())
            {
                var actual = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
                if (!actual.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("migration backup hash mismatch");
            }
            using (var targetStream = new FileStream(target, FileAccess.ReadWrite, 65536, false))
            {
                targetStream.SetLength(0);
                if (action == "restore")
                {
                    targetStream.Write(bytes, 0, bytes.Length);
                    targetStream.Flush(true);
                }
                else
                {
                    targetStream.Flush(true);
                }
            }
        }
        finally
        {
            for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose();
            root.Dispose();
        }
    }
}
"@

try {
  Add-Type -TypeDefinition $source
  $payload = [Console]::In.ReadToEnd()
  $entries = ConvertFrom-Json -InputObject $payload
  if ($entries -isnot [System.Array]) { $entries = @($entries) }
  if ($entries.Count -eq 0) { throw 'migration restore batch is empty' }
  foreach ($entry in $entries) {
    if ($entry.action -ne 'restore' -and $entry.action -ne 'truncate') { throw 'migration restore action is invalid' }
    [ArmorBreakSafeMigrationRestore]::Run(
      $WorkspaceRoot,
      [string]$entry.targetRelative,
      [string]$entry.backupRelative,
      [string]$entry.expectedBackupSha256,
      [string]$entry.action
    )
  }
  [Console]::Out.WriteLine('SAFE_MIGRATION_RESTORE_OK')
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
