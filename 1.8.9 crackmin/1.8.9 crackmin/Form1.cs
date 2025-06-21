using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace _1._8._9_crackmin
{
    public partial class Form1 : Form
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        const uint PAGE_EXECUTE_READWRITE = 0x40;

        int[] offsets = new int[]
              {
                0x4E31F1,
                0x4E31FB  
            };
        byte[][] originalBytesArr = new byte[][]
            {
                   new byte[] { 0x42, 0x0F, 0x10, 0x44, 0x01, 0x10 }, 
                      new byte[] { 0x42, 0x0F, 0x10, 0x4C, 0x01, 0x20 }  
            };
        int[] offsets2 = new int[]
{
    0x4E31E9,
    0x4E3211
};
        byte[][] originalBytesArr2 = new byte[][]
{
    new byte[] { 0x49, 0x69, 0x48, 0x08, 0x14, 0x01, 0x00, 0x00 }, 
    new byte[] { 0x42, 0x0F, 0x10, 0x4C, 0x01, 0x40 }              
};

        int[] lengths2 = new int[] { 8, 6 };
        int[] lengths = new int[] { 6, 6 };

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, int size, out IntPtr bytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        Process targetProcess;
        IntPtr processHandle;
        private void PatchInit()
        {
            string targetProcessName = "javaw";
            Process[] processes = Process.GetProcessesByName(targetProcessName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"{targetProcessName} 프로세스를 찾을 수 없습니다.");
                return;
            }

            targetProcess = processes[0];
            processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);

            if (processHandle == IntPtr.Zero)
            {
                MessageBox.Show("프로세스 핸들 열기 실패. 관리자 권한으로 실행하세요.");
                return;
            }

           
            ProcessModule targetModule = targetProcess.Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(m => m.ModuleName.ToLower() == "atio6axx.dll");

            if (targetModule == null)
            {
                MessageBox.Show("atio6axx.dll 모듈을 찾을 수 없습니다.");
                return;
            }

            IntPtr baseAddress = targetModule.BaseAddress;

           
            patchAddresses = offsets.Select(offset => IntPtr.Add(baseAddress, offset)).ToArray();
            nopBytesArr = new byte[patchAddresses.Length][];
            for (int i = 0; i < patchAddresses.Length; i++)
            {
                nopBytesArr[i] = Enumerable.Repeat((byte)0x90, lengths[i]).ToArray();
            }

           
            patchAddresses2 = offsets2.Select(offset => IntPtr.Add(baseAddress, offset)).ToArray();
            nopBytesArr2 = new byte[patchAddresses2.Length][];
            for (int i = 0; i < patchAddresses2.Length; i++)
            {
                nopBytesArr2[i] = Enumerable.Repeat((byte)0x90, lengths2[i]).ToArray();
            }

         
            checkBox1.CheckedChanged += checkBox1_CheckedChanged;
            checkBox2.CheckedChanged += checkBox2_CheckedChanged;
        }

     
        IntPtr[] patchAddresses;
     
        byte[][] nopBytesArr;
       

        public Form1()
        {
            InitializeComponent();
            PatchInit(); 
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {

            if (processHandle == IntPtr.Zero) return;

            for (int i = 0; i < patchAddresses.Length; i++)
            {
                byte[] patchBytes = checkBox1.Checked ? nopBytesArr[i] : originalBytesArr[i];

               
                uint oldProtect;
                bool result = VirtualProtectEx(
                    processHandle,
                    patchAddresses[i],
                    (UIntPtr)patchBytes.Length,
                    PAGE_EXECUTE_READWRITE,
                    out oldProtect
                );

                if (!result)
                {
                    MessageBox.Show($"VirtualProtectEx 실패 - 주소: {patchAddresses[i].ToString("X")}");
                    continue;
                }

              
                bool writeResult = WriteProcessMemory(
                    processHandle,
                    patchAddresses[i],
                    patchBytes,
                    patchBytes.Length,
                    out _
                );

                if (!writeResult)
                {
                    MessageBox.Show($"WriteProcessMemory 실패 - 주소: {patchAddresses[i].ToString("X")}");
                }

               
                VirtualProtectEx(
                    processHandle,
                    patchAddresses[i],
                    (UIntPtr)patchBytes.Length,
                    oldProtect,
                    out _
                );
            }
        }


       
        private void Form1_Load(object sender, EventArgs e)
        {

        }
        IntPtr[] patchAddresses2;
        byte[][] nopBytesArr2;

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            if (processHandle == IntPtr.Zero) return;

            for (int i = 0; i < patchAddresses2.Length; i++)
            {
                byte[] patchBytes = checkBox2.Checked ? nopBytesArr2[i] : originalBytesArr2[i];

                uint oldProtect;
                if (!VirtualProtectEx(processHandle, patchAddresses2[i], (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    MessageBox.Show($"VirtualProtectEx 실패 - 주소: 0x{patchAddresses2[i].ToInt64():X}");
                    continue;
                }

                if (!WriteProcessMemory(processHandle, patchAddresses2[i], patchBytes, patchBytes.Length, out _))
                {
                    MessageBox.Show($"WriteProcessMemory 실패 - 주소: 0x{patchAddresses2[i].ToInt64():X}");
                }

                VirtualProtectEx(processHandle, patchAddresses2[i], (UIntPtr)patchBytes.Length, oldProtect, out _);
            }
        }
    }
}
