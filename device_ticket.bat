<# :
@REM BSD 3-Clause License
@REM 
@REM Copyright(c) 2023, echnobas
@REM All rights reserved.
@REM 
@REM Redistribution and use in source and binary forms, with or without
@REM modification, are permitted provided that the following conditions are met:
@REM 
@REM 1. Redistributions of source code must retain the above copynotice, this
@REM    list of conditions and the following disclaimer.
@REM 
@REM 2. Redistributions in binary form must reproduce the above copynotice,
@REM    this list of conditions and the following disclaimer in the documentation
@REM    and/or other materials provided with the distribution.
@REM 
@REM 3. Neither the name of the copyholder nor the names of its
@REM    contributors may be used to endorse or promote products derived from
@REM    this software without specific prior written permission.
@REM 
@REM THIS SOFTWARE IS PROVIDED BY THE COPYHOLDERS AND CONTRIBUTORS "AS IS"
@REM AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
@REM IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
@REM DISCLAIMED. IN NO EVENT SHALL THE COPYHOLDER OR CONTRIBUTORS BE LIABLE
@REM FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
@REM DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
@REM SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
@REM CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
@REM OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
@REM OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@echo off &chcp 850 >nul &pushd "%~dp0"
fltmc >nul 2>&1 || (
    powershell Start-Process -FilePath "%~f0" -ArgumentList "%cd%" -verb runas >NUL 2>&1
    exit /b
)
set "psScript=%~f0"
powershell -nop -c "& ([ScriptBlock]::Create((Get-Content """$env:psScript""" -Raw)))" & exit /b
: #>
###################################### SUBLICENSE BEGIN ######################################
# BSD 3-Clause License
#
# Copyright(c) 2019, Tobias Heilig
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copynotice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copynotice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyholder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYHOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYHOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
try {
    & {
        $ErrorActionPreference = 'Stop'
        [void] [impsys.win32]
    }
}
catch {
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        namespace impsys {
            public class win32 {

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern bool CloseHandle(
                    IntPtr hHandle);

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern IntPtr OpenProcess(
                    uint processAccess,
                    bool bInheritHandle,
                    int processId);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool OpenProcessToken(
                    IntPtr ProcessHandle, 
                    uint DesiredAccess,
                    out IntPtr TokenHandle);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool DuplicateTokenEx(
                    IntPtr hExistingToken,
                    uint dwDesiredAccess,
                    IntPtr lpTokenAttributes,
                    uint ImpersonationLevel,
                    uint TokenType,
                    out IntPtr phNewToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool ImpersonateLoggedOnUser(
                    IntPtr hToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool RevertToSelf();
            }
        }
"@
}

$winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id

if (($processHandle = [impsys.win32]::OpenProcess(
            0x400,
            $true,
            [Int32]$winlogonPid)) -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "$([ComponentModel.Win32Exception]$err)"
    Exit $err
}

$tokenHandle = [IntPtr]::Zero
if (-not [impsys.win32]::OpenProcessToken(
        $processHandle,
        0x0E,
        [ref]$tokenHandle)) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "$([ComponentModel.Win32Exception]$err)"
    Exit $err
}

$dupTokenHandle = [IntPtr]::Zero
if (-not [impsys.win32]::DuplicateTokenEx(
        $tokenHandle,
        0x02000000,
        [IntPtr]::Zero,
        0x02,
        0x01,
        [ref]$dupTokenHandle)) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "$([ComponentModel.Win32Exception]$err)"
    Exit $err
}

if (-not [impsys.win32]::ImpersonateLoggedOnUser(
        $dupTokenHandle)) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "$([ComponentModel.Win32Exception]$err)"
    Exit $err
}
###################################### SUBLICENSE   END ######################################

Add-Type -AssemblyName System.Security
$key = "registry::HKEY_USERS\S-1-5-19\Software\Microsoft\IdentityCRL\Immersive\production\Token\{D6D5A677-0872-4AB0-9442-BB792FCE85C5}"
$ticket = (Get-ItemProperty -Path $key)."DeviceTicket"
$raw = ([Text.Encoding]::Unicode).GetString([Security.Cryptography.ProtectedData]::Unprotect($ticket[4..$ticket.length], $Null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) -replace "^.*?t\=" -replace "\&p\=.*"

Set-Content -NoNewline -Path dev_tik.txt -Value "$raw"
