 Assignment 3: Malware Analysis in Virtual Machines & Basic Dynamic Analysis

**Student:** Kyle Versluis
**Date:** March 30, 2026
**Course:** CYBV 454 - Malware Analysis
**Environment:** FLARE-VM (Windows 10, Build 26100) running in Parallels Desktop, host-only networking

---

# PART 1: Dynamic Malware Analysis Report

## 1. Introduction

This report documents the static and dynamic analysis of two malware samples provided for Assignment 3 of CYBV 454. The samples were analyzed within an isolated FLARE-VM environment configured with host-only networking to prevent any network propagation or command-and-control (C2) communication beyond the analysis environment.

### Samples Analyzed

| Sample | Original Filename | File Type | Size |
|--------|------------------|-----------|------|
| Malware2.bin | Lecture2.bin | PE32 (.NET, C#) | 11.50 KiB |
| Malware3.bin | HOW TO BACK YOUR FILES.bin | PE32 (Native C/C++) | 28.00 KiB |

### Analysis Tools

The following tools were used during this analysis:

**Static Analysis:** PEStudio 9.61, Detect It Easy (DiE) v3.10, FLARE FLOSS v3.1.1, Capa

**Dynamic Analysis:** Process Hacker, Process Explorer, Wireshark, Regshot, TCPView, Autoruns, API Monitor

**Tool Substitution Note:** Process Monitor (ProcMon) and FakeNet-NG could not be utilized during this analysis due to persistent kernel driver load failures on the FLARE-VM instance. Both tools rely on kernel-mode drivers (PROCMON24.sys and WinDivert.sys respectively) that were blocked by Windows Hypervisor-Protected Code Integrity (HVCI / Memory Integrity). This error persisted despite multiple remediation attempts including Test Mode enablement (`bcdedit /set testsigning on`), group policy modifications for driver signing, disabling Windows Defender Device Security, disabling Core Isolation and LSA Protection, disabling the Microsoft Vulnerable Driver Blocklist, modifying HVCI registry keys under `DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, and reinstallation via Chocolatey. To maintain equivalent analysis coverage, the following tools were substituted: Process Hacker (process tree, handles, network connections, I/O activity), API Monitor (Windows API call tracing for file, registry, and network operations), Wireshark combined with TCPView (network traffic capture and live connection monitoring).

*See Figure 1: Pre-execution analysis environment showing all monitoring tools open and baselined below*
<img width="1924" height="1076" alt="Figure1" src="https://github.com/user-attachments/assets/609afb87-0636-4125-902a-0c9db8cfaa7b" />


---

## 2. Static Analysis Results

### 2.1 Malware2.bin (Lecture2.bin) - Static Findings

#### PEStudio Analysis

PEStudio identified 24 indicators for this sample. Key findings:

- **File Signature:** Microsoft Linker 48.0 | Microsoft.NET
- **SHA-256:** `E74567B575FF61B948CA3E4D41C2A488C67F09BCC29DE5E35302716D63796C54`
- **Compilation Timestamp:** Wed Nov 25 11:49:37 2020
- **File Type:** Executable, 64-bit, GUI (PE32 .NET assembly running in 64-bit mode)
- **Entropy:** 5.067 (not packed)
- **.NET Module Name:** Shamoon.exe
- **File Description:** Shamoon, Version 4.0.0.0
- **Flagged Imports (3):** `WriteFile`, `GetRandomFileName`, `RandomNumberGenerator` — indicating file manipulation with randomized naming and cryptographic random number generation
- **Libraries:** kernel32 (via P/Invoke), mscoree.dll (.NET runtime)
- **Strings (435):** Contained references to `Shamoon`, `Gutmann`, `WipePass`, `PhysicalDrive`, `System.Security.Cryptography`, file system enumeration methods (`GetDrives`, `GetFiles`, `GetDirectories`), and process management (`ProcessStartInfo`, `set_Arguments`)

*See screenshots: Malware2-indicators.png, Malware2-imports.png, Malware2-strings.png, Malware2-sections.png below*
<img width="1199" height="747" alt="Malware3-indicators" src="https://github.com/user-attachments/assets/0a7ee301-6b3f-423a-9242-cce89944cd02" />
<img width="1198" height="966" alt="Malware2-imports" src="https://github.com/user-attachments/assets/10213511-0cdb-495e-8c56-8a2154d9cd25" />
<img width="1198" height="966" alt="Malware2-strings" src="https://github.com/user-attachments/assets/b7caaed6-a3f5-4ae1-928e-566f256a11dd" />
<img width="1198" height="966" alt="Malware2-sections" src="https://github.com/user-attachments/assets/20f86586-8b8b-456e-b118-b136dbdaffd6" />


#### Detect It Easy (DiE)

- **File Type:** PE32
- **Size:** 11.50 KiB
- **Operation System:** Windows(95)[I386, 32-bit, GUI]
- **Linker:** Microsoft Linker
- **Language:** C#
- **Library:** .NET Framework (Legacy, CLR v2.0.50727)
- **Tool:** Visual Studio
- **Packer Detection:** None — the sample is not packed
- **Debug Data:** PDB file link present (RSDS format)

*See screenshot: Malware2-DiE.png below*
<img width="1004" height="664" alt="Malware2-DiE" src="https://github.com/user-attachments/assets/99ace32b-6dd9-45a6-a4e0-aa731a755cd6" />


#### FLOSS String Analysis

FLOSS extracted 246 static strings (215 ASCII, 31 UTF-16LE) from the sample. Notable findings:

**UTF-16LE Strings (high-value indicators):**
- `Shamoon.Properties.Resources` — internal resource namespace
- `C:\Python27` — Python installation reference
- `\\.\PhysicalDrive` — raw disk device access path (critical: enables MBR/disk-level destruction)
- `/C choice /C Y /N /D Y /T 3 & Del` — self-deletion command via cmd.exe with 3-second delay
- `cmd.exe`, `windows`, `system volume information`
- `Shamoon` — self-identification in multiple contexts (CompanyName, FileDescription, ProductName)
- `Shamoon.exe` — internal name and original filename
- `Open source licensing` — copyright string
- `C:\Users\Arnav\Desktop\Shamoon-4-master\Shamoon 4\obj\Debug\Shamoon.pdb` — PDB debug path revealing the developer username "Arnav" and project structure
- `From Iran with love. - Shamoon 4` — attribution string referencing Iranian origin
- `_CorExeMain`, `mscoree.dll` — .NET runtime entry points

**ASCII Strings (functional indicators):**
- `System.IO`, `FileStream`, `FileMode`, `FileShareRead`, `FileShareWrite`, `GenericWrite` — file I/O operations
- `System.Security.Cryptography`, `RNGCryptoServiceProvider` — cryptographic random number generation
- `GetRandomFileName`, `GetLogicalDrives`, `GetDrives`, `get_DriveType` — drive enumeration
- `ProcessStartInfo`, `set_Arguments`, `set_WindowStyle`, `set_CreateNoWindow` — hidden process execution
- `WipePass`, `Gutmann` — references to the Gutmann secure deletion method (35-pass overwrite)
- `SetLastWriteTime`, `SetCreationTime`, `SetLastAccessTime` — timestamp manipulation (anti-forensics)
- `FileFlagDeleteOnClose` — file deletion flag

*See screenshots: FLOSS1.png through FLOSS6.png below*
<img width="1916" height="996" alt="FLOSS1" src="https://github.com/user-attachments/assets/de432db3-279f-44c0-b5b6-fcd10e5c0c8d" />
<img width="1916" height="996" alt="FLOSS2" src="https://github.com/user-attachments/assets/99fc3595-143b-4577-8fd8-82b167da6480" />
<img width="1916" height="996" alt="FLOSS3" src="https://github.com/user-attachments/assets/66edc768-d8bc-4654-9506-3112b6d1def0" />
<img width="1916" height="996" alt="FLOSS4" src="https://github.com/user-attachments/assets/c8073813-08e5-498b-b49a-b39045d4090f" />
<img width="1916" height="996" alt="FLOSS5" src="https://github.com/user-attachments/assets/3433eb0f-4f75-498d-8c47-115c8f10176a" />
<img width="1916" height="684" alt="FLOSS6" src="https://github.com/user-attachments/assets/22adfc7e-b3d3-401f-8935-89f72665a885" />

#### Capa Capability Analysis

Capa identified the following ATT&CK techniques and malware behaviors:

**ATT&CK Mapping:**

| Tactic | Technique |
|--------|-----------|
| DEFENSE EVASION | File and Directory Permissions Modification [T1222] |
| DEFENSE EVASION | Indicator Removal: File Deletion [T1070.004] |
| DISCOVERY | File and Directory Discovery [T1083] |
| DISCOVERY | System Information Discovery [T1082] |

**MBC (Malware Behavior Catalog) Behaviors:**
- CRYPTOGRAPHY: Generate Pseudo-random Sequence using API [C0021.003]
- DEFENSE EVASION: Self Deletion via COMSPEC Environment Variable [F0007.001]
- DISCOVERY: File and Directory Discovery [E1083], System Information Discovery [E1082]
- FILE SYSTEM: Delete File [C0047], Get/Set File Attributes [C0049/C0050], Move File [C0063], Writes File [C0052]
- PROCESS: Create Process [C0017], Terminate Process [C0018]

**Capabilities Detected:**
- Self delete (anti-forensic/self-deletion via COMSPEC — 2 matches)
- Generate random bytes in .NET (cryptographic random data for wipe patterns)
- Access .NET resources, generate random filenames
- Full file system interaction: delete, enumerate, get/set attributes, move, write
- Get disk information (drive enumeration for targeting all drives)
- Create and terminate processes (for spawning cmd.exe self-deletion)
- Compiled to .NET platform

**MAEC Classification:** malware-category: **launcher**

*See screenshots: Malware2-capa1.png, Malware2-capa2.png below*
<img width="827" height="643" alt="Malware2-capa1" src="https://github.com/user-attachments/assets/1fc6f5dd-9e9b-4992-99ae-af3f69fdedab" />
<img width="827" height="389" alt="Malware2-capa2" src="https://github.com/user-attachments/assets/9a18dd56-f9dc-4334-84f1-e2934923ed34" />

---

### 2.2 Malware3.bin (HOW TO BACK YOUR FILES.bin) — Static Findings

#### PEStudio Analysis

PEStudio identified 16 indicators for this sample. Key findings:

- **File Signature:** Microsoft Linker 14.16 | Microsoft Visual C++ 6.0 - 8.0 | Visual Studio 2008
- **SHA-256:** `8199F75132C17EA0BFDD09FAF426EB94DD50FF86B39B47795D0BBD88F94B3104`
- **Compilation Timestamp:** Mon Jan 20 14:06:17 2020
- **File Type:** Executable, 32-bit, GUI
- **Size:** 28,672 bytes, **Entropy: 7.619** (high — indicates compression or encryption)
- **Language:** English-US
- **Imports (37):** From KERNEL32.dll, USER32.dll, ole32.dll, OLEAUT32.dll
  - KERNEL32.dll: `lstrlenW`, `lstrlenA`, `MultiByteToWideChar`, `lstrcatW`, `lstrcpyW`, `GlobalAlloc`, `GlobalFree`, `HeapAlloc`, `GetProcessHeap`, `HeapFree`, `ExitProcess`, `GetModuleHandleA`, `GetStartupInfoA`, `GetCommandLineA`
  - USER32.dll: `RegisterClassExW`, `GetSystemMetrics`, `CreateWindowExW`, `DefWindowProcW`, `GetMessageW`, `GetWindowLongW`, `UpdateWindow`, `PostQuitMessage`, `GetClientRect`, `DispatchMessageW`, `SetWindowLongW`, `TranslateMessage`, `ShowWindow`
  - ole32.dll: `OleSetContainedObject`, `OleUninitialize`, `OleInitialize`, `OleCreate`
  - OLEAUT32.dll: `BSTR_UserUnmarshal`, `SysAllocString`
- **Imphash MD5:** `C12C22EB0397303F07B2293D0FD6134B`
- **Strings (786):** Large number of strings, mostly short/encoded — consistent with obfuscation
- **Sections:** .text (entropy 6.197), .rdata (entropy 7.868 — very high), .data, .rsrc, .reloc

*See screenshots: Malware3-indicators.png, Malware3-imports.png, Malware3-strings.png, Malware3-sections.png below*
<img width="1199" height="747" alt="Malware3-indicators" src="https://github.com/user-attachments/assets/05727e76-0a3b-4b0f-a519-df2d61b613ae" />
<img width="1199" height="747" alt="Malware3-imports" src="https://github.com/user-attachments/assets/1db5fe59-daee-443a-a52e-7e20e4529eef" />
<img width="1199" height="866" alt="Malware3-strings" src="https://github.com/user-attachments/assets/a419db64-3750-4df9-9025-f1f85fb1030e" />
<img width="1424" height="866" alt="Malware3-sections" src="https://github.com/user-attachments/assets/acf51748-3ea4-47e5-9f9a-4776c9a3b19d" />

#### Detect It Easy (DiE)

- **File Type:** PE32
- **Size:** 28.00 KiB
- **Operation System:** Windows(XP)[I386, 32-bit, GUI]
- **Linker:** Microsoft Linker (14.16.27031)
- **Compiler:** Microsoft Visual C/C++ (19.16.27031) [LTCG/C]
- **Language:** C
- **Tool:** Visual Studio (2017, v15.9)
- **Heuristic Packer Detection:** **(Heur) Packer: Compressed or packed data [High entropy + Section 1 (".rdata") compressed]**
- **Installer:** SQX Archive Installer 2002

The heuristic packer detection confirms that the .rdata section's high entropy (7.868) indicates compressed or encrypted data, likely containing the ransomware payload that unpacks at runtime.

*See screenshot: Malware3-DiE.png below*
<img width="1004" height="664" alt="Malware3-DiE" src="https://github.com/user-attachments/assets/b29eb013-19d4-4db5-93d5-8fe1d93d8064" />

#### FLOSS String Analysis

FLOSS extracted 329 static strings (322 ASCII, 7 UTF-16LE) and 3 decoded strings. Notable findings:

**UTF-16LE Strings:**
- `HTML` — indicates HTML content generation (ransom note)
- `GlobeImposter-Alpha865qqz` — **ransomware family identification**
- `HOW TO BACK YOUR FILES.exe` — self-reference
- `about:blank` — blank page reference (likely for HTML ransom note display)
- `My Host Name` — hostname collection template
- `{{ID}}` — template variable for victim identification
- `Requirements` — ransom note section header

**FLOSS Decoded Strings (3):**
- `/v 7+` repeated in a pattern — possible encoded configuration data
- `wYXz` — short decoded string, possibly a key fragment

**ASCII Strings:**
- `ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz0123456789+/H` — **Base64 alphabet** (confirms Base64 encoding usage for data obfuscation or C2 communication)
- Section names: `.text`, `.rdata`, `.data`, `.rsrc`, `.reloc`
- Large volume of short, seemingly random strings — consistent with XOR-encrypted or obfuscated configuration data

The majority of Malware3's strings are short and encoded, contrasting sharply with Malware2's readable .NET strings. This is consistent with native C/C++ compilation combined with runtime string decryption.

*See screenshots: FLOSS1.png through FLOSS6.png (side-by-side comparison with Malware2)*

#### Capa Capability Analysis

Capa detected significantly fewer capabilities than Malware2, which is expected given the packing/obfuscation:

**ATT&CK Mapping:**

| Tactic | Technique |
|--------|-----------|
| DEFENSE EVASION | Obfuscated Files or Information [T1027] |
| EXECUTION | Command and Scripting Interpreter [T1059] |

**MBC Behaviors:**
- DATA: Check String [C0019], Encode Data::Base64 [C0026.001], Encode Data::XOR [C0026.002]
- DEFENSE EVASION: Obfuscated Files or Information: Encoding-Standard Algorithm [E1027.m02]
- EXECUTION: Command and Scripting Interpreter [E1059]
- PROCESS: Terminate Process [C0018]

**Capabilities Detected:**
- Reference Base64 string (data encoding for obfuscation or C2)
- Encode data using XOR (string/payload decryption at runtime)
- Accept command line arguments (configurable execution)
- Terminate process

**Analysis Note:** The low capability count is directly attributable to the obfuscation. Capa performs static analysis and cannot see through packed/encrypted sections. The .rdata section (entropy 7.868) likely contains the actual ransomware functionality — file encryption, ransom note generation, persistence mechanisms — that only becomes visible during dynamic analysis or after unpacking.

*See screenshot: Malware3-capa.png below*
<img width="827" height="589" alt="Malware3-capa" src="https://github.com/user-attachments/assets/7a883ba5-22da-4611-8662-1d57f0be8d9e" />

---

## 3. Dynamic Analysis — Malware2.bin (Lecture2.bin / Shamoon Wiper)

### 3.1 Execution Environment

A clean VM snapshot was taken prior to execution. All monitoring tools were open and baselined (Regshot 1st shot completed with 538,524 registry keys and 878,806 values captured). The sample was executed from an Administrator command prompt:

```
C:\Users\kylev\Desktop\MAL3> Lecture2.bin
```

### 3.2 Execution Behavior

Upon execution, the Shamoon wiper immediately began aggressive disk I/O operations. The process (`Lecture2.bin`, PID 5596) was spawned as a child of `cmd.exe` (PID 5620) and ran continuously for over 19 minutes before the VM was reverted to its clean snapshot.

**Process Hacker Observations:**
- Process description: "Shamoon" (UNVERIFIED), Version 4.0.0.0
- Image file: `C:\Users\kylev\Desktop\MAL3\Lecture2.bin`
- Parent process: `cmd.exe` (PID 5620)
- Start time: 8:46:13 AM, 3/24/2026
- Image type: 64-bit (.NET assembly running in 64-bit mode on 64-bit OS)
- **I/O Activity:** Massive disk write spike — 8.2 MB/s sustained writes, with total write bytes reaching 28.24 GB during the observation period
- System CPU rose from baseline 3.39% to 8.79%
- Memory usage increased from 62% (2.7 GB) to 71% (3.1 GB)
- System Information I/O panel confirmed: Write bytes delta of 8.22 MB per refresh cycle, total writes of 7,684,009

*See screenshot: Lecture2.png below — Process Hacker showing Shamoon process with I/O spike*
<img width="1916" height="1021" alt="Lecture2" src="https://github.com/user-attachments/assets/00a640eb-8e57-47cf-ba57-5e85ddcfc67d" />


### 3.3 API Monitor — DLL Loading Analysis

API Monitor successfully captured the DLL loading sequence of Lecture2.bin, revealing the libraries loaded during execution:

- **Runtime:** `sechost.dll` → `.NET Framework\v4.0.30319\mscoree1.dll` → `MSVCR71.dll` (confirming .NET execution)
- **System Libraries:** `SHLWAPI.dll`, `USER32.dll`, `win32u.dll`, `GDI32.dll`, `gdi32full.dll`, `msvcp_win.dll`, `shell32.dll`, `IMM32.DLL`, `wintypes.dll`
- **Critical Libraries:**
  - `CRYPTSP.dll` and `CRYPTBASE.dll` — **cryptographic service providers** used for generating the Gutmann wipe pattern (pseudo-random data for multi-pass file overwriting)
  - `kernel.appcore.dll`, `VERSION.dll` — system version detection
  - `bcryptPrimitives.dll` — low-level cryptographic primitives
  - `profapi.dll`, `windows.storage.dll` — storage access
  - `SHCORE.dll` — shell core functions

The loading of `CRYPTSP.dll`, `CRYPTBASE.dll`, and `bcryptPrimitives.dll` confirms the malware's use of cryptographic operations for its Gutmann secure-wipe functionality.

*See screenshot: Lecture2.png below - API Monitor panel showing DLL load sequence*
<img width="1916" height="1021" alt="Lecture2" src="https://github.com/user-attachments/assets/c995a0d5-37f4-4ef2-9e5f-49fee79e4296" />


### 3.4 Network Activity — Wireshark Analysis

Wireshark captured 2,339 packets during the Malware2 execution, all consisting of SMB2 (Server Message Block Protocol version 2) traffic over IPv6 loopback (`::1` to `::1`).

**SMB2 Session Sequence:**
1. **Protocol Negotiation** (Packets 1-3): SMB2 Negotiate Protocol Request/Response
2. **Authentication** (Packets 4-7): NTLMSSP_NEGOTIATE → NTLMSSP_CHALLENGE → NTLMSSP_AUTH (User: `\`) — anonymous authentication
3. **IPC$ Connection** (Packets 8-9): Successful Tree Connect to `\\localhost\IPC$`
4. **DFS Referral Attempt** (Packet 10): FSCTL_DFS_GET_REFERRALS for `\localhost\C$` → Error: `STATUS_FS_DRIVER_REQUIRED`
5. **Aggressive Share Enumeration** (Packets 12-2335): Hundreds of Tree Connect Request/Response pairs targeting `\\localhost\C$`, all returning `STATUS_BAD_NETWORK_NAME`. The malware hammered this share request continuously.
6. **Session Teardown** (Packets 2336-2339): Tree Disconnect from `\\localhost\IPC$`, Session Logoff

**Analysis:** The Shamoon wiper attempted to access the administrative share `C$` via SMB2, which is consistent with its known lateral movement capability. In a network environment, this behavior would enable the wiper to spread to other machines by accessing their administrative shares. On the isolated VM, all connection attempts failed, but the behavior pattern clearly demonstrates the propagation mechanism.

*See screenshots: lecture2-wireshark1.png (session start, share enumeration), lecture2-wireshark2.png (continued enumeration and session teardown) below*
<img width="1567" height="972" alt="lecture2-wireshark1" src="https://github.com/user-attachments/assets/ca081717-e602-4acd-b072-aa1bbd417f2c" />
<img width="1567" height="972" alt="lecture2-wireshark2" src="https://github.com/user-attachments/assets/0b8fd69d-1e03-4a3c-bc0f-611d2ef67b17" />


### 3.5 Registry and Filesystem Changes — Regshot Comparison

After the malware had run for approximately 19 minutes, a second Regshot snapshot was taken and compared against the pre-execution baseline.

**Regshot Comparison Results — Total Changes: 2,007**

| Change Type | Count |
|-------------|-------|
| Keys deleted | 25 |
| Keys added | 131 |
| Values deleted | 70 |
| Values added | 1,382 |
| Values modified | 399 |
| Folders deleted | 0 |
| Folders added | 0 |
| Files deleted | 0 |
| Files added | 0 |
| Files [attributes] modified | 0 |

**Analysis:** The most significant finding is the massive registry manipulation (1,382 values added, 399 modified) combined with zero filesystem-level file additions or deletions. This is consistent with Shamoon's Gutmann wipe method — the malware overwrites file *contents* in place rather than deleting files from the filesystem. The overwritten files would still appear in directory listings but would contain only random/zero data. The 28+ GB of disk writes observed in Process Hacker confirms active data destruction was occurring.

The 131 new registry keys and 1,382 new values likely include .NET runtime configuration entries, temporary execution state, and potentially persistence mechanisms.

*See screenshot: lecture2-compare.png below - Regshot comparison summary*
<img width="191" height="267" alt="lecture2-compare" src="https://github.com/user-attachments/assets/59bb5dd3-b46b-444d-8a67-f861f53539a6" />


### 3.6 Process Properties

Process Hacker Properties confirmed the sample identity:

- **File:** Shamoon (UNVERIFIED), Version 4.0.0.0
- **Image file name:** `C:\Users\kylev\Desktop\MAL3\Lecture2.bin`
- **Command line:** `Lecture2.bin`
- **Parent:** `cmd.exe` (PID 5620)
- **Started:** 8:46:13 AM, 3/24/2026 (ran for 19 minutes 56 seconds at time of screenshot)
- **PEB address:** 0x3ad000
- **Image type:** 64-bit
- **Mitigation policies:** N/A
- **Protection:** None

*See screenshot: lecture2prop.png below - Process Hacker Properties dialog*
<img width="443" height="570" alt="lecture2prop" src="https://github.com/user-attachments/assets/7c9348f8-5d0a-4d6f-aed7-45b8ee905046" />

---

## 4. Dynamic Analysis — Malware3.bin (HOW TO BACK YOUR FILES.bin / GlobeImposter Ransomware)

### 4.1 Execution Environment

The VM was reverted to the clean pre-execution snapshot. All monitoring tools were re-opened and baselined (Regshot 1st shot completed). The sample was renamed to `.exe` for compatibility with API Monitor's process monitoring feature, then launched via API Monitor → Monitor New Process:

```
C:\Users\kylev\Desktop\MAL3> "HOW TO BACK YOUR FILES.exe"
```

### 4.2 Execution Behavior — Immediate Ransomware Deployment

Unlike Malware2's sustained background activity, Malware3 executed its ransomware payload **immediately and aggressively**, locking the user out of the FLARE-VM within seconds of execution.

**Observable Effects:**
1. **Desktop wallpaper changed** to a red and black screen displaying "YOUR FILES ARE ENCRYPTED" with a grid of hexadecimal/binary data
2. **Ransom note files created** across the system — `HOW TO DECRYPT YOUR FILES` documents appeared
3. **Files encrypted** across the filesystem with rapid succession
4. **System became unresponsive** — the ransomware's encryption and system modification operations consumed sufficient resources to effectively lock out the user

The speed and aggression of the GlobeImposter variant required an immediate VM shutdown and snapshot revert, limiting the duration of capture compared to Malware2. However, significant data was captured in the brief window before lockout.

*See screenshot: mal3-apimon0.png below - Encrypted desktop wallpaper and ransom note properties*
<img width="1190" height="462" alt="mal3-apimon0" src="https://github.com/user-attachments/assets/9cfa8266-f0ce-4c57-a049-3436e5ac7760" />


### 4.3 Ransom Note Analysis

The GlobeImposter ransomware generated an HTML ransom note with the following content:

**Title:** "YOUR FILES ARE ENCRYPTED!!!"

**Subtitle:** "TO DECRYPT, FOLLOW THE INSTRUCTIONS BELOW"

**Instructions to victim:**
> "To recover data you need decryptor. To get the decryptor you should:
>
> Send 1 test image or text file to China.Helper@aol.com
>
> In the letter include your personal ID (look at the beginning of this document)
>
> We will give you the decrypted file and assign the price for decryption of all files"

**Contact Email:** China.Helper@aol.com

**Threat:** The note warns that attempting to use third-party decryption tools or anti-malware will result in permanent data loss.

**Analysis:** The ransom note identifies this as a **GlobeImposter** variant (confirmed by the static analysis finding of `GlobeImposter-Alpha865qqz` in FLOSS strings). The use of an @aol.com email address is characteristic of older GlobeImposter campaigns. The `{{ID}}` template variable found in static analysis corresponds to the "personal ID" referenced in the ransom note — each victim receives a unique identifier for tracking ransom payments.

*See screenshot: mal3-apimon1.png below - Full ransom note HTML page*
<img width="826" height="700" alt="mal3-apimon1" src="https://github.com/user-attachments/assets/db54435d-34b8-4bcf-a719-47c0a44c8b13" />


### 4.4 Process Analysis — Process Explorer

Process Explorer captured the system state during Malware3 execution:

- **HOW TO BACK YOUR FILES.exe** appeared in the process tree, highlighted in magenta/pink (indicating the process was suspended or being terminated at the time of capture)
- Multiple system processes visible in their normal state
- The process tree showed the malware running under the user context `TALONS3150\kylev`

The rapid execution cycle — launch, encrypt, display ransom note, potentially exit — is characteristic of GlobeImposter variants that perform encryption as quickly as possible and then remove themselves from memory to complicate forensic analysis.

*See screenshots: mal3-procexp0.png (Process Explorer tree), mal3-tcpview-procexp.png (TCPView + Process Explorer side by side) below*
<img width="926" height="850" alt="mal3-procexp0" src="https://github.com/user-attachments/assets/14c70cb5-5858-40d0-b072-c25b2670e06f" />
<img width="1763" height="850" alt="mal3-tcpview-procexp" src="https://github.com/user-attachments/assets/3b972fc4-c24c-4e31-bda3-650c3c62a0a7" />

### 4.5 Network Activity — Wireshark Analysis

Wireshark captured DNS queries during the Malware3 execution period. The observed traffic consisted of:

- DNS queries to Microsoft telemetry domains: `mobile.events.data.microsoft.com`, `events.data.microsoft.com`
- DNS responses from `10.37.129.3` (the VM's DNS resolver)
- Standard Windows DNS resolution traffic for cloud services (Azure, Microsoft update endpoints)
- **Neighbor Solicitation/Advertisement** (IPv6 NDP) traffic

**Analysis:** Unlike Malware2, which generated 2,339 packets of SMB2 traffic, Malware3 did not produce any clearly malicious network traffic during the captured window. This is consistent with the host-only network configuration — the GlobeImposter ransomware likely attempted C2 callbacks that failed silently, or this variant operates in a fully offline encryption mode where C2 communication occurs only during the initial infection vector (before execution on the target). The DNS traffic observed was standard Windows telemetry, not malware-generated.

In a production environment with internet connectivity, we would expect to see:
- DNS lookups for C2 domains
- HTTP/HTTPS connections for key exchange
- Possible data exfiltration before encryption (double extortion)

*See screenshot: mal3-reg1st-wireshark.png below - Wireshark capture showing DNS traffic during execution*
<img width="1759" height="861" alt="mal3-reg1st-wireshark" src="https://github.com/user-attachments/assets/7477aa93-95df-4da3-afe0-60c6cd34e54e" />


### 4.6 Persistence Analysis — Autoruns

Autoruns was reviewed across all tabs during the Malware3 analysis session. The following tabs were inspected:

- **Logon:** Baseline entries including ZoomIt, BinDiffPerUserSetup, cmd.exe (SafeBoot\AlternateShell), Microsoft Edge, .NET IE SECURITY REGISTRATION
- **Scheduled Tasks:** Standard Microsoft Office, OneDrive, and Windows Update tasks. Notable yellow-highlighted entries included Microsoft Office ClickToRun and Windows Application Experience tasks.
- **Services:** Standard system services including ClickToRunSvc, edgeupdate, Parallels services (VM integration), NetTcpPortSharing, WMPNetworkSvc. Several services with "File not found" status highlighted in yellow.
- **Drivers:** Parallels VM drivers (prl_*, prl_boot, prl_dd, prl_fs, prl_memdev, prl_mouf, prl_strg, prl_tg, prl_usb_balloon), Qualcomm QCGNSS drivers, system manager drivers.
- **Boot Execute/Image Hijacks:** Windows Command Processor, Internet Explorer image file execution options

**Analysis:** Due to the rapid system lockout caused by GlobeImposter, a post-execution Autoruns comparison could not be completed before the snapshot revert. The baseline Autoruns captures serve as reference documentation. In a longer-running analysis (or with a delayed-execution ransomware variant), we would look for new Run/RunOnce registry entries, scheduled tasks for persistence, or service installations.

*See screenshots: mal3-autorun0.png through mal3-autorun4.png below*
<img width="1560" height="760" alt="mal3-autorun0" src="https://github.com/user-attachments/assets/6220c8ce-bf7f-458c-b193-36c6ebd1eefa" />
<img width="1560" height="760" alt="mal3-autorun1" src="https://github.com/user-attachments/assets/5f100de8-8b01-40b4-848c-e85e83c20512" />
<img width="1560" height="760" alt="mal3-autorun2" src="https://github.com/user-attachments/assets/4abbca6c-51a9-4c4f-a845-cee84de4d3eb" />
<img width="1560" height="760" alt="mal3-autorun4" src="https://github.com/user-attachments/assets/c0edcb54-560b-427c-b449-4a0557dfab42" />
<img width="1560" height="760" alt="mal3-autorun3" src="https://github.com/user-attachments/assets/e227ae3e-33a9-4eb7-b0e1-3318f6870a63" />

---

## 5. Tool Effectiveness Summary

| Tool | Malware2.bin (Shamoon) Result | Malware3.bin (GlobeImposter) Result | Useful? |
|------|-------------------------------|-------------------------------------|---------|
| **PEStudio** | Identified Shamoon name, version, flagged imports (WriteFile, RandomNumberGenerator, CreateFile), .NET module, compilation date | Identified high entropy (7.619), 37 imports from 4 DLLs, compilation date, imphash, 16 indicators | **Yes** |
| **Detect It Easy** | Correctly identified .NET/C#, Visual Studio, no packing | Identified native C/C++, detected heuristic packing in .rdata section, identified MSVC compiler version | **Yes** |
| **FLOSS** | Extracted critical strings: Shamoon, PhysicalDrive, Gutmann wipe, self-delete cmd, PDB path, "From Iran with love" | Extracted GlobeImposter-Alpha865qqz identifier, Base64 alphabet, ransom note template strings, 3 decoded strings | **Yes** |
| **Capa** | Comprehensive ATT&CK mapping (T1222, T1070.004, T1083, T1082), identified self-deletion, crypto, file system operations, disk info collection | Limited results due to packing — only T1027, T1059; Base64/XOR encoding detected but real capabilities hidden | **Partial** — effective on unpacked samples, limited on packed/obfuscated binaries |
| ~~ProcMon~~ | BLOCKED — kernel driver failed to load (HVCI) | BLOCKED | **N/A** |
| **Process Hacker** | Excellent — showed process tree, I/O activity (28+ GB writes), memory usage, system resource impact. Properties dialog confirmed Shamoon identity. | Showed process execution before system lockout, process tree context | **Yes** |
| **API Monitor** | Captured DLL loading sequence including crypto libraries (CRYPTSP.dll, CRYPTBASE.dll) | Enabled process launch and monitoring; captured execution before lockout | **Yes** |
| ~~FakeNet-NG~~ | BLOCKED — WinDivert driver failed to load (HVCI) | BLOCKED | **N/A** |
| **Process Explorer** | Secondary process view confirming findings | Showed GlobeImposter process in tree, suspension state, resource usage | **Yes** |
| **Wireshark** | Critical — captured 2,339 SMB2 packets showing share enumeration and lateral movement attempts | Captured DNS traffic but no obvious malware-specific network activity in host-only mode | **Yes** (Malware2) / **Limited** (Malware3) |
| **Regshot** | Captured 2,007 total changes: 131 keys added, 1,382 values added, 399 values modified. Confirmed in-place data overwriting (0 file additions/deletions despite 28+ GB writes). | 1st shot baseline captured; 2nd shot not possible due to rapid system lockout | **Yes** (Malware2) / **Limited** (Malware3) |
| **TCPView** | Baseline network connections documented | Showed connections during execution alongside Process Explorer | **Moderate** |
| **Autoruns** | Baseline documented | Baseline documented across all tabs; post-execution comparison not possible due to lockout | **Moderate** |

---

## 6. Conclusion

This analysis examined two fundamentally different classes of malware:

**Malware2 (Shamoon Wiper)** is a destructive wiper designed to cause maximum damage to data and infrastructure. Written in C# (.NET), it is relatively transparent in its static analysis — openly identifying itself as "Shamoon" version 4.0.0.0 with a clear PDB path and attribution string. Dynamically, it demonstrated aggressive disk writing (28+ GB), SMB2 network share enumeration for lateral movement, and heavy registry manipulation. Its use of the Gutmann method (35-pass overwrite) makes data recovery effectively impossible. The self-deletion mechanism (`/C choice /C Y /N /D Y /T 3 & Del`) ensures the binary removes itself after execution.

**Malware3 (GlobeImposter Ransomware)** is an encryption-based ransomware designed for financial extortion. Written in native C/C++ with significant obfuscation (entropy 7.619, packed .rdata section), it resists static analysis — Capa detected only a fraction of its actual capabilities. Dynamically, it executed with extreme speed, encrypting files and locking out the user within seconds. It generated HTML ransom notes directing victims to China.Helper@aol.com and changed the desktop wallpaper to display "YOUR FILES ARE ENCRYPTED."

**Comparative Assessment:** While both samples are dangerous, **Malware2 (Shamoon) represents the greater threat** from an organizational perspective. Ransomware victims can potentially recover through backups, decryption tools, or (as a last resort) ransom payment. Wiper victims have no recovery path — the Gutmann 35-pass overwrite destroys data beyond any possibility of forensic recovery. Additionally, Shamoon's SMB2 lateral movement capability means a single execution could propagate across an entire network, destroying data on every accessible system. GlobeImposter's rapid encryption is devastating but potentially recoverable; Shamoon's disk wiping is permanent.

---
