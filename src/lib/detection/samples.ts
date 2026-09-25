// Example rules and synthetic events for the detection lab. The events are
// fabricated for demonstration and are labelled as such in the interface.

export const YARA_EXAMPLES: { id: string; label: string; source: string }[] = [
  {
    id: "packer",
    label: "UPX-packed Windows executable",
    source: `import "pe"

rule UPX_Packed_PE
{
  meta:
    description = "PE file with UPX section names and the UPX magic"
    attack = "T1027.002"
  strings:
    $magic = "UPX!"
  condition:
    pe.is_pe and
    for any i in (0..pe.number_of_sections - 1) : ( pe.sections[i].name == "UPX0" or pe.sections[i].name == "UPX1" ) and
    $magic in (0..1024)
}
`,
  },
  {
    id: "injection",
    label: "Remote process injection imports",
    source: `import "pe"

rule PE_Remote_Injection_Imports
{
  meta:
    description = "Imports the classic allocate / write / create-remote-thread sequence"
    attack = "T1055"
  condition:
    pe.is_pe and
    pe.imports("kernel32.dll", "VirtualAllocEx") and
    pe.imports("kernel32.dll", "WriteProcessMemory") and
    pe.imports("kernel32.dll", "CreateRemoteThread")
}
`,
  },
  {
    id: "powershell",
    label: "PowerShell download cradle",
    source: `rule PowerShell_Download_Cradle
{
  meta:
    description = "Script text that downloads and executes content"
    attack = "T1059.001"
  strings:
    $dl1 = "DownloadString" nocase ascii wide
    $dl2 = "DownloadFile" nocase ascii wide
    $dl3 = "Invoke-WebRequest" nocase ascii wide
    $ex1 = "IEX" fullword nocase ascii wide
    $ex2 = "Invoke-Expression" nocase ascii wide
    $b64 = "FromBase64String" nocase ascii wide
  condition:
    filesize < 5MB and 1 of ($dl*) and (1 of ($ex*) or $b64)
}
`,
  },
  {
    id: "embedded",
    label: "Embedded executable",
    source: `rule Embedded_PE
{
  meta:
    description = "A second DOS stub after the start of the file"
    attack = "T1027.009"
  strings:
    $stub = "This program cannot be run in DOS mode"
  condition:
    for any i in (1..#stub) : ( @stub[i] > 0x200 )
}
`,
  },
  {
    id: "overlay",
    label: "High-entropy overlay",
    source: `import "pe"
import "math"

rule PE_Encrypted_Overlay
{
  meta:
    description = "More than 16 KB of near-random data appended after the image"
  condition:
    pe.is_pe and pe.overlay.size > 16KB and
    math.entropy(pe.overlay.offset, pe.overlay.size) > 7.5
}
`,
  },
];

export const SIGMA_EXAMPLES: { id: string; label: string; source: string }[] = [
  {
    id: "encoded-ps",
    label: "Encoded PowerShell command line",
    source: `title: PowerShell With Encoded Command
id: 6a1f7e4c-3c55-4f3e-9d2a-51d3c6b7e1a0
status: experimental
description: PowerShell started with an encoded command, common in loaders and living-off-the-land activity.
author: NOPS detection lab
date: 2026-09-25
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_flag:
    CommandLine|windash|contains:
      - ' -enc '
      - ' -encodedcommand '
      - ' -ec '
  condition: all of selection_*
falsepositives:
  - Management and deployment tools that pass scripts encoded
level: high
`,
  },
  {
    id: "office-shell",
    label: "Office application spawning a shell",
    source: `title: Office Application Spawns Script Interpreter
id: 0d3f9c2b-8b1e-4a44-9d6f-2f1e7c9b5a11
status: experimental
description: A document-handling process started a shell or script host, typical of malicious macros.
author: NOPS detection lab
date: 2026-09-25
tags:
  - attack.execution
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\\winword.exe'
      - '\\excel.exe'
      - '\\powerpnt.exe'
      - '\\outlook.exe'
  child:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
      - '\\rundll32.exe'
  condition: parent and child
falsepositives:
  - Add-ins that launch helpers
level: high
`,
  },
  {
    id: "shadow",
    label: "Shadow copy deletion",
    source: `title: Shadow Copies Deleted
id: 4e7b2a91-6d0c-4d4f-8f55-7a3b2c1d9e02
status: experimental
description: Deletion of volume shadow copies, which ransomware does before encrypting.
author: NOPS detection lab
date: 2026-09-25
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  vssadmin:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  wmic:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  condition: 1 of them
falsepositives:
  - Backup software maintenance
level: critical
`,
  },
  {
    id: "log-clear",
    label: "Security event log cleared",
    source: `title: Windows Event Log Cleared
id: 9b2c4e6f-1a3d-4c5b-8e7f-0a1b2c3d4e5f
status: stable
description: The Security log was cleared (event 1102) or a log was cleared via the System channel (event 104).
author: NOPS detection lab
date: 2026-09-25
tags:
  - attack.defense-evasion
  - attack.t1070.001
logsource:
  product: windows
  service: security
detection:
  security:
    EventID: 1102
  system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: security or system
level: high
`,
  },
];

/** Fabricated Sysmon-style events used only to demonstrate rule evaluation. */
export const SYNTHETIC_EVENTS = JSON.stringify(
  [
    { EventID: 1, UtcTime: "2026-09-25 09:12:01.101", Computer: "WS-0042", User: "CORP\\\\j.doe", Image: "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE", CommandLine: '"WINWORD.EXE" /n "C:\\\\Users\\\\j.doe\\\\Downloads\\\\invoice_0925.docm"', ParentImage: "C:\\\\Windows\\\\explorer.exe" },
    { EventID: 1, UtcTime: "2026-09-25 09:12:04.550", Computer: "WS-0042", User: "CORP\\\\j.doe", Image: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", CommandLine: "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", ParentImage: "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE" },
    { EventID: 1, UtcTime: "2026-09-25 09:13:40.020", Computer: "WS-0042", User: "CORP\\\\j.doe", Image: "C:\\\\Windows\\\\System32\\\\cmd.exe", CommandLine: "cmd.exe /c whoami /all", ParentImage: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe" },
    { EventID: 1, UtcTime: "2026-09-25 09:20:11.900", Computer: "SRV-FILE01", User: "NT AUTHORITY\\\\SYSTEM", Image: "C:\\\\Windows\\\\System32\\\\vssadmin.exe", CommandLine: "vssadmin.exe Delete Shadows /All /Quiet", ParentImage: "C:\\\\Windows\\\\System32\\\\cmd.exe" },
    { EventID: 1, UtcTime: "2026-09-25 10:02:00.000", Computer: "WS-0017", User: "CORP\\\\a.smith", Image: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", CommandLine: "powershell.exe -File C:\\\\Scripts\\\\inventory.ps1", ParentImage: "C:\\\\Windows\\\\System32\\\\svchost.exe" },
    { EventID: 1102, Channel: "Security", Computer: "SRV-FILE01", Provider_Name: "Microsoft-Windows-Eventlog", SubjectUserName: "svc_backup" },
  ],
  null,
  2
);
