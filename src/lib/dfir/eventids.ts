// Curated reference of Windows event IDs analysts see most often during
// DFIR: Security auditing, Sysmon, PowerShell logging and System/Task
// Scheduler. IDs, channels and field names are drawn from Microsoft's and
// Sysmon's own published schemas — this is reference data, not telemetry.

export interface EventIdEntry {
  id: number;
  channel: string;
  name: string;
  description: string;
  attack?: string[];
  fields?: string[];
}

export const EVENT_ID_REFERENCE: EventIdEntry[] = [
  // ---- Security: logon / authentication ----
  { id: 4624, channel: "Security", name: "An account was successfully logged on", description: "Successful logon. LogonType distinguishes interactive (2), network (3), service (5), unlock (7), RDP (10) and others.", fields: ["TargetUserName", "LogonType", "IpAddress", "WorkstationName"] },
  { id: 4625, channel: "Security", name: "An account failed to log on", description: "Failed logon attempt; repeated occurrences from one source suggest password guessing or spraying.", attack: ["T1110"], fields: ["TargetUserName", "LogonType", "IpAddress", "Status"] },
  { id: 4634, channel: "Security", name: "An account was logged off", description: "Session logoff; pair with the matching 4624 by Logon ID to compute session duration." },
  { id: 4647, channel: "Security", name: "User initiated logoff", description: "Explicit user-initiated logoff, as opposed to a session simply ending." },
  { id: 4648, channel: "Security", name: "A logon was attempted using explicit credentials", description: "A process supplied different credentials than the logged-on user (RunAs, scheduled task, lateral movement tooling).", attack: ["T1078"] },
  { id: 4672, channel: "Security", name: "Special privileges assigned to new logon", description: "The new logon session was granted admin-equivalent privileges (SeDebugPrivilege and similar)." },
  { id: 4675, channel: "Security", name: "SIDs were filtered", description: "SID filtering across a forest trust removed a SID from the token." },
  { id: 4768, channel: "Security", name: "A Kerberos authentication ticket (TGT) was requested", description: "Kerberos AS-REQ. Unusual encryption types or a burst of requests are the classic signature of Kerberoasting-adjacent activity.", attack: ["T1558"] },
  { id: 4769, channel: "Security", name: "A Kerberos service ticket was requested", description: "Kerberos TGS-REQ. RC4 encryption (0x17) for a service ticket is a Kerberoasting indicator.", attack: ["T1558.003"] },
  { id: 4771, channel: "Security", name: "Kerberos pre-authentication failed", description: "Failed AS-REQ; repeated failures against many accounts suggest a Kerberos brute-force or AS-REP roasting probe.", attack: ["T1558.004"] },
  { id: 4776, channel: "Security", name: "The domain controller attempted to validate credentials (NTLM)", description: "NTLM authentication attempt against a DC; the Error Code field distinguishes success from various failure reasons." },
  { id: 4778, channel: "Security", name: "A session was reconnected to a Window Station", description: "RDP session reconnect." },
  { id: 4779, channel: "Security", name: "A session was disconnected from a Window Station", description: "RDP session disconnect without logoff." },
  // ---- Security: account & group management ----
  { id: 4720, channel: "Security", name: "A user account was created", description: "New local or domain account.", attack: ["T1136"] },
  { id: 4722, channel: "Security", name: "A user account was enabled", description: "A previously disabled account was enabled — check why it was disabled in the first place." },
  { id: 4723, channel: "Security", name: "An attempt was made to change an account's password", description: "Self-service password change by the account owner." },
  { id: 4724, channel: "Security", name: "An attempt was made to reset an account's password", description: "Password reset performed by someone other than the account owner.", attack: ["T1098"] },
  { id: 4725, channel: "Security", name: "A user account was disabled", description: "Account disabled." },
  { id: 4726, channel: "Security", name: "A user account was deleted", description: "Account deletion — an anti-forensic move after account creation for persistence." },
  { id: 4728, channel: "Security", name: "A member was added to a security-enabled global group", description: "Group membership change (often Domain Admins) — a privilege-escalation indicator.", attack: ["T1098"] },
  { id: 4732, channel: "Security", name: "A member was added to a security-enabled local group", description: "Local group membership change, e.g. added to local Administrators." },
  { id: 4738, channel: "Security", name: "A user account was changed", description: "Account attribute change: look at the specific flags changed (UAC flags, SPN, expiration)." },
  { id: 4740, channel: "Security", name: "A user account was locked out", description: "Account lockout, usually from repeated bad-password attempts." },
  { id: 4756, channel: "Security", name: "A member was added to a security-enabled universal group", description: "Universal group membership change." },
  // ---- Security: object access / policy ----
  { id: 4657, channel: "Security", name: "A registry value was modified", description: "Requires registry auditing (SACL) to be configured on the key." },
  { id: 4663, channel: "Security", name: "An attempt was made to access an object", description: "File/object access audit event; needs a SACL on the object to fire." },
  { id: 4670, channel: "Security", name: "Permissions on an object were changed", description: "ACL modification on an audited object." },
  { id: 4698, channel: "Security", name: "A scheduled task was created", description: "New scheduled task — a common persistence mechanism.", attack: ["T1053.005"] },
  { id: 4699, channel: "Security", name: "A scheduled task was deleted", description: "Scheduled task removed, sometimes to cover tracks." },
  { id: 4700, channel: "Security", name: "A scheduled task was enabled", description: "Scheduled task enabled." },
  { id: 4702, channel: "Security", name: "A scheduled task was updated", description: "Scheduled task modified — the action, trigger or account may have changed.", attack: ["T1053.005"] },
  { id: 4719, channel: "Security", name: "System audit policy was changed", description: "The audit policy itself changed, which can blind future logging.", attack: ["T1562.002"] },
  { id: 4738, channel: "Security", name: "A user account was changed", description: "See above; listed once for cross-reference." },
  { id: 4907, channel: "Security", name: "Auditing settings on object were changed", description: "SACL change on an object." },
  { id: 4964, channel: "Security", name: "Special groups have been assigned to a new logon", description: "A logon received membership in a 'special group' watch list defined by policy." },
  { id: 5140, channel: "Security", name: "A network share object was accessed", description: "SMB share access; combined with ShareName it shows lateral movement or data staging over shares.", attack: ["T1021.002"] },
  { id: 5145, channel: "Security", name: "A network share object was checked for access", description: "Detailed per-file SMB access check; verbose but useful for tracing exfiltration over shares." },
  { id: 1102, channel: "Security", name: "The audit log was cleared", description: "The Security event log was cleared — a strong anti-forensic signal; check who and from where.", attack: ["T1070.001"] },
  // ---- System / Service control / Task Scheduler ----
  { id: 7034, channel: "System", name: "A service terminated unexpectedly", description: "Unexpected service crash." },
  { id: 7035, channel: "System", name: "A service was sent a start/stop control", description: "Service control manager start/stop request." },
  { id: 7036, channel: "System", name: "A service entered the running/stopped state", description: "Service state transition; useful for tracking when a malicious service actually started." },
  { id: 7040, channel: "System", name: "A service's start type was changed", description: "Service start type changed (e.g. disabled → auto), often to enable persistence or disable defences.", attack: ["T1562.001"] },
  { id: 7045, channel: "System", name: "A new service was installed", description: "New Windows service installed — a classic persistence and lateral-movement (PsExec-style) indicator.", attack: ["T1543.003"] },
  { id: 104, channel: "System", name: "The event log was cleared", description: "A log (not necessarily Security) was cleared via wevtutil or the Event Viewer.", attack: ["T1070.001"] },
  { id: 106, channel: "Microsoft-Windows-TaskScheduler/Operational", name: "Task registered", description: "A scheduled task was registered." },
  { id: 140, channel: "Microsoft-Windows-TaskScheduler/Operational", name: "Task updated", description: "A scheduled task's definition was updated." },
  { id: 141, channel: "Microsoft-Windows-TaskScheduler/Operational", name: "Task deleted", description: "A scheduled task was deleted." },
  { id: 200, channel: "Microsoft-Windows-TaskScheduler/Operational", name: "Task action started", description: "A scheduled task's action began executing." },
  { id: 201, channel: "Microsoft-Windows-TaskScheduler/Operational", name: "Task completed", description: "A scheduled task's action finished." },
  // ---- PowerShell ----
  { id: 4103, channel: "Microsoft-Windows-PowerShell/Operational", name: "Module logging", description: "Records pipeline execution details for each cmdlet call when module logging is enabled." },
  { id: 4104, channel: "Microsoft-Windows-PowerShell/Operational", name: "Script block logging", description: "Full (de-obfuscated) script block text — the single richest PowerShell forensic source; look for ScriptBlockText with suspicious content.", attack: ["T1059.001"] },
  { id: 4105, channel: "Microsoft-Windows-PowerShell/Operational", name: "Script block execution started", description: "Marks the start of a logged script block's execution." },
  { id: 4106, channel: "Microsoft-Windows-PowerShell/Operational", name: "Script block execution stopped", description: "Marks the end of a logged script block's execution." },
  { id: 400, channel: "Windows PowerShell", name: "Engine state changed to Available", description: "Legacy (pre-5.0) log: a PowerShell host started; HostApplication shows the command line." },
  { id: 800, channel: "Windows PowerShell", name: "Pipeline execution details", description: "Legacy log: records the pipeline that was executed." },
  // ---- Sysmon ----
  { id: 1, channel: "Sysmon", name: "Process creation", description: "New process with full command line, hashes, parent process and user.", attack: ["T1059"], fields: ["Image", "CommandLine", "ParentImage", "Hashes", "User"] },
  { id: 2, channel: "Sysmon", name: "A process changed a file creation time", description: "Timestomping indicator: a file's creation time was set to a different value.", attack: ["T1070.006"] },
  { id: 3, channel: "Sysmon", name: "Network connection", description: "TCP/UDP connection with source/destination and the initiating process.", fields: ["Image", "DestinationIp", "DestinationPort"] },
  { id: 4, channel: "Sysmon", name: "Sysmon service state changed", description: "Sysmon itself started or stopped." },
  { id: 5, channel: "Sysmon", name: "Process terminated", description: "A monitored process exited." },
  { id: 6, channel: "Sysmon", name: "Driver loaded", description: "A kernel driver was loaded; useful for spotting unsigned or vulnerable ('BYOVD') drivers.", attack: ["T1215"] },
  { id: 7, channel: "Sysmon", name: "Image loaded", description: "A DLL was loaded into a process; noisy by default, valuable for DLL side-loading and injection follow-up.", attack: ["T1574.002"] },
  { id: 8, channel: "Sysmon", name: "CreateRemoteThread", description: "A process created a thread in another process — a direct process-injection indicator.", attack: ["T1055"] },
  { id: 9, channel: "Sysmon", name: "RawAccessRead", description: "Raw (sector-level) volume read, bypassing the file system — used to read locked files such as NTDS.dit or the SAM.", attack: ["T1003.002"] },
  { id: 10, channel: "Sysmon", name: "ProcessAccess", description: "A process opened a handle to another process; GrantedAccess reveals capability (e.g. PROCESS_VM_WRITE for injection, full access to lsass.exe for credential dumping).", attack: ["T1003.001"] },
  { id: 11, channel: "Sysmon", name: "FileCreate", description: "A file was created or overwritten." },
  { id: 12, channel: "Sysmon", name: "RegistryEvent (Create/Delete)", description: "A registry key or value was created or deleted." },
  { id: 13, channel: "Sysmon", name: "RegistryEvent (Value Set)", description: "A registry value was set — commonly used to catch Run-key persistence.", attack: ["T1547.001"] },
  { id: 14, channel: "Sysmon", name: "RegistryEvent (Key/Value Rename)", description: "A registry key or value was renamed." },
  { id: 15, channel: "Sysmon", name: "FileCreateStreamHash", description: "A file was created with an alternate data stream, including the Zone.Identifier mark-of-the-web stream." },
  { id: 16, channel: "Sysmon", name: "ServiceConfigurationChange", description: "The Sysmon service's own configuration changed." },
  { id: 17, channel: "Sysmon", name: "PipeEvent (Pipe Created)", description: "A named pipe was created; many post-exploitation frameworks use characteristically named pipes for C2." },
  { id: 18, channel: "Sysmon", name: "PipeEvent (Pipe Connected)", description: "A process connected to a named pipe." },
  { id: 19, channel: "Sysmon", name: "WmiEvent (WmiEventFilter activity detected)", description: "A WMI event filter was registered — used for WMI-based persistence.", attack: ["T1546.003"] },
  { id: 20, channel: "Sysmon", name: "WmiEvent (WmiEventConsumer activity detected)", description: "A WMI event consumer was registered.", attack: ["T1546.003"] },
  { id: 21, channel: "Sysmon", name: "WmiEvent (WmiEventConsumerToFilter activity detected)", description: "A WMI consumer was bound to a filter, completing a WMI persistence subscription.", attack: ["T1546.003"] },
  { id: 22, channel: "Sysmon", name: "DNSEvent (DNS query)", description: "A monitored process issued a DNS query, with the answer if resolved." },
  { id: 23, channel: "Sysmon", name: "FileDelete (archived)", description: "A file was deleted; Sysmon can retain a copy in its archive directory." },
  { id: 24, channel: "Sysmon", name: "ClipboardChange", description: "The clipboard contents changed." },
  { id: 25, channel: "Sysmon", name: "ProcessTampering", description: "Process image change detected, e.g. process hollowing.", attack: ["T1055.012"] },
  { id: 26, channel: "Sysmon", name: "FileDeleteDetected", description: "A file was deleted (event only, no archived copy)." },
  { id: 27, channel: "Sysmon", name: "FileBlockExecutable", description: "Sysmon blocked an executable file from being written (requires FileBlockExecutable rule)." },
  { id: 28, channel: "Sysmon", name: "FileBlockShredding", description: "Sysmon blocked an attempt to shred (securely delete) a file." },
  { id: 29, channel: "Sysmon", name: "FileExecutableDetected", description: "An executable file was created on disk." },
  { id: 255, channel: "Sysmon", name: "Error", description: "Sysmon reported an internal error." },
];

export const EVENT_ID_CHANNELS = [...new Set(EVENT_ID_REFERENCE.map((e) => e.channel))];
