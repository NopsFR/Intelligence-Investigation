// Windows API capability catalogue. An import says what a program *can* call,
// not what it does: single imports are annotated, and only combinations that
// together implement a technique become findings.

export type ApiCategory =
  | "injection"
  | "execution"
  | "anti-analysis"
  | "credential-access"
  | "persistence"
  | "privilege"
  | "discovery"
  | "collection"
  | "network"
  | "crypto"
  | "dynamic-loading"
  | "filesystem"
  | "service";

export interface ApiInfo {
  category: ApiCategory;
  note: string;
}

export const API_CATEGORY_LABEL: Record<ApiCategory, string> = {
  injection: "Process injection",
  execution: "Execution",
  "anti-analysis": "Anti-analysis",
  "credential-access": "Credential access",
  persistence: "Persistence",
  privilege: "Privilege & tokens",
  discovery: "Discovery",
  collection: "Collection",
  network: "Network",
  crypto: "Cryptography",
  "dynamic-loading": "Dynamic API resolution",
  filesystem: "File system",
  service: "Service control",
};

const A = (category: ApiCategory, note: string): ApiInfo => ({ category, note });

export const CATALOGUE: Record<string, ApiInfo> = {
  VirtualAllocEx: A("injection", "Allocates memory in another process"),
  VirtualProtectEx: A("injection", "Changes memory protection in another process"),
  WriteProcessMemory: A("injection", "Writes into another process's memory"),
  ReadProcessMemory: A("injection", "Reads another process's memory"),
  CreateRemoteThread: A("injection", "Starts a thread inside another process"),
  CreateRemoteThreadEx: A("injection", "Starts a thread inside another process"),
  NtCreateThreadEx: A("injection", "Native thread creation, often in another process"),
  RtlCreateUserThread: A("injection", "Native thread creation, often in another process"),
  QueueUserAPC: A("injection", "Queues an asynchronous procedure call to a thread"),
  NtQueueApcThread: A("injection", "Native APC queueing"),
  SetThreadContext: A("injection", "Rewrites a thread's registers (instruction pointer)"),
  Wow64SetThreadContext: A("injection", "Rewrites a WOW64 thread's registers"),
  GetThreadContext: A("injection", "Reads a thread's registers"),
  NtUnmapViewOfSection: A("injection", "Unmaps an image from a process (process hollowing)"),
  ZwUnmapViewOfSection: A("injection", "Unmaps an image from a process (process hollowing)"),
  NtMapViewOfSection: A("injection", "Maps a section into a process"),
  NtWriteVirtualMemory: A("injection", "Native write into another process"),
  NtAllocateVirtualMemory: A("injection", "Native memory allocation"),
  SetWindowsHookExA: A("collection", "Installs a system hook (keyboard, mouse, messages)"),
  SetWindowsHookExW: A("collection", "Installs a system hook (keyboard, mouse, messages)"),
  GetAsyncKeyState: A("collection", "Polls key state"),
  GetKeyState: A("collection", "Reads key state"),
  GetKeyboardState: A("collection", "Reads the whole keyboard state"),
  GetClipboardData: A("collection", "Reads the clipboard"),
  BitBlt: A("collection", "Copies screen or window pixels"),
  GetDC: A("collection", "Gets a device context (screen drawing)"),
  GetWindowDC: A("collection", "Gets a window's device context"),
  CreateCompatibleBitmap: A("collection", "Creates an off-screen bitmap"),
  CreateProcessA: A("execution", "Starts a process"),
  CreateProcessW: A("execution", "Starts a process"),
  CreateProcessAsUserA: A("execution", "Starts a process as another user"),
  CreateProcessAsUserW: A("execution", "Starts a process as another user"),
  CreateProcessWithTokenW: A("execution", "Starts a process with a duplicated token"),
  WinExec: A("execution", "Legacy process execution"),
  ShellExecuteA: A("execution", "Opens or runs a file through the shell"),
  ShellExecuteW: A("execution", "Opens or runs a file through the shell"),
  ShellExecuteExA: A("execution", "Opens or runs a file through the shell"),
  ShellExecuteExW: A("execution", "Opens or runs a file through the shell"),
  IsDebuggerPresent: A("anti-analysis", "Checks for an attached debugger"),
  CheckRemoteDebuggerPresent: A("anti-analysis", "Checks for a debugger on a process"),
  NtQueryInformationProcess: A("anti-analysis", "Queries process information (often debug port / flags)"),
  ZwQueryInformationProcess: A("anti-analysis", "Queries process information (often debug port / flags)"),
  NtSetInformationThread: A("anti-analysis", "Can hide a thread from the debugger"),
  OutputDebugStringA: A("anti-analysis", "Debugger detection trick when paired with error checks"),
  OutputDebugStringW: A("anti-analysis", "Debugger detection trick when paired with error checks"),
  GetTickCount: A("anti-analysis", "Timing (used in sandbox and debugger checks, also common in normal code)"),
  QueryPerformanceCounter: A("anti-analysis", "High-resolution timing (also common in normal code)"),
  NtDelayExecution: A("anti-analysis", "Native sleep (sandbox evasion by delay)"),
  MiniDumpWriteDump: A("credential-access", "Writes a process memory dump (LSASS dumping when targeted at lsass.exe)"),
  CredEnumerateA: A("credential-access", "Enumerates saved credentials"),
  CredEnumerateW: A("credential-access", "Enumerates saved credentials"),
  CredReadA: A("credential-access", "Reads a saved credential"),
  CredReadW: A("credential-access", "Reads a saved credential"),
  LsaRetrievePrivateData: A("credential-access", "Reads LSA secrets"),
  LsaEnumerateLogonSessions: A("credential-access", "Enumerates logon sessions"),
  SamIConnect: A("credential-access", "Connects to the SAM database"),
  CryptUnprotectData: A("credential-access", "Decrypts DPAPI-protected data (browser and app secrets)"),
  RegSetValueExA: A("persistence", "Writes a registry value"),
  RegSetValueExW: A("persistence", "Writes a registry value"),
  RegCreateKeyExA: A("persistence", "Creates a registry key"),
  RegCreateKeyExW: A("persistence", "Creates a registry key"),
  CreateServiceA: A("service", "Creates a Windows service"),
  CreateServiceW: A("service", "Creates a Windows service"),
  ChangeServiceConfigA: A("service", "Modifies a service"),
  ChangeServiceConfigW: A("service", "Modifies a service"),
  StartServiceA: A("service", "Starts a service"),
  StartServiceW: A("service", "Starts a service"),
  OpenSCManagerA: A("service", "Opens the service control manager"),
  OpenSCManagerW: A("service", "Opens the service control manager"),
  AdjustTokenPrivileges: A("privilege", "Enables privileges on a token (e.g. SeDebugPrivilege)"),
  LookupPrivilegeValueA: A("privilege", "Resolves a privilege name"),
  LookupPrivilegeValueW: A("privilege", "Resolves a privilege name"),
  OpenProcessToken: A("privilege", "Opens a process token"),
  DuplicateTokenEx: A("privilege", "Duplicates an access token"),
  ImpersonateLoggedOnUser: A("privilege", "Impersonates a user token"),
  SetThreadToken: A("privilege", "Assigns a token to a thread"),
  CreateToolhelp32Snapshot: A("discovery", "Snapshots processes, threads or modules"),
  Process32First: A("discovery", "Enumerates processes"),
  Process32FirstW: A("discovery", "Enumerates processes"),
  Process32Next: A("discovery", "Enumerates processes"),
  Process32NextW: A("discovery", "Enumerates processes"),
  EnumProcesses: A("discovery", "Enumerates process IDs"),
  Module32First: A("discovery", "Enumerates loaded modules"),
  Module32FirstW: A("discovery", "Enumerates loaded modules"),
  GetComputerNameA: A("discovery", "Reads the computer name"),
  GetComputerNameW: A("discovery", "Reads the computer name"),
  GetUserNameA: A("discovery", "Reads the current user name"),
  GetUserNameW: A("discovery", "Reads the current user name"),
  GetAdaptersInfo: A("discovery", "Reads network adapter configuration"),
  GetAdaptersAddresses: A("discovery", "Reads network adapter configuration"),
  NetShareEnum: A("discovery", "Enumerates network shares"),
  NetUserEnum: A("discovery", "Enumerates user accounts"),
  GetLogicalDrives: A("discovery", "Enumerates drives"),
  GetVolumeInformationA: A("discovery", "Reads volume serial and file system"),
  GetVolumeInformationW: A("discovery", "Reads volume serial and file system"),
  InternetOpenA: A("network", "Initialises WinINet"),
  InternetOpenW: A("network", "Initialises WinINet"),
  InternetOpenUrlA: A("network", "Opens a URL"),
  InternetOpenUrlW: A("network", "Opens a URL"),
  InternetConnectA: A("network", "Connects to an HTTP/FTP server"),
  InternetConnectW: A("network", "Connects to an HTTP/FTP server"),
  HttpOpenRequestA: A("network", "Builds an HTTP request"),
  HttpOpenRequestW: A("network", "Builds an HTTP request"),
  HttpSendRequestA: A("network", "Sends an HTTP request"),
  HttpSendRequestW: A("network", "Sends an HTTP request"),
  InternetReadFile: A("network", "Reads a response body"),
  URLDownloadToFileA: A("network", "Downloads a URL straight to disk"),
  URLDownloadToFileW: A("network", "Downloads a URL straight to disk"),
  WinHttpOpen: A("network", "Initialises WinHTTP"),
  WinHttpConnect: A("network", "Connects to an HTTP server"),
  WinHttpSendRequest: A("network", "Sends an HTTP request"),
  WSAStartup: A("network", "Initialises Winsock"),
  socket: A("network", "Creates a socket"),
  connect: A("network", "Connects a socket"),
  send: A("network", "Sends on a socket"),
  recv: A("network", "Receives on a socket"),
  gethostbyname: A("network", "Resolves a host name"),
  getaddrinfo: A("network", "Resolves a host name"),
  DnsQuery_A: A("network", "DNS query"),
  DnsQuery_W: A("network", "DNS query"),
  CryptEncrypt: A("crypto", "Encrypts data (CryptoAPI)"),
  CryptDecrypt: A("crypto", "Decrypts data (CryptoAPI)"),
  CryptGenKey: A("crypto", "Generates a key (CryptoAPI)"),
  CryptImportKey: A("crypto", "Imports a key (CryptoAPI)"),
  CryptAcquireContextA: A("crypto", "Opens a CryptoAPI provider"),
  CryptAcquireContextW: A("crypto", "Opens a CryptoAPI provider"),
  BCryptEncrypt: A("crypto", "Encrypts data (CNG)"),
  BCryptDecrypt: A("crypto", "Decrypts data (CNG)"),
  BCryptGenerateSymmetricKey: A("crypto", "Creates a symmetric key (CNG)"),
  LoadLibraryA: A("dynamic-loading", "Loads a DLL at run time"),
  LoadLibraryW: A("dynamic-loading", "Loads a DLL at run time"),
  LoadLibraryExA: A("dynamic-loading", "Loads a DLL at run time"),
  LoadLibraryExW: A("dynamic-loading", "Loads a DLL at run time"),
  LdrLoadDll: A("dynamic-loading", "Native DLL loading"),
  GetProcAddress: A("dynamic-loading", "Resolves a function address at run time"),
  LdrGetProcedureAddress: A("dynamic-loading", "Native function resolution"),
  DeleteFileA: A("filesystem", "Deletes a file"),
  DeleteFileW: A("filesystem", "Deletes a file"),
  MoveFileExA: A("filesystem", "Moves a file (can schedule replace-on-reboot)"),
  MoveFileExW: A("filesystem", "Moves a file (can schedule replace-on-reboot)"),
  FindFirstFileA: A("filesystem", "Enumerates files"),
  FindFirstFileW: A("filesystem", "Enumerates files"),
  FindFirstFileExW: A("filesystem", "Enumerates files"),
  SetFileAttributesA: A("filesystem", "Changes file attributes (hidden / system)"),
  SetFileAttributesW: A("filesystem", "Changes file attributes (hidden / system)"),
  SetFileTime: A("filesystem", "Changes file timestamps"),
};

export function apiInfo(name: string): ApiInfo | undefined {
  return CATALOGUE[name];
}

export interface CapabilityRule {
  id: string;
  title: string;
  attack: string[];
  severity: "info" | "low" | "medium" | "high";
  /** Every group must be satisfied by at least one import. */
  all: string[][];
  explanation: string;
}

export const CAPABILITY_RULES: CapabilityRule[] = [
  {
    id: "cap.remote-injection",
    title: "Remote process injection capability",
    attack: ["T1055"],
    severity: "medium",
    all: [["VirtualAllocEx", "NtAllocateVirtualMemory", "NtMapViewOfSection"], ["WriteProcessMemory", "NtWriteVirtualMemory", "NtMapViewOfSection"], ["CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext"]],
    explanation: "Imports for allocating memory in another process, writing to it, and starting execution there. Debuggers and some security tools use the same calls.",
  },
  {
    id: "cap.hollowing",
    title: "Process hollowing capability",
    attack: ["T1055.012"],
    severity: "high",
    all: [["NtUnmapViewOfSection", "ZwUnmapViewOfSection"], ["SetThreadContext", "Wow64SetThreadContext"], ["ResumeThread", "NtResumeThread"]],
    explanation: "Unmapping a process image, redirecting a thread's context and resuming it is the sequence used to hollow a suspended process.",
  },
  {
    id: "cap.apc-injection",
    title: "APC injection capability",
    attack: ["T1055.004"],
    severity: "medium",
    all: [["QueueUserAPC", "NtQueueApcThread"], ["OpenThread", "CreateProcessA", "CreateProcessW"], ["WriteProcessMemory", "NtWriteVirtualMemory"]],
    explanation: "Queues code for execution in another thread after writing it into the target process.",
  },
  {
    id: "cap.keylogging",
    title: "Keystroke capture capability",
    attack: ["T1056.001"],
    severity: "medium",
    all: [["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState"], ["GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "CallNextHookEx", "MapVirtualKeyA", "MapVirtualKeyW", "ToUnicode", "ToAscii"]],
    explanation: "Keyboard hooks or key-state polling combined with window or key translation calls. Accessibility and hotkey software use these too.",
  },
  {
    id: "cap.screen-capture",
    title: "Screen capture capability",
    attack: ["T1113"],
    severity: "low",
    all: [["BitBlt"], ["GetDC", "GetWindowDC"], ["CreateCompatibleBitmap", "CreateCompatibleDC"]],
    explanation: "Device-context copy into an off-screen bitmap. Common in legitimate graphics code; context decides.",
  },
  {
    id: "cap.lsass-dump",
    title: "Process memory dump capability",
    attack: ["T1003.001"],
    severity: "medium",
    all: [["MiniDumpWriteDump"], ["OpenProcess"]],
    explanation: "Opens a process and writes a minidump. Against lsass.exe this dumps credentials; crash reporters also use it.",
  },
  {
    id: "cap.credential-store",
    title: "Credential store access",
    attack: ["T1555"],
    severity: "medium",
    all: [["CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW", "CryptUnprotectData", "LsaRetrievePrivateData"]],
    explanation: "Reads Windows Credential Manager entries, DPAPI-protected blobs or LSA secrets.",
  },
  {
    id: "cap.download-execute",
    title: "Download and execute capability",
    attack: ["T1105"],
    severity: "medium",
    all: [["URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpSendRequest", "HttpSendRequestA", "HttpSendRequestW"], ["CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW"]],
    explanation: "Fetches content over HTTP and can start processes. Installers and updaters do this legitimately.",
  },
  {
    id: "cap.service-install",
    title: "Service creation capability",
    attack: ["T1543.003"],
    severity: "low",
    all: [["OpenSCManagerA", "OpenSCManagerW"], ["CreateServiceA", "CreateServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"]],
    explanation: "Creates or reconfigures Windows services, a persistence and privilege path.",
  },
  {
    id: "cap.token-manipulation",
    title: "Token privilege manipulation",
    attack: ["T1134"],
    severity: "low",
    all: [["OpenProcessToken"], ["AdjustTokenPrivileges"], ["LookupPrivilegeValueA", "LookupPrivilegeValueW"]],
    explanation: "Enables privileges on its own token, commonly SeDebugPrivilege before touching other processes.",
  },
  {
    id: "cap.process-discovery",
    title: "Process enumeration",
    attack: ["T1057"],
    severity: "low",
    all: [["CreateToolhelp32Snapshot", "EnumProcesses"], ["Process32First", "Process32FirstW", "Process32Next", "Process32NextW", "EnumProcesses"]],
    explanation: "Lists running processes, used for targeting injection or detecting analysis tools.",
  },
  {
    id: "cap.debugger-detection",
    title: "Debugger detection",
    attack: ["T1622"],
    severity: "low",
    all: [["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess", "NtSetInformationThread"]],
    explanation: "Checks for a debugger. The C runtime imports IsDebuggerPresent in many ordinary programs, so on its own this is weak.",
  },
  {
    id: "cap.dynamic-resolution",
    title: "Run-time API resolution",
    attack: ["T1027.007"],
    severity: "info",
    all: [["GetProcAddress", "LdrGetProcedureAddress"], ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll", "GetModuleHandleA", "GetModuleHandleW"]],
    explanation: "Resolves functions at run time, which hides them from the import table. Extremely common in legitimate software; it matters when the import table is otherwise tiny.",
  },
  {
    id: "cap.file-encryption",
    title: "File enumeration with encryption",
    attack: ["T1486"],
    severity: "medium",
    all: [["FindFirstFileA", "FindFirstFileW", "FindFirstFileExW"], ["CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "BCryptGenerateSymmetricKey"], ["MoveFileExA", "MoveFileExW", "DeleteFileA", "DeleteFileW", "WriteFile"]],
    explanation: "Walks files, encrypts data and rewrites or deletes files: the building blocks of encryption for impact. Backup and archiving tools share them.",
  },
];

export interface CapabilityHit {
  rule: CapabilityRule;
  matched: string[];
}

/** Match capability rules against a set of imported function names (case-sensitive, A/W suffixes listed explicitly). */
export function matchCapabilities(imported: Iterable<string>): CapabilityHit[] {
  const set = new Set(imported);
  const hits: CapabilityHit[] = [];
  for (const rule of CAPABILITY_RULES) {
    const matched: string[] = [];
    let ok = true;
    for (const group of rule.all) {
      const found = group.filter((n) => set.has(n));
      if (!found.length) {
        ok = false;
        break;
      }
      for (const f of found) if (!matched.includes(f)) matched.push(f);
    }
    if (ok) hits.push({ rule, matched });
  }
  return hits;
}
