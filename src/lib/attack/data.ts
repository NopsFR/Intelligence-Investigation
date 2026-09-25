// Curated subset of the MITRE ATT&CK Enterprise matrix (public domain,
// https://attack.mitre.org). This is a hand-picked slice of tactics and
// widely-referenced techniques for the ATT&CK Explorer — not the full STIX
// dataset — chosen to keep the vendored payload small while remaining
// genuinely useful for navigation.

export interface AttackTechnique {
  id: string;
  name: string;
  tacticIds: string[];
  description: string;
  subTechniques?: { id: string; name: string; description: string }[];
  url: string;
}

export interface AttackTactic {
  id: string;
  name: string;
  shortName: string;
  description: string;
}

export const ATTACK_TACTICS: AttackTactic[] = [
  { id: "TA0043", shortName: "reconnaissance", name: "Reconnaissance", description: "Gathering information to plan future adversary operations." },
  { id: "TA0042", shortName: "resource-development", name: "Resource Development", description: "Establishing resources to support operations." },
  { id: "TA0001", shortName: "initial-access", name: "Initial Access", description: "Gaining an initial foothold within a network." },
  { id: "TA0002", shortName: "execution", name: "Execution", description: "Running adversary-controlled code." },
  { id: "TA0003", shortName: "persistence", name: "Persistence", description: "Maintaining a foothold across restarts and credential changes." },
  { id: "TA0004", shortName: "privilege-escalation", name: "Privilege Escalation", description: "Gaining higher-level permissions." },
  { id: "TA0005", shortName: "defense-evasion", name: "Defense Evasion", description: "Avoiding detection throughout a compromise." },
  { id: "TA0006", shortName: "credential-access", name: "Credential Access", description: "Stealing account names and credentials." },
  { id: "TA0007", shortName: "discovery", name: "Discovery", description: "Gaining knowledge of the system and internal network." },
  { id: "TA0008", shortName: "lateral-movement", name: "Lateral Movement", description: "Moving through the environment." },
  { id: "TA0009", shortName: "collection", name: "Collection", description: "Gathering data of interest to the adversary's goal." },
  { id: "TA0011", shortName: "command-and-control", name: "Command and Control", description: "Communicating with compromised systems." },
  { id: "TA0010", shortName: "exfiltration", name: "Exfiltration", description: "Stealing data." },
  { id: "TA0040", shortName: "impact", name: "Impact", description: "Manipulating, interrupting, or destroying systems and data." },
];

export const ATTACK_TECHNIQUES: AttackTechnique[] = [
  {
    id: "T1595",
    name: "Active Scanning",
    tacticIds: ["TA0043"],
    description: "Adversaries may execute active reconnaissance scans to gather information for targeting.",
    url: "https://attack.mitre.org/techniques/T1595/",
  },
  {
    id: "T1589",
    name: "Gather Victim Identity Information",
    tacticIds: ["TA0043"],
    description: "Adversaries may gather information about the victim's identity to support targeting.",
    url: "https://attack.mitre.org/techniques/T1589/",
  },
  {
    id: "T1583",
    name: "Acquire Infrastructure",
    tacticIds: ["TA0042"],
    description: "Adversaries may buy, lease, or rent infrastructure for use throughout their operation.",
    subTechniques: [
      { id: "T1583.001", name: "Domains", description: "Acquiring domain registrations for operational infrastructure." },
      { id: "T1583.006", name: "Web Services", description: "Acquiring web service accounts for hosting or C2 use." },
    ],
    url: "https://attack.mitre.org/techniques/T1583/",
  },
  {
    id: "T1566",
    name: "Phishing",
    tacticIds: ["TA0001"],
    description: "Adversaries may send phishing messages to gain access to victim systems.",
    subTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", description: "Sending emails with malicious attachments." },
      { id: "T1566.002", name: "Spearphishing Link", description: "Sending emails with malicious links." },
    ],
    url: "https://attack.mitre.org/techniques/T1566/",
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tacticIds: ["TA0001"],
    description: "Adversaries may exploit a weakness in an internet-facing host or system to gain access.",
    url: "https://attack.mitre.org/techniques/T1190/",
  },
  {
    id: "T1133",
    name: "External Remote Services",
    tacticIds: ["TA0001", "TA0003"],
    description: "Adversaries may leverage external remote services as a point of initial access or persistence.",
    url: "https://attack.mitre.org/techniques/T1133/",
  },
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tacticIds: ["TA0002"],
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
    subTechniques: [
      { id: "T1059.001", name: "PowerShell", description: "Abusing PowerShell commands and scripts for execution." },
      { id: "T1059.003", name: "Windows Command Shell", description: "Abusing the Windows command shell for execution." },
      { id: "T1059.004", name: "Unix Shell", description: "Abusing Unix shell commands and scripts for execution." },
      { id: "T1059.007", name: "JavaScript", description: "Abusing JavaScript / JScript for execution." },
    ],
    url: "https://attack.mitre.org/techniques/T1059/",
  },
  {
    id: "T1204",
    name: "User Execution",
    tacticIds: ["TA0002"],
    description: "Adversaries may rely on a user performing an action to gain execution, such as opening a file.",
    subTechniques: [
      { id: "T1204.001", name: "Malicious Link", description: "A user clicking a malicious link to gain execution." },
      { id: "T1204.002", name: "Malicious File", description: "A user opening a malicious file to gain execution." },
    ],
    url: "https://attack.mitre.org/techniques/T1204/",
  },
  {
    id: "T1053",
    name: "Scheduled Task/Job",
    tacticIds: ["TA0002", "TA0003", "TA0004"],
    description: "Adversaries may abuse task scheduling functionality to facilitate execution or persistence.",
    subTechniques: [{ id: "T1053.005", name: "Scheduled Task", description: "Abusing the Windows Task Scheduler." }],
    url: "https://attack.mitre.org/techniques/T1053/",
  },
  {
    id: "T1543",
    name: "Create or Modify System Process",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
    subTechniques: [{ id: "T1543.003", name: "Windows Service", description: "Creating or modifying Windows services." }],
    url: "https://attack.mitre.org/techniques/T1543/",
  },
  {
    id: "T1547",
    name: "Boot or Logon Autostart Execution",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
    subTechniques: [{ id: "T1547.001", name: "Registry Run Keys / Startup Folder", description: "Adding an entry to run keys or the startup folder." }],
    url: "https://attack.mitre.org/techniques/T1547/",
  },
  {
    id: "T1055",
    name: "Process Injection",
    tacticIds: ["TA0004", "TA0005"],
    description: "Adversaries may inject code into processes to evade process-based defenses and elevate privileges.",
    url: "https://attack.mitre.org/techniques/T1055/",
  },
  {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tacticIds: ["TA0005"],
    description: "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
    url: "https://attack.mitre.org/techniques/T1027/",
  },
  {
    id: "T1070",
    name: "Indicator Removal",
    tacticIds: ["TA0005"],
    description: "Adversaries may delete or modify artifacts generated on a host to remove evidence of their presence.",
    subTechniques: [{ id: "T1070.004", name: "File Deletion", description: "Deleting files left behind by tools or actions." }],
    url: "https://attack.mitre.org/techniques/T1070/",
  },
  {
    id: "T1112",
    name: "Modify Registry",
    tacticIds: ["TA0005"],
    description: "Adversaries may interact with the Windows Registry to hide configuration information or evade defenses.",
    url: "https://attack.mitre.org/techniques/T1112/",
  },
  {
    id: "T1110",
    name: "Brute Force",
    tacticIds: ["TA0006"],
    description: "Adversaries may use brute force techniques to gain access to accounts.",
    subTechniques: [{ id: "T1110.003", name: "Password Spraying", description: "Attempting a single password across many accounts." }],
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  {
    id: "T1003",
    name: "OS Credential Dumping",
    tacticIds: ["TA0006"],
    description: "Adversaries may attempt to dump credentials to obtain account login information.",
    subTechniques: [{ id: "T1003.001", name: "LSASS Memory", description: "Dumping credential material from LSASS process memory." }],
    url: "https://attack.mitre.org/techniques/T1003/",
  },
  {
    id: "T1087",
    name: "Account Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries may attempt to get a listing of valid accounts on a system or network.",
    url: "https://attack.mitre.org/techniques/T1087/",
  },
  {
    id: "T1018",
    name: "Remote System Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries may attempt to get a listing of other systems by IP address on a network.",
    url: "https://attack.mitre.org/techniques/T1018/",
  },
  {
    id: "T1021",
    name: "Remote Services",
    tacticIds: ["TA0008"],
    description: "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.",
    subTechniques: [{ id: "T1021.001", name: "Remote Desktop Protocol", description: "Using RDP to move laterally." }],
    url: "https://attack.mitre.org/techniques/T1021/",
  },
  {
    id: "T1560",
    name: "Archive Collected Data",
    tacticIds: ["TA0009"],
    description: "Adversaries may compress and/or encrypt data prior to exfiltration.",
    url: "https://attack.mitre.org/techniques/T1560/",
  },
  {
    id: "T1071",
    name: "Application Layer Protocol",
    tacticIds: ["TA0011"],
    description: "Adversaries may communicate using OSI application layer protocols to blend in with existing traffic.",
    subTechniques: [
      { id: "T1071.001", name: "Web Protocols", description: "Using HTTP/HTTPS for command and control." },
      { id: "T1071.004", name: "DNS", description: "Using the DNS protocol for command and control." },
    ],
    url: "https://attack.mitre.org/techniques/T1071/",
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tacticIds: ["TA0011"],
    description: "Adversaries may transfer tools or files from an external system into a compromised environment.",
    url: "https://attack.mitre.org/techniques/T1105/",
  },
  {
    id: "T1568",
    name: "Dynamic Resolution",
    tacticIds: ["TA0011"],
    description: "Adversaries may dynamically establish C2 infrastructure to hinder defensive resolution efforts.",
    subTechniques: [{ id: "T1568.002", name: "Domain Generation Algorithms", description: "Using DGAs to programmatically generate C2 domain names." }],
    url: "https://attack.mitre.org/techniques/T1568/",
  },
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tacticIds: ["TA0010"],
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
    url: "https://attack.mitre.org/techniques/T1041/",
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tacticIds: ["TA0040"],
    description: "Adversaries may encrypt data on target systems to interrupt availability, e.g. ransomware.",
    url: "https://attack.mitre.org/techniques/T1486/",
  },
  {
    id: "T1498",
    name: "Network Denial of Service",
    tacticIds: ["TA0040"],
    description: "Adversaries may perform network denial of service attacks to degrade or block availability.",
    url: "https://attack.mitre.org/techniques/T1498/",
  },
];

export function tacticById(id: string): AttackTactic | undefined {
  return ATTACK_TACTICS.find((t) => t.id === id);
}

export function techniquesForTactic(tacticId: string): AttackTechnique[] {
  return ATTACK_TECHNIQUES.filter((t) => t.tacticIds.includes(tacticId));
}
