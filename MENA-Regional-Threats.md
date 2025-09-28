# MENA Region Threat Intelligence Queries

## Overview
Advanced hunting queries tailored for Middle East & North Africa (MENA) region-specific threats. These queries incorporate regional threat intelligence, geopolitical threat actors, and localized attack patterns observed in the MENA cybersecurity landscape.

**Author**: Ali AlEnezi
**Region Focus**: Kuwait, UAE, Saudi Arabia, Qatar, Oman, Bahrain, Egypt, Jordan  
**Last Updated**: September 2025  
**Threat Intelligence Sources**: Regional CERTs, MISP, Commercial TI feeds  

---

## 🌍 Regional APT Groups

### MuddyWater (APT Group)
**Description**: Detects activities associated with MuddyWater APT group targeting MENA organizations.  
**MITRE ATT&CK**: T1566.001 (Spear Phishing Attachment), T1059.003 (PowerShell)  
**Regional Impact**: High - Active against government and telecom in MENA

```kql
// MuddyWater APT activity detection
// Known for PowerShell-based attacks and custom tools (POWERSTATS, SHARPSTATS)
union DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
| where Timestamp > ago(24h)
| where (
    // PowerShell execution patterns
    (ProcessCommandLine has_any (
        "-w hidden -noni -nop -c",
        "System.Net.WebClient",
        "DownloadString",
        "IEX(",
        "Invoke-Expression",
        "FromBase64String",
        "-enc",
        "POWERSTATS",
        "SHARPSTATS"
    ))
    or
    // File creation patterns
    (FileName has_any (
        "temp.ps1",
        "update.vbs", 
        "system.bat",
        "adobe.exe",
        "word.exe" // Masquerading filenames
    ) and FolderPath has "\\AppData\\")
    or  
    // Network communication to known infrastructure
    (RemoteIP in (
        "185.161.208.0/24",    // Known MuddyWater infrastructure
        "185.161.209.0/24",
        "5.34.180.0/24",
        "185.161.211.0/24"
    ))
)
| where not (ProcessCommandLine has_any (
    "Microsoft Office",
    "Adobe Reader", 
    "Windows Update"
))
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    FileName,
    RemoteIP,
    ActionType
| order by Timestamp desc
```

### APT33 (Elfin) Detection
**Description**: Monitors for APT33/Elfin activities targeting energy and aviation sectors in MENA.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link), T1055 (Process Injection)

```kql
// APT33 (Elfin) tactical pattern detection
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "TURNEDUP",         // Known APT33 backdoor
    "DROPSHOT",         // APT33 wiper malware
    "SHAPESHIFT",       // APT33 tunneling tool
    "nslookup -q=TXT",  // DNS tunneling technique
    "certutil -decode", // Certificate utility abuse
    "schtasks /create /tn \"Adobe\"", // Persistence mechanism
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
) or InitiatingProcessCommandLine has_any (
    "winword.exe",
    "excel.exe", 
    "outlook.exe"
) and ProcessCommandLine has_any (
    "powershell.exe",
    "cmd.exe /c",
    "rundll32.exe"
)
| join kind=leftouter (
    DeviceNetworkEvents 
    | where Timestamp > ago(24h)
    | where RemotePort in (80, 443, 53)
    | where RemoteIP has_any (
        ".ir",              // Iranian TLD
        "185.15.247.140",   // Known APT33 C2
        "wordpress.com",    // Compromised WordPress sites
        "blogspot.com"      // Compromised blog platforms
    )
    | summarize NetworkActivity = count() by DeviceName
) on DeviceName
| project 
    Timestamp,
    DeviceName, 
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    NetworkActivity
| order by Timestamp desc
```

---

## 🏛️ Government and Critical Infrastructure

### Government Sector Targeting
**Description**: Detects attacks specifically targeting government institutions in MENA region.  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts), T1566.001 (Spear Phishing)

```kql
// Government sector specific threat detection
EmailEvents
| where Timestamp > ago(24h)
| where RecipientEmailAddress has_any (
    ".gov.kw",          // Kuwait government
    ".gov.sa",          // Saudi Arabia government  
    ".gov.ae",          // UAE government
    ".gov.qa",          // Qatar government
    ".gov.om",          // Oman government
    ".gov.bh",          // Bahrain government
    ".gov.jo",          // Jordan government
    ".gov.eg",          // Egypt government
    "@moi.",            // Ministry of Interior variants
    "@mof.",            // Ministry of Finance variants
    "@mod.",            // Ministry of Defense variants
    "@parliament.",     // Parliamentary institutions
    "@cbk.gov.kw",      // Central Bank of Kuwait
    "@sama.gov.sa"      // Saudi Arabian Monetary Authority
) and (
    Subject has_any (
        "Urgent: Security Update",
        "Account Verification Required", 
        "Document Sharing",
        "Meeting Request",
        "Budget Approval",
        "Security Alert",
        "System Maintenance",
        "Regional Conference"
    ) or AttachmentName has_any (
        ".scr", ".pif", ".exe",
        ".docm", ".xlsm", ".pptm",
        "Invoice.pdf", "Document.pdf"
    )
)
| where SenderFromAddress !has_any (
    ".gov.kw", ".gov.sa", ".gov.ae",
    "@microsoft.com", "@office.com"
)
| project 
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress, 
    Subject,
    AttachmentName,
    ThreatTypes,
    DeliveryAction
| order by Timestamp desc
```

### Critical Infrastructure Protection
**Description**: Monitors threats targeting oil, gas, and energy infrastructure common in MENA.  
**MITRE ATT&CK**: T1020 (Automated Exfiltration), T1498 (Network Denial of Service)

```kql
// Energy sector infrastructure monitoring
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName has_any (
    "SCADA", "HMI", "PLC", "RTU",        // Industrial control systems
    "ARAMCO", "ADNOC", "KOC", "QP",      // Major regional energy companies
    "REFINERY", "PIPELINE", "DRILLING"    // Infrastructure keywords
) or ProcessCommandLine has_any (
    "Wonderware",       // SCADA software
    "FactoryTalk",      // Rockwell Automation
    "WinCC",            // Siemens SCADA
    "Citect",           // Schneider Electric
    "GE iFIX",          // GE Digital SCADA
    "Historian",        // Process data historians
    "OPC",              // OLE Process Control
    "Modbus",           // Industrial protocol
    "DNP3"              // Distributed Network Protocol
)
| where (
    // Suspicious network activity
    (RemoteIPType == "Public" and RemotePort !in (80, 443, 53))
    or
    // Suspicious process execution
    (ProcessCommandLine has_any (
        "net user", "net group", "whoami",
        "systeminfo", "tasklist", "netstat",
        "ping", "nslookup", "tracert"
    ))
    or
    // File system access
    (ActionType == "ProcessCreated" and ProcessCommandLine has_any (
        "copy", "xcopy", "robocopy",
        "7z", "winrar", "zip"
    ))
)
| project 
    Timestamp,
    DeviceName,
    ActionType,
    ProcessCommandLine,
    RemoteIP,
    RemotePort,
    AccountName
| order by Timestamp desc
```

---

## 💰 Financial Services Targeting

### Banking Sector Threats
**Description**: Detects threats specifically targeting MENA banking and financial institutions.  
**MITRE ATT&CK**: T1566.001 (Spear Phishing), T1552.001 (Credentials In Files)

```kql
// MENA banking sector threat detection
EmailEvents
| where Timestamp > ago(24h)
| where RecipientEmailAddress has_any (
    "@nbk.com", "@cbk.com.kw",     // Kuwait
    "@samba.com", "@alrajhi-bank.com", "@riyadbank.com",  // Saudi Arabia
    "@adcb.com", "@nbad.com", "@fab.ae",                  // UAE  
    "@qnb.com", "@cbq.qa",                                // Qatar
    "@bankdhofar.com", "@bankmuscat.com",                 // Oman
    "@bbb.com.bh", "@nbonline.com.bh",                    // Bahrain
    "@nbe.com.eg", "@banquemisr.com"                      // Egypt
) and (
    SenderFromAddress has_any (
        "noreply@", "no-reply@", "donotreply@",
        "security@", "admin@", "support@",
        "swift@", "correspondent@", "treasury@"
    ) and Subject has_any (
        "SWIFT Message", "Wire Transfer",
        "Account Security", "KYC Update",
        "Compliance Alert", "AML Notice", 
        "Correspondent Banking", "Settlement",
        "Regulatory Update", "CBK Circular"
    )
) or AttachmentName has_any (
    "swift_message.pdf", "transfer_details.xlsx",
    "kyc_form.docm", "compliance.xlsm",
    "statement.pdf", "invoice.scr"
)
| where not (SenderFromAddress has_any (
    "@swift.com", "@mastercard.com", "@visa.com",
    "@reuters.com", "@bloomberg.com"
))
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(24h) 
    | where Url has_any (".tk", ".ml", ".ga", ".cf") // Suspicious TLDs
    | summarize SuspiciousUrls = count() by NetworkMessageId
) on NetworkMessageId
| project 
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject, 
    AttachmentName,
    SuspiciousUrls,
    ThreatTypes
| order by Timestamp desc
```

---

## 🚨 Regional Malware Families

### Agent Tesla Detection (MENA Variant)
**Description**: Detects Agent Tesla malware variants commonly used in MENA region.  
**MITRE ATT&CK**: T1056.001 (Keylogging), T1041 (Exfiltration Over C2)

```kql
// Agent Tesla malware detection (MENA specific indicators)
union DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents
| where Timestamp > ago(24h)
| where (
    // Process indicators
    (ProcessCommandLine has_any (
        "AgentTesla", "tesla", "agent.exe",
        "Stub.exe", "Client.exe", "Server.exe",
        "temp.exe", "update.exe", "install.exe"
    ) and FolderPath has_any ("\\Temp\\", "\\AppData\\"))
    or
    // File system indicators  
    (FileName has_any (
        "kl.txt", "passwords.txt", "cookies.txt",
        "history.txt", "screenshots.jpg"
    ) and FolderPath has "\\AppData\\Roaming\\")
    or
    // Registry persistence
    (RegistryKey has_any (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Classes\\exefile\\shell\\open\\command"
    ) and RegistryValueData has_any (
        "tesla", "agent", "stub", "client"
    ))
)
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where RemoteIP has_any (
        // Known Agent Tesla C2 servers in MENA region
        "185.183.96.0/24",
        "185.244.25.0/24", 
        "193.29.187.0/24",
        "mail.ru", "yandex.ru", // Common exfil destinations
        "tutanota.com", "protonmail.com"
    )
    | summarize C2Communications = count() by DeviceName
) on DeviceName
| project 
    Timestamp,
    DeviceName,
    ActionType,
    ProcessCommandLine,
    FileName,
    RegistryKey,
    C2Communications
| order by Timestamp desc
```

### Lokibot MENA Variant
**Description**: Monitors for Lokibot information stealer active in MENA region.  
**MITRE ATT&CK**: T1555 (Credentials from Password Stores), T1005 (Data from Local System)

```kql
// Lokibot information stealer detection
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "sqlite3.exe", "sqlite.exe",     // Database access tools
    "taskkill /im chrome.exe",       // Browser process termination
    "taskkill /im firefox.exe",
    "taskkill /im opera.exe",
    "reg query HKCU\\Software",      // Registry enumeration
    "dir /s *.txt", "dir /s *.db",   // File system enumeration
    "netsh wlan show profiles",      // WiFi password extraction
    "cmdkey /list"                   // Windows credential manager
) or InitiatingProcessCommandLine has_any (
    "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe"
) and ProcessCommandLine has_any (
    "Local\\Google\\Chrome\\User Data",
    "AppData\\Roaming\\Mozilla\\Firefox",
    "AppData\\Roaming\\Opera",
    "Microsoft\\Protect\\", // DPAPI
    "Application Data\\Bitcoin",
    "wallet.dat"
)
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where FileName has_any (
        "passwords.txt", "cookies.txt", "autofill.txt",
        "history.txt", "bookmarks.txt", "wallets.txt"
    )
    | summarize StolenFiles = count() by DeviceName
) on DeviceName
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    StolenFiles
| order by Timestamp desc
```

---

## 🌐 Regional Infrastructure Threats

### Telecom Sector Targeting
**Description**: Detects threats against telecommunications infrastructure in MENA.  
**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1021 (Remote Services)

```kql
// Telecommunications sector threat monitoring
DeviceLogonEvents
| where Timestamp > ago(24h)  
| where DeviceName has_any (
    "TELECOM", "MOBILE", "STC", "ETISALAT", 
    "OOREDOO", "ZAIN", "DU", "VIVA", "ORANGE"
) or AccountName has_any (
    "telecom", "network", "radius", "diameter",
    "hss", "mme", "sgw", "pgw"  // 4G/5G core network elements
)
| where LogonType in ("Network", "RemoteInteractive")
| join kind=inner (
    DeviceProcessEvents  
    | where Timestamp > ago(24h)
    | where ProcessCommandLine has_any (
        "ss7", "sigtran", "diameter", "gtp",  // Telecom protocols
        "snmp", "netconf", "cli",             // Network management
        "subscriber", "imsi", "imei",         // Subscriber management  
        "hlr", "hss", "auc",                  // Telecom databases
        "charging", "billing", "cdr"          // Billing systems
    )
    | summarize TelecomProcesses = count() by DeviceName
) on DeviceName
| where TelecomProcesses > 5
| project 
    Timestamp,
    DeviceName,
    AccountName,
    LogonType,
    RemoteIP,
    TelecomProcesses
| order by Timestamp desc
```

---

## 📊 Geopolitical Indicators

### Regional Conflict Indicators
**Description**: Monitors for cyber activities related to regional geopolitical tensions.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link), T1583.001 (Domains)

```kql
// Geopolitical cyber activity indicators
EmailEvents
| where Timestamp > ago(24h)
| where Subject has_any (
    "Yemen", "Syria", "Iran", "Israel", "Palestine",
    "Saudi", "Qatar", "Emirates", "Kuwait", "Bahrain",
    "Regional Summit", "GCC Meeting", "Arab League",
    "Nuclear Deal", "Oil Prices", "OPEC",
    "Military Exercise", "Defense Cooperation"
) or SenderDisplayName has_any (
    "Ministry of Foreign Affairs",
    "Embassy", "Consulate", "Ambassador",
    "Regional Office", "Press Office",
    "News Agency", "Media Center"
) and not SenderFromAddress has_any (
    "@reuters.com", "@ap.org", "@bbc.com",
    "@cnn.com", "@aljazeera.com"
)
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(24h)
    | where Url has_any (
        ".tk", ".ml", ".ga", ".cf",     // Free domains
        "bit.ly", "tinyurl.com",        // URL shorteners
        "dropbox.com", "drive.google.com" // File sharing
    )
    | summarize SuspiciousUrls = count() by NetworkMessageId
) on NetworkMessageId
| project 
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    SuspiciousUrls,
    DeliveryAction
| order by Timestamp desc
```

---

## 🛠️ Regional Customization Guide

### Kuwait-Specific Indicators
```kql
// Kuwait government and critical infrastructure
| where RecipientEmailAddress has_any (
    ".gov.kw", "@kuna.net.kw", "@cbk.gov.kw",
    "@nbk.com", "@kfh.com", "@warba.com",
    "@knpc.com", "@koc.com.kw", "@equate.com"
)
```

### UAE-Specific Indicators  
```kql
// UAE government and business entities
| where RecipientEmailAddress has_any (
    ".gov.ae", ".ac.ae", "@adnoc.ae",
    "@emirates.com", "@etisalat.ae", "@du.ae",
    "@adcb.com", "@nbad.com", "@fab.ae"
)
```

### Saudi Arabia-Specific Indicators
```kql
// Saudi Arabia critical sectors
| where RecipientEmailAddress has_any (
    ".gov.sa", ".edu.sa", "@aramco.com",
    "@saudia.com", "@stc.com.sa", "@sabic.com",
    "@samba.com", "@alrajhi-bank.com"
)
```

---

## 🔍 Threat Intelligence Integration

### IOC Feed Integration
```kql
// Template for integrating regional threat intelligence feeds
let RegionalIOCs = pack_array(
    "185.183.96.0/24",    // Known malicious infrastructure
    "185.244.25.0/24",    // APT group infrastructure  
    "193.29.187.0/24"     // Regional botnet C2
);
DeviceNetworkEvents
| where RemoteIP in (RegionalIOCs)
| project Timestamp, DeviceName, RemoteIP, LocalPort, RemotePort
```

### MISP Integration Template
```kql
// Template for MISP threat intelligence platform integration
externaldata(Indicator:string, Type:string, Source:string) 
[@"https://misp.regional-cert.org/attributes/restSearch.json"]
with(format="json")
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
) on $left.Indicator == $right.RemoteIP
```

---

*These queries are based on threat intelligence from regional CERT organizations and security vendors operating in the MENA region. Regular updates are recommended as threat landscape evolves.*
