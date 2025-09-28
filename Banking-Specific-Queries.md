# Banking-Specific Advanced Hunting Queries

## Overview
Advanced hunting queries specifically designed for banking and financial services environments. These queries focus on detecting threats commonly targeting financial institutions including ATM malware, payment fraud, and core banking system attacks.

**Author**: Ali AlEnezi
**Last Updated**: September 2025  
**MITRE ATT&CK Coverage**: Multiple tactics and techniques  

---

## 🏧 ATM Security Monitoring

### ATM Malware Detection
**Description**: Detects processes commonly associated with ATM malware including jackpotting and cash-out attacks.  
**MITRE ATT&CK**: T1055 (Process Injection), T1027 (Obfuscated Files)

```kql
// ATM-specific malware detection
// Monitors for suspicious processes targeting ATM software and hardware interfaces
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName has_any ("ATM", "NCR", "DIEBOLD", "WINCOR")
| where ProcessCommandLine has_any (
    "CSCSERVICE.EXE",    // Common ATM jackpot malware
    "DISPENSR",          // Cash dispenser interface
    "XFS",               // eXtensions for Financial Services
    "MSXFS",             // Microsoft XFS
    "AGILIS",            // ATM software component
    "APTRA",             // NCR ATM software
    "PROCASH",           // ATM cash management
    "*.xfs"              // XFS configuration files
) or InitiatingProcessCommandLine has_any (
    "svchost.exe -k CSCSERVICE",
    "rundll32.exe *xfs*",
    "regsvr32.exe *xfs*"
)
| where not (ProcessCommandLine has_any ("legitATMService.exe", "authorizedATMUpdate.exe"))
| project 
    Timestamp,
    DeviceName, 
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    ProcessId,
    ParentProcessName,
    MD5 = tostring(MD5)
| order by Timestamp desc
```

### Suspicious ATM Network Communication
**Description**: Identifies unusual network communications from ATM systems that may indicate C2 communications.  
**MITRE ATT&CK**: T1041 (Exfiltration Over C2 Channel)

```kql
// ATM unusual network activity detection  
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName has_any ("ATM", "NCR", "DIEBOLD", "WINCOR")
| where RemoteIPType == "Public"
| where not (RemoteIP has_any (
    "10.",      // Internal networks
    "172.",     // Internal networks  
    "192.168.", // Internal networks
    "banknetwork.local",
    "atmnetwork.internal"
))
| where RemotePort !in (80, 443, 53) // Exclude standard web/DNS traffic
| summarize 
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    DataSent = sum(BytesSent),
    DataReceived = sum(BytesReceived),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, LocalIP
| where ConnectionCount > 10 or UniqueRemoteIPs > 5 or DataSent > 10000000
| order by ConnectionCount desc
```

---

## 💳 Payment Processing Security

### Card Data Scraping Detection
**Description**: Monitors for processes attempting to access or manipulate payment card data.  
**MITRE ATT&CK**: T1005 (Data from Local System), T1056 (Input Capture)

```kql
// Payment card data access monitoring
DeviceFileEvents  
| where Timestamp > ago(24h)
| where FileName has_any (
    "track1", "track2", "track3",     // Magnetic stripe data
    "cvv", "cvv2", "cvc", "cvc2",     // Card verification codes
    "pan", "cardnum",                  // Primary Account Number
    "pinblock", "pinverify",           // PIN verification
    "iso8583", "atmprot"               // Payment protocols
) or FolderPath has_any (
    "\\POS\\",           // Point of Sale
    "\\Payment\\",       // Payment processing
    "\\CardData\\",      // Card data storage  
    "\\Transaction\\",   // Transaction logs
    "\\Terminal\\",      // Terminal data
    "\\Acquirer\\"       // Payment acquirer data
)
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where not (InitiatingProcessFileName has_any (
    "AuthorizedPOS.exe",
    "BankTerminal.exe", 
    "SecurePayment.exe"
))
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### Suspicious Payment Terminal Activity
**Description**: Detects abnormal payment terminal operations that may indicate compromise.  
**MITRE ATT&CK**: T1074 (Data Staged), T1560 (Archive Collected Data)

```kql
// Payment terminal compromise detection
DeviceProcessEvents
| where Timestamp > ago(24h) 
| where DeviceName has_any ("POS", "TERMINAL", "PAYMENT", "ACQUIRER")
| where ProcessCommandLine has_any (
    "netsh wlan",              // WiFi profile manipulation
    "reg add",                 // Registry modification
    "schtasks /create",        // Scheduled task creation
    "powershell -enc",         // Encoded PowerShell
    "cmd.exe /c echo",         // Command execution
    "bitsadmin /transfer",     // File transfer
    "curl", "wget",            // Download tools
    "7z", "winrar", "zip"      // Archive creation
) and not ProcessCommandLine has_any (
    "AuthorizedUpdate.exe",
    "TerminalMaintenance.exe",
    "BankApprovedScript.ps1"
)
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where RemoteIPType == "Public" 
    | where RemotePort !in (80, 443, 53)
    | summarize NetworkConnections = count() by DeviceName
    | where NetworkConnections > 20
) on DeviceName
| project 
    Timestamp,
    DeviceName,
    AccountName, 
    ProcessCommandLine,
    ParentProcessName,
    NetworkConnections
| order by Timestamp desc
```

---

## 🏦 Core Banking System Protection

### Banking Application Tampering
**Description**: Monitors for unauthorized modifications to core banking applications and configurations.  
**MITRE ATT&CK**: T1546 (Event Triggered Execution), T1112 (Modify Registry)

```kql
// Core banking system integrity monitoring
union DeviceFileEvents, DeviceRegistryEvents
| where Timestamp > ago(24h)
| where (
    // Banking application files
    (FolderPath has_any (
        "\\CoreBanking\\",
        "\\CBS\\", 
        "\\BankingCore\\",
        "\\FinancialSoft\\",
        "\\T24\\",           // Temenos T24
        "\\Flexcube\\",      // Oracle Flexcube  
        "\\Finacle\\",       // Infosys Finacle
        "\\SAP Banking\\",   // SAP Banking Platform
        "\\Avaloq\\",        // Avaloq Core Banking
        "\\Silverlake\\"     // Silverlake Axis
    ) and ActionType in ("FileCreated", "FileModified", "FileDeleted"))
    or
    // Banking registry modifications
    (RegistryKey has_any (
        "SOFTWARE\\CoreBanking",
        "SOFTWARE\\CBS", 
        "SOFTWARE\\T24",
        "SOFTWARE\\Flexcube",
        "SOFTWARE\\Finacle",
        "SOFTWARE\\SAP\\Banking"
    ) and ActionType in ("RegistryValueSet", "RegistryKeyDeleted"))
)
| where not (InitiatingProcessFileName has_any (
    "BankingUpdate.exe",
    "CBSPatch.exe", 
    "AuthorizedMaintenance.exe",
    "BankApproved.exe"
))
| project 
    Timestamp,
    DeviceName,
    ActionType,
    iif(isnotempty(FileName), FileName, RegistryKey) as TargetResource,
    iif(isnotempty(FolderPath), FolderPath, RegistryValueName) as Location,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### SWIFT Message Monitoring  
**Description**: Monitors SWIFT (Society for Worldwide Interbank Financial Telecommunication) message handling for suspicious activity.  
**MITRE ATT&CK**: T1020 (Automated Exfiltration), T1041 (Exfiltration Over C2 Channel)

```kql
// SWIFT infrastructure monitoring
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName has_any ("SWIFT", "SWIFTNet", "ALLIANCE", "SAA")
| where ProcessCommandLine has_any (
    "MT103",        // Single customer credit transfer
    "MT202",        // General financial institution transfer  
    "MT950",        // Statement message
    "MT940",        // Customer statement message
    "MT999",        // Free format message
    "FIN.COPY",     // SWIFT message copying
    "MQHA",         // Message Queue Host Adapter
    "SNL",          // SWIFTNet Link
    "AUTOKEY",      // SWIFT security
    "HSM"           // Hardware Security Module
) or FolderPath has_any (
    "\\SWIFT\\",
    "\\Alliance\\", 
    "\\SWIFTNet\\",
    "\\MessageStore\\",
    "\\MQHA\\",
    "\\SNL\\"
)
| where not (ProcessCommandLine has_any (
    "SwiftAuthorized.exe",
    "AllianceUpdate.exe",
    "SwiftMaintenance.exe"
))
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(24h) 
    | where RemotePort in (7541, 7542, 7543) // SWIFT network ports
    | summarize SWIFTConnections = count() by DeviceName
) on DeviceName
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine, 
    ParentProcessName,
    SWIFTConnections
| order by Timestamp desc
```

---

## 🚨 Fraud Detection Queries

### Unusual Transaction Patterns
**Description**: Identifies suspicious patterns in banking transaction logs that may indicate fraud.  
**MITRE ATT&CK**: T1552 (Unsecured Credentials), T1078 (Valid Accounts)

```kql
// Transaction fraud pattern detection
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Interactive"
| where DeviceName has_any ("TELLER", "CASHIER", "BRANCH", "WORKSTATION")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where ProcessCommandLine has_any (
        "TRANSACTION",
        "TRANSFER", 
        "WITHDRAW",
        "DEPOSIT",
        "BALANCE",
        "ACCOUNT"
    )
) on DeviceName
| summarize 
    TransactionCount = count(),
    UniqueAccounts = dcount(AccountName),
    TimeSpan = datetime_diff('minute', max(Timestamp), min(Timestamp)),
    FirstTransaction = min(Timestamp),
    LastTransaction = max(Timestamp)
    by DeviceName
| where TransactionCount > 100 or UniqueAccounts > 20 or TimeSpan < 30
| order by TransactionCount desc
```

### After-Hours Banking Activity
**Description**: Monitors for suspicious banking system access outside normal business hours.  
**MITRE ATT&CK**: T1078 (Valid Accounts), T1021 (Remote Services)

```kql
// After-hours banking system access
DeviceLogonEvents  
| where Timestamp > ago(7d)
| extend Hour = datetime_part("hour", Timestamp)
| extend DayOfWeek = dayofweek(Timestamp) 
| where DeviceName has_any ("BANK", "CORE", "CBS", "TELLER", "BRANCH")
| where (Hour < 6 or Hour > 20) or DayOfWeek in (0, 6) // Before 6 AM, after 8 PM, or weekends
| where LogonType in ("Interactive", "RemoteInteractive")
| where AccountName !has_any ("service", "system", "admin")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("BANKING", "TRANSACTION", "TRANSFER")
    | summarize ProcessCount = count() by DeviceName, AccountName
) on DeviceName, AccountName  
| project 
    Timestamp,
    DeviceName,
    AccountName,
    LogonType,
    Hour,
    DayOfWeek,
    RemoteIP,
    ProcessCount
| order by Timestamp desc
```

---

## 📊 Query Usage Guidelines

### Performance Optimization
- **Time Range**: Always specify appropriate time ranges (typically 1-24 hours for real-time monitoring)
- **Device Filtering**: Use device name patterns specific to your banking environment
- **Exclusions**: Maintain whitelist of authorized banking applications and processes

### Customization for Your Environment
1. **Device Naming**: Update device name patterns to match your organization's naming convention
2. **Application Names**: Modify process and file name filters for your specific banking software
3. **Network Ranges**: Update IP ranges and ports for your banking network infrastructure
4. **Time Zones**: Adjust time-based queries for your local business hours

### Deployment Recommendations
- **Test Environment**: Always validate queries in non-production environment first
- **Gradual Rollout**: Start with detection rules in "audit mode" before enabling blocking
- **Tuning Period**: Allow 2-4 weeks for initial tuning to reduce false positives
- **Regular Updates**: Review and update queries monthly based on new threat intelligence

---

## 🛡️ Security Considerations

### Compliance Requirements
- **PCI DSS**: Queries support card data environment monitoring requirements
- **SOX**: Assists with financial controls monitoring and audit trails  
- **Basel III**: Supports operational risk management requirements
- **Local Regulations**: Adaptable for regional banking compliance (CBK, SAMA, etc.)

### Data Privacy
- **Anonymization**: Consider anonymizing account numbers and personal identifiers in logs
- **Retention**: Align query result retention with data protection policies  
- **Access Control**: Implement proper RBAC for accessing hunting results

---

*These queries are based on real-world banking cybersecurity experience and threat intelligence. Always test and customize for your specific environment.*
