# Cloud Application Security Queries

## Overview
Advanced hunting queries for Microsoft 365 cloud applications including SharePoint, OneDrive, Teams, and Exchange Online. These queries focus on data exfiltration, unauthorized access, and cloud-specific attack vectors.

**Author**: Ali AlEnezi
**Last Updated**: September 2025  
**MITRE ATT&CK Coverage**: T1020, T1041, T1567, T1537, T1530, T1114  

---

## 📁 SharePoint and OneDrive Security

### Mass Data Download Detection
**Description**: Detects suspicious bulk downloads from SharePoint and OneDrive that may indicate data exfiltration.  
**MITRE ATT&CK**: T1020 (Automated Exfiltration), T1567.002 (Exfiltration to Cloud Storage)  
**Use Case**: Identify potential data theft or unauthorized bulk access

```kql
// Mass data download and exfiltration detection
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull", "FileDownloadedViaMobileApp")
| extend FileExtension = extract(@"\.([^.]+)$", 1, ObjectName)
| extend FileSizeMB = round(todouble(AdditionalFields.SiteUrl) / 1024 / 1024, 2)
| summarize 
    DownloadCount = count(),
    TotalSizeMB = sum(FileSizeMB),
    UniqueFiles = dcount(ObjectName),
    FileTypes = make_set(FileExtension),
    SensitiveFiles = countif(FileExtension in ("docx", "xlsx", "pdf", "pptx", "txt")),
    TimeSpan = datetime_diff('minute', max(Timestamp), min(Timestamp)),
    Sites = make_set(AdditionalFields.SiteUrl),
    IPs = make_set(IPAddress)
    by AccountDisplayName, bin(Timestamp, 1h)
| where DownloadCount >= 50 or TotalSizeMB >= 500 or SensitiveFiles >= 20
| extend ExfiltrationScore = 
    (iff(DownloadCount > 100, 4, 2) +
     iff(TotalSizeMB > 1000, 3, 1) +
     iff(TimeSpan < 60, 3, 0) +  // Rapid downloads
     iff(SensitiveFiles > 50, 2, 0) +
     iff(array_length(IPs) > 1, 1, 0) +  // Multiple IPs
     iff(array_length(Sites) > 5, 1, 0))  // Multiple sites
| where ExfiltrationScore >= 5
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    ExfiltrationScore,
    DownloadCount,
    TotalSizeMB,
    SensitiveFiles,
    TimeSpan,
    FileTypes,
    Sites,
    IPs
| order by ExfiltrationScore desc, DownloadCount desc
```

### External Sharing Abuse Detection
**Description**: Identifies suspicious external sharing activities that may lead to data exposure.  
**MITRE ATT&CK**: T1537 (Transfer Data to Cloud Account)

```kql
// External sharing and data exposure detection
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType has_any ("SharingSet", "AnonymousLinkCreated", "ExternalUserAdded", "SharingInvitationCreated")
| extend ShareType = case(
    ActionType == "AnonymousLinkCreated", "Anonymous_Link",
    ActionType == "SharingInvitationCreated", "External_Invitation",
    ActionType == "ExternalUserAdded", "External_User_Added",
    ActionType == "SharingSet", "Sharing_Permissions_Set",
    "Other_Sharing"
)
| extend ExternalDomain = extract(@"@(.+)$", 1, tostring(AdditionalFields.TargetUserOrGroupName))
| extend FileExtension = extract(@"\.([^.]+)$", 1, ObjectName)
| where ExternalDomain !in ("company.com", "organization.org")  // Replace with your domains
| summarize 
    SharingEvents = count(),
    ShareTypes = make_set(ShareType),
    ExternalDomains = make_set(ExternalDomain),
    SharedFiles = make_set(ObjectName),
    SensitiveFiles = countif(FileExtension in ("docx", "xlsx", "pdf", "pptx")),
    AnonymousLinks = countif(ShareType == "Anonymous_Link"),
    Sites = make_set(AdditionalFields.SiteUrl)
    by AccountDisplayName, bin(Timestamp, 4h)
| where SharingEvents >= 10 or AnonymousLinks >= 3 or SensitiveFiles >= 5
| extend SharingRisk = 
    (iff(SharingEvents > 25, 4, 2) +
     iff(AnonymousLinks > 5, 4, iff(AnonymousLinks > 0, 2, 0)) +
     iff(SensitiveFiles > 10, 3, 1) +
     iff(array_length(ExternalDomains) > 5, 2, 0) +
     iff(ExternalDomains has_any ("gmail.com", "hotmail.com", "yahoo.com"), 1, 0))
| where SharingRisk >= 5
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    SharingRisk,
    SharingEvents,
    AnonymousLinks,
    SensitiveFiles,
    ShareTypes,
    ExternalDomains,
    Sites
| order by SharingRisk desc, SharingEvents desc
```

### Ransomware File Pattern Detection
**Description**: Detects file modification patterns consistent with ransomware encryption.  
**MITRE ATT&CK**: T1486 (Data Encrypted for Impact)

```kql
// Ransomware file encryption pattern detection
CloudAppEvents
| where Timestamp > ago(6h)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileModified", "FileRenamed", "FileDeleted", "FileUploaded")
| extend FileExtension = extract(@"\.([^.]+)$", 1, ObjectName)
| extend SuspiciousExtension = FileExtension in~ (
    "encrypted", "locked", "crypto", "crypt", "enc", "lock",
    "xxx", "zzz", "aaa", "micro", "teslacrypt", "locky",
    "cerber", "dharma", "maze", "ryuk", "revil"
)
| extend RansomwareFileName = ObjectName has_any (
    "readme", "decrypt", "ransom", "recovery", "unlock",
    "how_to_decrypt", "restore_files", "files_encrypted"
)
| summarize 
    TotalFileChanges = count(),
    SuspiciousFiles = countif(SuspiciousExtension or RansomwareFileName),
    FileTypes = make_set(FileExtension),
    RenamedFiles = countif(ActionType == "FileRenamed"),
    DeletedFiles = countif(ActionType == "FileDeleted"),
    ModifiedFiles = countif(ActionType == "FileModified"),
    TimeSpan = datetime_diff('minute', max(Timestamp), min(Timestamp)),
    AffectedSites = dcount(AdditionalFields.SiteUrl)
    by AccountDisplayName, bin(Timestamp, 30m)
| where (
    SuspiciousFiles >= 5 or
    (RenamedFiles >= 20 and TimeSpan < 30) or
    (ModifiedFiles >= 50 and TimeSpan < 60)
)
| extend RansomwareScore = 
    (iff(SuspiciousFiles > 10, 5, iff(SuspiciousFiles > 0, 3, 0)) +
     iff(RenamedFiles > 50, 4, iff(RenamedFiles > 20, 2, 0)) +
     iff(TimeSpan < 15, 3, iff(TimeSpan < 30, 2, 0)) +
     iff(DeletedFiles > 10, 2, 0) +
     iff(AffectedSites > 1, 1, 0))
| where RansomwareScore >= 5
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    RansomwareScore,
    TotalFileChanges,
    SuspiciousFiles,
    RenamedFiles,
    DeletedFiles,
    TimeSpan,
    AffectedSites,
    FileTypes
| order by RansomwareScore desc, TotalFileChanges desc
```

---

## 💬 Microsoft Teams Security

### Teams Data Exfiltration Detection
**Description**: Monitors for suspicious data sharing and file transfers in Microsoft Teams.  
**MITRE ATT&CK**: T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service)

```kql
// Teams data exfiltration and suspicious file sharing
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Teams"
| where ActionType in ("FileUploaded", "FileShared", "MessageSent", "ChatCreated")
| extend FileExtension = extract(@"\.([^.]+)$", 1, ObjectName)
| extend ExternalUser = iff(AdditionalFields.ParticipantInfo has "@", 
                           extract(@"@(.+)$", 1, tostring(AdditionalFields.ParticipantInfo)), "")
| where ExternalUser !in ("", "company.com", "organization.org")  // Replace with your domains
| summarize 
    Activities = count(),
    FileUploads = countif(ActionType == "FileUploaded"),
    FilesShared = countif(ActionType == "FileShared"),
    Messages = countif(ActionType == "MessageSent"),
    ExternalDomains = make_set(ExternalUser),
    FileTypes = make_set(FileExtension),
    SensitiveFiles = countif(FileExtension in ("docx", "xlsx", "pdf", "pptx", "zip")),
    Chats = dcount(AdditionalFields.ChatName)
    by AccountDisplayName, bin(Timestamp, 2h)
| where Activities >= 20 or FileUploads >= 10 or SensitiveFiles >= 5
| extend TeamsExfilRisk = 
    (iff(FileUploads > 20, 4, 2) +
     iff(SensitiveFiles > 10, 3, 1) +
     iff(array_length(ExternalDomains) > 3, 2, 0) +
     iff(ExternalDomains has_any ("gmail.com", "outlook.com", "yahoo.com"), 1, 0) +
     iff(Chats > 5, 1, 0))
| where TeamsExfilRisk >= 4
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    TeamsExfilRisk,
    Activities,
    FileUploads,
    SensitiveFiles,
    ExternalDomains,
    FileTypes,
    Chats
| order by TeamsExfilRisk desc, FileUploads desc
```

### Teams External Access Abuse
**Description**: Detects abuse of Teams external access and guest user interactions.  
**MITRE ATT&CK**: T1199 (Trusted Relationship)

```kql
// Teams external access and guest user abuse
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Teams"
| where ActionType in ("MemberAdded", "GuestAdded", "TeamCreated", "ChannelCreated")
| extend GuestUser = iff(AdditionalFields.Members has "#EXT#", 
                        extract(@"([^#]+)#EXT#", 1, tostring(AdditionalFields.Members)), "")
| extend ExternalDomain = extract(@"@(.+)_", 1, GuestUser)
| where isnotempty(GuestUser) or ActionType in ("TeamCreated", "ChannelCreated")
| summarize 
    ExternalActivities = count(),
    GuestsAdded = countif(ActionType == "GuestAdded"),
    TeamsCreated = countif(ActionType == "TeamCreated"),
    ChannelsCreated = countif(ActionType == "ChannelCreated"),
    ExternalDomains = make_set(ExternalDomain),
    Teams = make_set(AdditionalFields.TeamName)
    by AccountDisplayName, bin(Timestamp, 4h)
| where GuestsAdded >= 5 or TeamsCreated >= 3 or ExternalActivities >= 10
| extend ExternalAccessRisk = 
    (iff(GuestsAdded > 10, 4, 2) +
     iff(TeamsCreated > 5, 3, 1) +
     iff(array_length(ExternalDomains) > 5, 2, 0) +
     iff(ExternalDomains has_any ("gmail.com", "outlook.com"), 1, 0))
| where ExternalAccessRisk >= 3
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    ExternalAccessRisk,
    GuestsAdded,
    TeamsCreated,
    ChannelsCreated,
    ExternalDomains,
    Teams
| order by ExternalAccessRisk desc, GuestsAdded desc
```

---

## 📧 Exchange Online Security

### Email Forwarding Rule Abuse
**Description**: Detects creation of suspicious email forwarding rules for data exfiltration.  
**MITRE ATT&CK**: T1114.003 (Email Forwarding Rule)

```kql
// Email forwarding rule creation and abuse
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule", "New-TransportRule")
| extend RuleName = tostring(AdditionalFields.Parameters[0].Value)
| extend ForwardTo = tostring(AdditionalFields.Parameters[1].Value)
| extend RuleConditions = tostring(AdditionalFields.Parameters[2].Value)
| extend ExternalDomain = extract(@"@(.+)$", 1, ForwardTo)
| where ExternalDomain !in ("company.com", "organization.org")  // Replace with your domains
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where RiskLevelDuringSignIn in ("high", "medium")
    | summarize RiskyLogins = count() by UserPrincipalName
) on $left.AccountDisplayName == $right.UserPrincipalName
| extend ForwardingRisk = 
    (iff(ExternalDomain in ("gmail.com", "outlook.com", "yahoo.com"), 3, 1) +
     iff(RuleName has_any (".", " ", "temp", "test") or strlen(RuleName) < 5, 2, 0) +
     iff(RuleConditions has_any ("all", "*", ""), 2, 0) +  // Rules that forward all emails
     iff(RiskyLogins > 0, 2, 0) +
     iff(ActionType == "New-TransportRule", 3, 1))  // Organization-wide rules are riskier
| where ForwardingRisk >= 3
| project 
    Timestamp,
    AccountDisplayName,
    RuleName,
    ForwardTo,
    ExternalDomain,
    RuleConditions,
    ForwardingRisk,
    RiskyLogins,
    ActionType
| order by ForwardingRisk desc, Timestamp desc
```

### Mailbox Permission Abuse
**Description**: Identifies suspicious mailbox access permissions and delegation abuse.  
**MITRE ATT&CK**: T1114.002 (Remote Email Collection)

```kql
// Mailbox access permission and delegation abuse
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("Add-MailboxPermission", "Add-RecipientPermission", "Set-Mailbox")
| extend TargetMailbox = tostring(AdditionalFields.Parameters[0].Value)
| extend GrantedTo = tostring(AdditionalFields.Parameters[1].Value)
| extend PermissionType = tostring(AdditionalFields.Parameters[2].Value)
| where PermissionType has_any ("FullAccess", "SendAs", "SendOnBehalfOf", "ReadPermission")
| join kind=leftouter (
    CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application == "Microsoft Exchange Online"
    | where ActionType == "MailItemsAccessed"
    | where AdditionalFields.MailboxOwnerUPN != AccountDisplayName  // Accessing someone else's mailbox
    | summarize SuspiciousAccess = count() by AccountDisplayName
) on $left.GrantedTo == $right.AccountDisplayName
| extend PermissionRisk = 
    (iff(PermissionType == "FullAccess", 4, 2) +
     iff(PermissionType has_any ("SendAs", "SendOnBehalfOf"), 2, 0) +
     iff(SuspiciousAccess > 0, 3, 0) +
     iff(TargetMailbox has_any ("ceo", "cfo", "admin", "exec"), 2, 0) +
     iff(GrantedTo has_any ("temp", "contractor", "external"), 1, 0))
| where PermissionRisk >= 4
| project 
    Timestamp,
    AccountDisplayName,
    TargetMailbox,
    GrantedTo,
    PermissionType,
    PermissionRisk,
    SuspiciousAccess
| order by PermissionRisk desc, Timestamp desc
```

---

## ☁️ Cloud App Security Anomalies

### Unusual Application Access Patterns
**Description**: Detects anomalous access patterns across Microsoft 365 applications.  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts)

```kql
// Cross-application access anomaly detection
let UserBaseline = CloudAppEvents
| where Timestamp > ago(30d)
| summarize 
    AvgDailyActivities = count() / 30,
    CommonApps = make_set(Application),
    CommonIPs = dcount(IPAddress),
    CommonCountries = make_set(AdditionalFields.ClientCountry)
    by AccountDisplayName;
CloudAppEvents
| where Timestamp > ago(24h)
| summarize 
    TodayActivities = count(),
    TodayApps = make_set(Application),
    TodayIPs = dcount(IPAddress),
    TodayCountries = make_set(AdditionalFields.ClientCountry),
    AfterHours = countif(datetime_part("hour", Timestamp) > 20 or datetime_part("hour", Timestamp) < 6),
    HighRiskActions = countif(ActionType has_any ("Delete", "Export", "Download", "Share"))
    by AccountDisplayName
| join kind=inner UserBaseline on AccountDisplayName
| extend 
    VolumeAnomaly = iff(TodayActivities > (AvgDailyActivities * 5), 3, 0),
    AppAnomaly = array_length(set_difference(TodayApps, CommonApps)) * 2,
    LocationAnomaly = array_length(set_difference(TodayCountries, CommonCountries)) * 2,
    IPAnomaly = iff(TodayIPs > (CommonIPs * 3), 2, 0)
| extend CloudAnomalyScore = 
    VolumeAnomaly + AppAnomaly + LocationAnomaly + IPAnomaly + 
    (AfterHours / 5) + (HighRiskActions / 3)
| where CloudAnomalyScore >= 5
| project 
    AccountDisplayName,
    CloudAnomalyScore,
    TodayActivities,
    VolumeAnomaly,
    AppAnomaly,
    LocationAnomaly,
    TodayApps,
    TodayCountries,
    HighRiskActions
| order by CloudAnomalyScore desc
```

### Data Loss Prevention Bypass
**Description**: Identifies attempts to bypass DLP policies and controls.  
**MITRE ATT&CK**: T1562.001 (Disable or Modify Tools)

```kql
// DLP policy bypass and evasion detection
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business", "Microsoft Exchange Online")
| where ActionType in ("FileShared", "FileDownloaded", "MessageSent", "FileUploaded")
| extend FileExtension = extract(@"\.([^.]+)$", 1, ObjectName)
| extend FileName = extract(@"([^/\\]+)$", 1, ObjectName)
| extend SuspiciousPattern = (
    // File name obfuscation patterns
    FileName matches regex @".*\d{10,}.*" or  // Long numeric strings
    FileName has_any ("temp", "tmp", "copy", "backup", "draft") or
    strlen(FileName) > 50 or
    // Extension manipulation
    FileExtension in ("txt", "rtf", "csv") and FileName has_any ("confidential", "sensitive", "private") or
    // Compression and encoding
    FileExtension in ("zip", "rar", "7z") and ActionType in ("FileShared", "FileDownloaded")
)
| extend ExternalRecipient = iff(AdditionalFields.TargetUserOrGroupName has "@" and 
                                not (AdditionalFields.TargetUserOrGroupName has "company.com"),  // Replace with your domain
                                AdditionalFields.TargetUserOrGroupName, "")
| where SuspiciousPattern or isnotempty(ExternalRecipient)
| summarize 
    DLPBypassAttempts = count(),
    SuspiciousFiles = countif(SuspiciousPattern),
    ExternalShares = countif(isnotempty(ExternalRecipient)),
    FileTypes = make_set(FileExtension),
    ExternalRecipients = make_set(ExternalRecipient),
    Apps = make_set(Application)
    by AccountDisplayName, bin(Timestamp, 2h)
| where DLPBypassAttempts >= 10 or ExternalShares >= 3
| extend DLPBypassRisk = 
    (iff(SuspiciousFiles > 5, 3, 1) +
     iff(ExternalShares > 5, 3, 1) +
     iff(array_length(ExternalRecipients) > 3, 2, 0) +
     iff(FileTypes has_any ("zip", "rar", "7z"), 2, 0))
| where DLPBypassRisk >= 3
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    DLPBypassRisk,
    DLPBypassAttempts,
    SuspiciousFiles,
    ExternalShares,
    FileTypes,
    ExternalRecipients
| order by DLPBypassRisk desc, DLPBypassAttempts desc
```

---

## 🏢 Power Platform Security

### Power Platform Data Exfiltration
**Description**: Monitors Power Platform apps for suspicious data access and export activities.  
**MITRE ATT&CK**: T1020 (Automated Exfiltration)

```kql
// Power Platform data access and exfiltration monitoring
CloudAppEvents
| where Timestamp > ago(24h)
| where Application in ("Microsoft Power Apps", "Microsoft Power Automate", "Microsoft Power BI")
| where ActionType in ("ViewReport", "ExportReport", "CreateApp", "RunFlow", "AccessDataSource")
| extend ExternalConnector = AdditionalFields.ConnectorName
| extend DataSource = AdditionalFields.DataSourceName
| where ExternalConnector has_any ("HTTP", "SQL", "SharePoint", "OneDrive", "Outlook") or
      DataSource has_any ("External", "API", "Database")
| summarize 
    PowerPlatformActivities = count(),
    ReportExports = countif(ActionType == "ExportReport"),
    ExternalConnections = countif(ExternalConnector has_any ("HTTP", "SQL")),
    DataSources = make_set(DataSource),
    Apps = make_set(AdditionalFields.AppName),
    Connectors = make_set(ExternalConnector)
    by AccountDisplayName, bin(Timestamp, 4h)
| where PowerPlatformActivities >= 20 or ReportExports >= 5 or ExternalConnections >= 3
| extend PowerPlatformRisk = 
    (iff(ReportExports > 10, 4, 2) +
     iff(ExternalConnections > 5, 3, 1) +
     iff(array_length(DataSources) > 5, 2, 0) +
     iff(Connectors has_any ("HTTP", "SQL", "API"), 2, 0))
| where PowerPlatformRisk >= 4
| project 
    TimeWindow = Timestamp,
    AccountDisplayName,
    PowerPlatformRisk,
    PowerPlatformActivities,
    ReportExports,
    ExternalConnections,
    DataSources,
    Apps,
    Connectors
| order by PowerPlatformRisk desc, ReportExports desc
```

---

## 📊 Cloud Security Analytics Dashboard

### Cloud Security Risk Scorecard
**Description**: Comprehensive risk assessment across all Microsoft 365 cloud applications.  
**Use Case**: Executive dashboard and risk prioritization

```kql
// Comprehensive cloud security risk scorecard
let SharePointRisks = CloudAppEvents
| where Timestamp > ago(24h) and Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileShared", "AnonymousLinkCreated")
| summarize SharePointRiskEvents = count() by AccountDisplayName;
let TeamsRisks = CloudAppEvents  
| where Timestamp > ago(24h) and Application == "Microsoft Teams"
| where ActionType in ("FileUploaded", "GuestAdded", "ExternalUserAdded")
| summarize TeamsRiskEvents = count() by AccountDisplayName;
let ExchangeRisks = CloudAppEvents
| where Timestamp > ago(24h) and Application == "Microsoft Exchange Online" 
| where ActionType in ("New-InboxRule", "Add-MailboxPermission", "MailItemsAccessed")
| summarize ExchangeRiskEvents = count() by AccountDisplayName;
let PowerPlatformRisks = CloudAppEvents
| where Timestamp > ago(24h) and Application in ("Microsoft Power Apps", "Microsoft Power BI")
| where ActionType in ("ExportReport", "CreateApp", "AccessDataSource")
| summarize PowerPlatformRiskEvents = count() by AccountDisplayName;
CloudAppEvents
| where Timestamp > ago(24h)
| summarize TotalCloudActivities = count() by AccountDisplayName
| join kind=fullouter SharePointRisks on AccountDisplayName
| join kind=fullouter TeamsRisks on AccountDisplayName 
| join kind=fullouter ExchangeRisks on AccountDisplayName
| join kind=fullouter PowerPlatformRisks on AccountDisplayName
| extend 
    SharePointRisk = coalesce(SharePointRiskEvents, 0),
    TeamsRisk = coalesce(TeamsRiskEvents, 0), 
    ExchangeRisk = coalesce(ExchangeRiskEvents, 0),
    PowerPlatformRisk = coalesce(PowerPlatformRiskEvents, 0)
| extend OverallCloudRisk = SharePointRisk + TeamsRisk + ExchangeRisk + PowerPlatformRisk
| where OverallCloudRisk >= 10
| project 
    AccountDisplayName = coalesce(AccountDisplayName, AccountDisplayName1, AccountDisplayName2, AccountDisplayName3, AccountDisplayName4),
    OverallCloudRisk,
    TotalCloudActivities,
    SharePointRisk,
    TeamsRisk,
    ExchangeRisk,
    PowerPlatformRisk
| order by OverallCloudRisk desc
```

---

## 🔧 Cloud Security Optimization

### Query Performance Guidelines
```kql
// Performance-optimized cloud app query template
CloudAppEvents
| where Timestamp > ago(1h)  // Appropriate time window for detection rules
| where Application == "Microsoft SharePoint Online"  // Filter early on indexed fields
| where ActionType in ("FileDownloaded", "FileShared")  // Specific action types
| summarize count() by AccountDisplayName, bin(Timestamp, 10m)
| where count_ > 10  // Threshold-based filtering
```

### Integration Recommendations
- **Microsoft Sentinel**: Export high-risk cloud activities for correlation
- **Cloud App Security**: Supplement native MCAS detection capabilities
- **DLP Integration**: Enhance data loss prevention with behavioral analytics
- **SIEM Forwarding**: Send critical cloud security alerts to central platform

### Detection Rule Templates
```kql
// Template for cloud application detection rules
CloudAppEvents
| where Timestamp > ago(1h)
| [your cloud security detection logic]
| extend 
    AlertTitle = "Cloud Application Security Alert",
    AlertSeverity = "High",
    Category = "Data Exfiltration"
| project 
    Timestamp,
    AlertTitle,
    AlertSeverity,
    Category,
    AccountDisplayName,
    Application,
    ActionType,
    Evidence = strcat("Suspicious ", ActionType, " activity in ", Application)
```

---

*These cloud application security queries provide comprehensive monitoring across the Microsoft 365 ecosystem. Regular tuning based on your organization's cloud usage patterns will optimize detection accuracy and reduce false positives.*
