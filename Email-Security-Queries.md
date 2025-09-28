# Email Security Advanced Hunting Queries

## Overview
Comprehensive collection of Microsoft 365 Defender advanced hunting queries for email threat detection. These queries help identify sophisticated email-based attacks including phishing, business email compromise, and malware distribution.

**Author**: Ali AlEnezi - Cybersecurity Specialist  
**Last Updated**: September 2025  
**MITRE ATT&CK Coverage**: T1566.001, T1566.002, T1566.003, T1114, T1020  

---

## 🎯 Business Email Compromise (BEC) Detection

### Executive Impersonation Detection
**Description**: Detects emails impersonating C-suite executives or senior management.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link), T1534 (Internal Spear Phishing)  
**Use Case**: Identify BEC attempts targeting financial departments

```kql
// Executive impersonation and BEC detection
EmailEvents
| where Timestamp > ago(24h)
| where DeliveryAction == "Delivered"
| where SenderDisplayName has_any (
    "CEO", "CFO", "CTO", "President", "Director", 
    "Vice President", "Managing Director", "General Manager"
) or Subject has_any (
    "Urgent Payment", "Wire Transfer", "Invoice Payment",
    "Vendor Payment", "Confidential", "URGENT", "Re: Payment"
)
| where not (SenderFromAddress has_any (
    "@company.com", "@organization.org", "@legitimate-domain.com"
))
| where SenderFromAddress != SenderDisplayName
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(24h)
    | summarize UrlCount = count(), SuspiciousUrls = countif(Url has_any ("bit.ly", "tinyurl", "t.co")) by NetworkMessageId
) on NetworkMessageId
| extend SuspicionScore = 
    (iff(SenderDisplayName has "CEO", 3, 0) +
     iff(SenderDisplayName has "CFO", 3, 0) +
     iff(Subject has "Urgent", 2, 0) +
     iff(Subject has "Payment", 2, 0) +
     iff(SuspiciousUrls > 0, 2, 0))
| where SuspicionScore >= 3
| project 
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderDisplayName,
    Subject,
    DeliveryLocation,
    ThreatTypes,
    SuspicionScore,
    UrlCount,
    SuspiciousUrls
| order by SuspicionScore desc, Timestamp desc
```

### Financial Services BEC Patterns
**Description**: Detects BEC campaigns specifically targeting banking and financial services.  
**MITRE ATT&CK**: T1566.001 (Spear Phishing Attachment)

```kql
// Banking-focused BEC detection
EmailEvents
| where Timestamp > ago(7d)
| where Subject has_any (
    "SWIFT Message", "Wire Transfer Confirmation", "Account Verification",
    "KYC Update", "AML Alert", "Correspondent Bank", "Settlement",
    "Trade Finance", "Letter of Credit", "Remittance", "CBK Circular"
) or SenderDisplayName has_any (
    "Central Bank", "Correspondent Bank", "SWIFT", "Clearing House",
    "Regulatory Authority", "Compliance Department", "Treasury"
)
| where not (SenderFromAddress has_any (
    "@swift.com", "@centralbank", "@regulatoryauth", "@clearinghouse"
))
| extend RiskIndicators = pack_array(
    iff(SenderFromAddress has_any ("gmail.com", "outlook.com", "yahoo.com"), "FreeEmail", ""),
    iff(Subject has_any ("Urgent", "URGENT", "Immediate"), "UrgentLanguage", ""),
    iff(SenderFromAddress != SenderDisplayName, "DisplayNameSpoof", ""),
    iff(Subject has_any ("Confidential", "Restricted", "Internal"), "ConfidentialClaim", "")
) | mv-expand RiskIndicators
| where isnotempty(RiskIndicators)
| summarize 
    RiskFactors = make_set(RiskIndicators),
    RiskCount = dcount(RiskIndicators),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    EmailCount = count()
    by RecipientEmailAddress, SenderFromAddress, Subject
| where RiskCount >= 2
| order by RiskCount desc, EmailCount desc
```

---

## 🦠 Malware and Attachment Analysis

### Suspicious Attachment Detection
**Description**: Identifies potentially malicious email attachments using multiple indicators.  
**MITRE ATT&CK**: T1566.001 (Spear Phishing Attachment), T1027 (Obfuscated Files)

```kql
// Advanced malicious attachment detection
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in~ (
    "exe", "scr", "pif", "com", "bat", "cmd", "vbs", "js",
    "jar", "docm", "xlsm", "pptm", "dotm", "xltm", "potm"
)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(24h)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryLocation
) on NetworkMessageId
| extend SuspiciousIndicators = pack_array(
    iff(FileName has_any ("invoice", "receipt", "statement", "document"), "FakeDocument", ""),
    iff(FileName has_any ("update", "urgent", "important", "security"), "SocialEngineering", ""),
    iff(FileType in~ ("exe", "scr", "pif", "com"), "ExecutableFile", ""),
    iff(FileType in~ ("docm", "xlsm", "pptm"), "MacroEnabled", ""),
    iff(SHA256 == "", "NoHash", ""),
    iff(strlen(FileName) > 50, "LongFileName", "")
)
| mv-expand SuspiciousIndicators
| where isnotempty(SuspiciousIndicators)
| summarize 
    Indicators = make_set(SuspiciousIndicators),
    IndicatorCount = dcount(SuspiciousIndicators),
    AttachmentDetails = make_set(pack("FileName", FileName, "FileType", FileType, "SHA256", SHA256))
    by NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
| where IndicatorCount >= 2
| project 
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress, 
    Subject,
    IndicatorCount,
    Indicators,
    AttachmentDetails
| order by IndicatorCount desc
```

### Archive File Analysis
**Description**: Detects suspicious compressed files that may contain malware.  
**MITRE ATT&CK**: T1027.002 (Software Packing)

```kql
// Suspicious archive file detection
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in~ ("zip", "rar", "7z", "tar", "gz")
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| extend ArchiveRisk = 
    (iff(FileName has_any ("invoice", "document", "file", "attachment"), 2, 0) +
     iff(SenderFromAddress has_any ("gmail", "outlook", "yahoo", "hotmail"), 1, 0) +
     iff(Subject has_any ("urgent", "important", "payment", "statement"), 1, 0) +
     iff(strlen(FileName) < 10 or strlen(FileName) > 40, 1, 0))
| where ArchiveRisk >= 3
| project 
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    FileName,
    FileType,
    SHA256,
    ArchiveRisk,
    DeliveryLocation
| order by ArchiveRisk desc, Timestamp desc
```

---

## 🔗 URL and Link Analysis

### Malicious URL Detection
**Description**: Identifies suspicious URLs in emails using reputation and pattern analysis.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link)

```kql
// Advanced malicious URL detection
EmailUrlInfo
| where Timestamp > ago(24h)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(24h) 
    | where DeliveryAction == "Delivered"
) on NetworkMessageId
| extend URLRisk = pack_array(
    iff(Url has_any (".tk", ".ml", ".ga", ".cf"), "SuspiciousTLD", ""),
    iff(Url has_any ("bit.ly", "tinyurl", "t.co", "goo.gl"), "URLShortener", ""),
    iff(Url matches regex @"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", "IPAddress", ""),
    iff(strlen(tostring(split(Url, "/")[2])) > 30, "LongDomain", ""),
    iff(Url has_any ("-", "_") and Url has_any ("microsoft", "office", "login"), "Typosquatting", ""),
    iff(UrlDomain != Url and UrlDomain has_any ("microsoft", "office365", "outlook"), "BrandAbuse", "")
)
| mv-expand URLRisk
| where isnotempty(URLRisk)
| summarize 
    RiskFactors = make_set(URLRisk),
    RiskScore = dcount(URLRisk),
    URLs = make_set(Url),
    UniqueUrls = dcount(Url)
    by NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
| where RiskScore >= 2 or UniqueUrls > 5
| project 
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    RiskScore,
    RiskFactors,
    UniqueUrls,
    URLs
| order by RiskScore desc, UniqueUrls desc
```

### Credential Harvesting Detection
**Description**: Identifies emails attempting to harvest credentials through fake login pages.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link), T1552.001 (Credentials In Files)

```kql
// Credential harvesting campaign detection
EmailUrlInfo
| where Timestamp > ago(24h)
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| where Url has_any (
    "login", "signin", "auth", "verify", "confirm", "secure", 
    "account", "update", "suspended", "expired"
) or Subject has_any (
    "verify", "confirm", "suspended", "expired", "security alert",
    "account locked", "sign in", "authentication"
)
| where not (UrlDomain has_any (
    "microsoft.com", "office.com", "microsoftonline.com",
    "outlook.com", "live.com", "msauth.net"
))
| extend SpoofingIndicators = pack_array(
    iff(UrlDomain has_any ("microsoft", "office", "outlook") and not (UrlDomain has_any ("microsoft.com", "office.com")), "MicrosoftSpoof", ""),
    iff(UrlDomain has_any ("google", "gmail") and not (UrlDomain has "google.com"), "GoogleSpoof", ""),
    iff(UrlDomain has_any ("apple", "icloud") and not (UrlDomain has "apple.com"), "AppleSpoof", ""),
    iff(UrlDomain has_any ("-", "_") and UrlDomain has_any ("secure", "login", "auth"), "SuspiciousDomain", ""),
    iff(Url matches regex @"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", "DirectIP", "")
)
| mv-expand SpoofingIndicators
| where isnotempty(SpoofingIndicators)
| summarize 
    SpoofingMethods = make_set(SpoofingIndicators),
    SpoofingScore = dcount(SpoofingIndicators),
    SuspiciousUrls = make_set(Url)
    by NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
| project 
    NetworkMessageId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    SpoofingScore,
    SpoofingMethods,
    SuspiciousUrls
| order by SpoofingScore desc
```

---

## 🏢 Internal Email Security

### Internal Phishing Detection
**Description**: Detects phishing emails sent from compromised internal accounts.  
**MITRE ATT&CK**: T1534 (Internal Spear Phishing), T1078.004 (Cloud Accounts)

```kql
// Internal account compromise and lateral phishing
EmailEvents
| where Timestamp > ago(24h)
| where SenderFromAddress has "@company.com" // Replace with your domain
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(24h)
    | summarize ExternalUrls = countif(not (UrlDomain has_any ("company.com", "microsoft.com", "office.com"))) by NetworkMessageId
) on NetworkMessageId
| join kind=leftouter (
    EmailAttachmentInfo  
    | where Timestamp > ago(24h)
    | where FileType in~ ("exe", "zip", "docm", "xlsm")
    | summarize SuspiciousAttachments = count() by NetworkMessageId
) on NetworkMessageId
| where ExternalUrls > 0 or SuspiciousAttachments > 0
| where Subject has_any (
    "urgent", "important", "confidential", "review", "approve",
    "document", "file", "link", "update", "security"
)
| extend InternalPhishingScore = 
    (iff(ExternalUrls > 2, 2, 0) +
     iff(SuspiciousAttachments > 0, 3, 0) +
     iff(Subject has_any ("urgent", "important"), 1, 0) +
     iff(TimeGenerated has_any ("18:", "19:", "20:", "21:", "22:"), 1, 0)) // After hours
| where InternalPhishingScore >= 3
| project 
    Timestamp,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    ExternalUrls,
    SuspiciousAttachments,
    InternalPhishingScore
| order by InternalPhishingScore desc, Timestamp desc
```

### Email Forwarding Rule Abuse
**Description**: Detects creation of suspicious email forwarding rules that may indicate compromise.  
**MITRE ATT&CK**: T1114.003 (Email Forwarding Rule)

```kql
// Suspicious email forwarding rule detection
CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Exchange Online"
| where ActionType == "New-InboxRule"
| extend RawEventData = parse_json(RawEventData)
| extend ForwardTo = tostring(RawEventData.Parameters[1].Value)
| extend RuleName = tostring(RawEventData.Parameters[0].Value)
| where ForwardTo has_any ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com")
    or RuleName has_any (".", " ", "temp", "test", "rule")
    or strlen(RuleName) < 3
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == 0
    | where ClientAppUsed != "Exchange ActiveSync"
    | summarize 
        RecentLogins = count(),
        UniqueIPs = dcount(IPAddress),
        Countries = make_set(LocationDetails.country)
        by UserPrincipalName
    | where UniqueIPs > 3
) on $left.ActorDisplayName == $right.UserPrincipalName
| project 
    Timestamp,
    ActorDisplayName,
    RuleName,
    ForwardTo,
    RecentLogins,
    UniqueIPs,
    Countries
| order by Timestamp desc
```

---

## 📊 Email Volume and Pattern Analysis

### Email Bomb Attack Detection
**Description**: Identifies email bombing or volume-based attacks against specific recipients.  
**MITRE ATT&CK**: T1498.003 (Application or System Exploitation)

```kql
// Email bombing and volume attack detection
EmailEvents
| where Timestamp > ago(1h)
| summarize 
    EmailCount = count(),
    UniqueSenders = dcount(SenderFromAddress),
    UniqueSubjects = dcount(Subject),
    DeliveredCount = countif(DeliveryAction == "Delivered"),
    BlockedCount = countif(DeliveryAction in ("Blocked", "Quarantined"))
    by RecipientEmailAddress
| where EmailCount > 50 // Threshold for suspicious volume
| extend VolumePattern = case(
    UniqueSenders == 1 and UniqueSubjects == 1, "SingleSenderRepeated",
    UniqueSenders > EmailCount * 0.8, "MultiSenderDistributed", 
    UniqueSubjects < EmailCount * 0.1, "LimitedSubjects",
    "MixedPattern"
)
| extend SuspicionScore = 
    (iff(EmailCount > 100, 3, 1) +
     iff(VolumePattern == "SingleSenderRepeated", 2, 0) +
     iff(DeliveredCount > EmailCount * 0.8, 1, 0) +
     iff(BlockedCount > EmailCount * 0.5, 2, 0))
| where SuspicionScore >= 3
| project 
    RecipientEmailAddress,
    EmailCount,
    UniqueSenders,
    UniqueSubjects,
    DeliveredCount,
    BlockedCount,
    VolumePattern,
    SuspicionScore
| order by SuspicionScore desc, EmailCount desc
```

### Newsletter and Bulk Email Abuse
**Description**: Detects abuse of legitimate bulk email services for malicious campaigns.  
**MITRE ATT&CK**: T1566.002 (Spear Phishing Link)

```kql
// Bulk email service abuse detection
EmailEvents
| where Timestamp > ago(24h)
| where SenderFromAddress has_any (
    "mailchimp.com", "constantcontact.com", "sendinblue.com",
    "mailgun.com", "sendgrid.com", "amazonses.com"
)
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(24h)
    | where not (UrlDomain has_any ("unsubscribe", "mailchimp", "constantcontact"))
) on NetworkMessageId
| where Subject has_any (
    "urgent", "verify", "confirm", "suspended", "expired", 
    "security", "payment", "invoice", "winner"
)
| summarize 
    Recipients = dcount(RecipientEmailAddress),
    ExternalUrls = dcount(UrlDomain),
    UniqueSubjects = dcount(Subject),
    SuspiciousUrls = countif(UrlDomain has_any (".tk", ".ml", ".ga", ".cf", "bit.ly"))
    by SenderFromAddress, bin(Timestamp, 1h)
| where Recipients > 10 or SuspiciousUrls > 0
| project 
    TimeWindow = Timestamp,
    SenderFromAddress,
    Recipients,
    ExternalUrls, 
    UniqueSubjects,
    SuspiciousUrls
| order by Recipients desc, SuspiciousUrls desc
```

---

## 🎯 Advanced Persistent Threat (APT) Email Indicators

### Spear Phishing Campaign Detection
**Description**: Identifies coordinated spear phishing campaigns using advanced techniques.  
**MITRE ATT&CK**: T1566.001 (Spear Phishing Attachment), T1585.002 (Email Accounts)

```kql
// Advanced spear phishing campaign detection
EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in~ ("docm", "xlsm", "pdf", "zip")
    | project NetworkMessageId, FileName, FileType, SHA256
) on NetworkMessageId
| extend CampaignIndicators = pack_array(
    iff(SenderDisplayName != "" and SenderFromAddress != SenderDisplayName, "DisplayNameSpoof", ""),
    iff(Subject has_any ("re:", "fwd:") and not (Subject startswith "re:" or Subject startswith "fwd:"), "FakeReply", ""),
    iff(FileName has_any ("invoice", "statement", "document", "report") and FileType != "pdf", "DocumentImpersonation", ""),
    iff(tolower(FileName) has_any ("urgent", "confidential", "important"), "UrgentLanguage", ""),
    iff(SenderFromAddress has_any ("noreply", "no-reply", "donotreply"), "NoReplySpoof", "")
)
| mv-expand CampaignIndicators  
| where isnotempty(CampaignIndicators)
| summarize 
    TacticsUsed = make_set(CampaignIndicators),
    TacticCount = dcount(CampaignIndicators),
    Recipients = dcount(RecipientEmailAddress),
    Attachments = make_set(FileName),
    TimeSpan = datetime_diff('hour', max(Timestamp), min(Timestamp))
    by SenderFromAddress, SHA256, Subject
| where TacticCount >= 2 or Recipients >= 3
| extend CampaignScore = (TacticCount * 2) + Recipients
| project 
    SenderFromAddress,
    Subject,
    Recipients,
    CampaignScore,
    TacticsUsed,
    Attachments,
    TimeSpan,
    SHA256
| order by CampaignScore desc
```

---

## 🔧 Email Security Optimization

### Email Security Policy Effectiveness
**Description**: Analyzes effectiveness of email security policies and filters.  
**Use Case**: Optimize security configurations based on threat patterns

```kql
// Email security policy effectiveness analysis
EmailEvents
| where Timestamp > ago(7d)
| summarize 
    TotalEmails = count(),
    DeliveredEmails = countif(DeliveryAction == "Delivered"),
    BlockedEmails = countif(DeliveryAction == "Blocked"),
    QuarantinedEmails = countif(DeliveryAction == "Quarantined"),
    SpamEmails = countif(ThreatTypes has "Spam"),
    PhishingEmails = countif(ThreatTypes has "Phish"),
    MalwareEmails = countif(ThreatTypes has "Malware")
    by bin(Timestamp, 1d), DeliveryLocation
| extend 
    BlockRate = round((BlockedEmails * 100.0) / TotalEmails, 2),
    QuarantineRate = round((QuarantinedEmails * 100.0) / TotalEmails, 2),
    DeliveryRate = round((DeliveredEmails * 100.0) / TotalEmails, 2),
    ThreatDetectionRate = round(((SpamEmails + PhishingEmails + MalwareEmails) * 100.0) / TotalEmails, 2)
| project 
    Date = format_datetime(Timestamp, 'yyyy-MM-dd'),
    DeliveryLocation,
    TotalEmails,
    DeliveryRate,
    BlockRate,
    QuarantineRate,
    ThreatDetectionRate,
    SpamEmails,
    PhishingEmails,
    MalwareEmails
| order by Date desc, DeliveryLocation
```

---

## 📋 Query Deployment Guidelines

### Performance Optimization
- **Time Range**: Most queries use 24h for real-time monitoring
- **Result Limiting**: Add `| take 1000` for queries that might return large result sets  
- **Indexing**: Filter on Timestamp first, then other indexed fields
- **Joins**: Use appropriate join types and limit join scope when possible

### Customization Requirements
1. **Domain Names**: Replace "company.com" with your organization's domain
2. **Thresholds**: Adjust numerical thresholds based on your email volume
3. **Exclusions**: Add legitimate senders and services to exclusion lists
4. **Time Zones**: Modify after-hours detection based on your timezone

### Detection Rule Creation
```kql
// Template for converting to detection rule
EmailEvents
| where Timestamp > ago(1h)  // Adjust frequency as needed
| [your query logic here]
| project 
    Timestamp,
    AlertTitle = "Email Security Alert",
    AlertSeverity = "Medium", 
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    ThreatIndicators = "Suspicious Email Pattern"
```

---

*These queries provide comprehensive email security monitoring capabilities. Regular tuning and customization for your environment will improve detection accuracy and reduce false positives.*