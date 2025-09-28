# Email Security Advanced Hunting Queries

## Overview
Comprehensive collection of Microsoft 365 Defender advanced hunting queries for email threat detection. These queries help identify sophisticated email-based attacks including phishing, business email compromise, and malware distribution.

**Author**: Ali AlEnezi  
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

*[Rest of content remains the same, just updating author attribution]*