# Identity and Access Security Queries

## Overview
Advanced hunting queries focused on identity security, authentication anomalies, and access control threats in Microsoft 365 environments. These queries help detect account compromise, privilege escalation, and suspicious authentication patterns.

**Author**: Ali AlEnezi  
**Last Updated**: September 2025  
**MITRE ATT&CK Coverage**: T1078, T1110, T1556, T1087, T1069, T1484  

---

## 🔑 Authentication Anomaly Detection

### Impossible Travel Detection
**Description**: Detects logins from geographically impossible locations within a short time frame.  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts)  
**Use Case**: Identify potential account compromise through geolocation analysis

```kql
// Advanced impossible travel detection with risk scoring
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful logins only
| where isnotempty(LocationDetails.countryOrRegion)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend State = tostring(LocationDetails.state)
| sort by UserPrincipalName, TimeGenerated asc
| extend PreviousCountry = prev(Country, 1), PreviousCity = prev(City, 1), PreviousTime = prev(TimeGenerated, 1)
| where UserPrincipalName == prev(UserPrincipalName, 1)  // Same user
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PreviousTime)
| where Country != PreviousCountry and TimeDiff < 360  // Different countries within 6 hours
| extend TravelDistance = case(
    // Major geographical regions with estimated distances
    (PreviousCountry == "United States" and Country == "China") or
    (PreviousCountry == "China" and Country == "United States"), 11000,
    (PreviousCountry == "United Kingdom" and Country == "Australia") or  
    (PreviousCountry == "Australia" and Country == "United Kingdom"), 17000,
    (PreviousCountry == "Germany" and Country == "Japan") or
    (PreviousCountry == "Japan" and Country == "Germany"), 9000,
    // Regional impossible travels
    (PreviousCountry in ("Kuwait", "UAE", "Saudi Arabia") and Country in ("United States", "United Kingdom")), 7000,
    (PreviousCountry in ("United States", "Canada") and Country in ("China", "Russia")), 8000,
    5000  // Default distance for other country pairs
)
| extend MinTravelTime = TravelDistance / 900  // Assuming max speed of 900 km/h (commercial flight)
| where TimeDiff < MinTravelTime
| extend ImpossibleTravelScore = 
    (iff(TimeDiff < 60, 5, 3) +  // Very short time difference
     iff(TravelDistance > 10000, 2, 1) +  // Long distance
     iff(Country in ("China", "Russia", "North Korea", "Iran"), 1, 0) +  // High-risk countries
     iff(AppDisplayName has_any ("Office", "SharePoint", "Exchange"), 1, 0))  // Accessing sensitive apps
| project 
    TimeGenerated,
    UserPrincipalName,
    PreviousCountry, 
    PreviousCity,
    Country,
    City,
    TimeDiff,
    TravelDistance,
    MinTravelTime,
    ImpossibleTravelScore,
    IPAddress,
    AppDisplayName,
    UserAgent
| order by ImpossibleTravelScore desc, TimeGenerated desc
```

### Suspicious Authentication Patterns
**Description**: Identifies unusual authentication patterns that may indicate compromise or attack.  
**MITRE ATT&CK**: T1110 (Brute Force), T1078 (Valid Accounts)

```kql
// Multi-dimensional authentication anomaly detection
SigninLogs  
| where TimeGenerated > ago(7d)
| extend Hour = datetime_part("hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| summarize 
    TotalLogins = count(),
    SuccessfulLogins = countif(ResultType == 0),
    FailedLogins = countif(ResultType != 0),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName), 
    UniqueDevices = dcount(DeviceDetail.deviceId),
    UniqueCountries = dcount(LocationDetails.countryOrRegion),
    AfterHoursLogins = countif(Hour < 6 or Hour > 20),
    WeekendLogins = countif(DayOfWeek in (0, 6)),
    HighRiskSignins = countif(RiskLevelDuringSignIn in ("high", "medium")),
    Countries = make_set(LocationDetails.countryOrRegion),
    Apps = make_set(AppDisplayName),
    IPs = make_set(IPAddress)
    by UserPrincipalName
| extend 
    FailureRate = round((FailedLogins * 100.0) / TotalLogins, 2),
    AfterHoursRate = round((AfterHoursLogins * 100.0) / TotalLogins, 2),
    WeekendRate = round((WeekendLogins * 100.0) / TotalLogins, 2)
| extend AuthAnomalyScore = 
    (iff(UniqueIPs > 10, 3, iff(UniqueIPs > 5, 2, 0)) +
     iff(UniqueCountries > 3, 2, iff(UniqueCountries > 1, 1, 0)) +
     iff(FailureRate > 20, 3, iff(FailureRate > 10, 1, 0)) +
     iff(AfterHoursRate > 50, 2, 0) +
     iff(WeekendRate > 30, 1, 0) +
     iff(HighRiskSignins > 0, 2, 0) +
     iff(TotalLogins > 200, 1, 0))
| where AuthAnomalyScore >= 4
| project 
    UserPrincipalName,
    AuthAnomalyScore,
    TotalLogins,
    SuccessfulLogins,
    FailedLogins,
    FailureRate,
    UniqueIPs,
    UniqueCountries,
    AfterHoursRate,
    WeekendRate,
    HighRiskSignins,
    Countries,
    Apps
| order by AuthAnomalyScore desc, TotalLogins desc
```

---

## 🎯 Privilege Escalation Detection

### Administrative Role Assignment Monitoring
**Description**: Monitors for suspicious administrative role assignments and privilege escalation.  
**MITRE ATT&CK**: T1484.002 (Trust Modification), T1078.004 (Cloud Accounts)

```kql
// Administrative privilege escalation detection
AuditLogs
| where TimeGenerated > ago(24h)
| where Category == "RoleManagement"
| where OperationName has_any (
    "Add member to role", "Add eligible member to role",
    "Add app role assignment", "Update role", "Activate role"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend AdminRole = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend InitiatedBy = iif(isnotempty(InitiatedBy.user.userPrincipalName), 
                          tostring(InitiatedBy.user.userPrincipalName),
                          tostring(InitiatedBy.app.displayName))
| where AdminRole has_any (
    "Global Administrator", "Privileged Role Administrator", "User Administrator",
    "Security Administrator", "Application Administrator", "Cloud Application Administrator",
    "Privileged Authentication Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Teams Administrator", "Compliance Administrator"
)
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d) 
    | where ResultType == 0
    | summarize 
        RecentLogins = count(),
        LoginCountries = dcount(LocationDetails.countryOrRegion),
        RiskyLogins = countif(RiskLevelDuringSignIn in ("high", "medium"))
        by UserPrincipalName
) on $left.TargetUser == $right.UserPrincipalName
| extend PrivEscRisk = 
    (iff(AdminRole has "Global Administrator", 5, 3) +
     iff(LoginCountries > 2, 2, 0) +
     iff(RiskyLogins > 0, 2, 0) +
     iff(RecentLogins < 5, 1, 0) +  // Newly active accounts
     iff(TimeGenerated has_any ("18:", "19:", "20:", "21:"), 1, 0))  // After hours
| where PrivEscRisk >= 4
| project 
    TimeGenerated,
    TargetUser,
    AdminRole, 
    InitiatedBy,
    PrivEscRisk,
    RecentLogins,
    LoginCountries,
    RiskyLogins,
    Result
| order by PrivEscRisk desc, TimeGenerated desc
```

### Service Principal Privilege Abuse
**Description**: Detects suspicious service principal activities and application permissions.  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts), T1484.002 (Trust Modification)

```kql
// Service principal and application permission abuse
union AuditLogs, SigninLogs
| where TimeGenerated > ago(24h)
| where (
    // Application permission changes
    (Category == "ApplicationManagement" and OperationName has_any (
        "Add app role assignment", "Update application", "Add service principal"
    ))
    or
    // Service principal sign-ins
    (AppDisplayName != "" and UserPrincipalName == "" and isnotempty(ServicePrincipalId))
)
| extend ActivityType = case(
    OperationName has "Add app role assignment", "Permission_Grant",
    OperationName has "Update application", "App_Modification", 
    OperationName has "Add service principal", "SP_Creation",
    isnotempty(ServicePrincipalId), "SP_Authentication",
    "Unknown"
)
| extend AppName = case(
    ActivityType == "SP_Authentication", AppDisplayName,
    isnotempty(TargetResources[0].displayName), tostring(TargetResources[0].displayName),
    "Unknown App"
)
| extend Permissions = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Permissions has_any (
    "Directory.ReadWrite.All", "User.ReadWrite.All", "Mail.ReadWrite",
    "Files.ReadWrite.All", "Sites.FullControl.All", "RoleManagement.ReadWrite.Directory"
) or ActivityType == "SP_Authentication"
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where isnotempty(ServicePrincipalId)
    | summarize 
        AuthCount = count(),
        UniqueIPs = dcount(IPAddress),
        UniqueCountries = dcount(LocationDetails.countryOrRegion),
        FailedAuths = countif(ResultType != 0)
        by ServicePrincipalId
) on ServicePrincipalId
| extend SPRiskScore = 
    (iff(Permissions has "Directory.ReadWrite.All", 5, 0) +
     iff(Permissions has "RoleManagement.ReadWrite.Directory", 4, 0) +
     iff(Permissions has_any ("User.ReadWrite.All", "Mail.ReadWrite"), 3, 0) +
     iff(UniqueCountries > 1, 2, 0) +
     iff(AuthCount > 100, 1, 0) +
     iff(FailedAuths > 10, 1, 0))
| where SPRiskScore >= 3 or ActivityType != "SP_Authentication"
| project 
    TimeGenerated,
    ActivityType,
    AppName,
    ServicePrincipalId,
    Permissions,
    SPRiskScore,
    AuthCount,
    UniqueIPs,
    UniqueCountries,
    IPAddress,
    LocationDetails
| order by SPRiskScore desc, TimeGenerated desc
```

---

## 🔍 Account Discovery and Enumeration

### Bulk User Enumeration Detection
**Description**: Identifies attempts to enumerate user accounts and directory information.  
**MITRE ATT&CK**: T1087.003 (Email Account Discovery), T1087.004 (Cloud Account Discovery)

```kql
// User account enumeration and discovery
union AuditLogs, SigninLogs
| where TimeGenerated > ago(24h)
| where (
    // Audit log enumeration activities
    (OperationName has_any ("Get user", "List users", "Get directory role", "Get group"))
    or
    // Failed sign-in attempts that might indicate enumeration
    (ResultType in (50126, 50034, 50053) and isnotempty(UserPrincipalName))  // User doesn't exist, invalid password, account locked
)
| extend EnumerationType = case(
    OperationName has "Get user", "User_Lookup",
    OperationName has "List users", "User_List",
    OperationName has "Get group", "Group_Lookup", 
    OperationName has "Get directory role", "Role_Lookup",
    ResultType == 50126, "Invalid_User_Signin",
    ResultType in (50034, 50053), "Failed_Auth_Attempt", 
    "Unknown"
)
| extend SourceIP = coalesce(IPAddress, tostring(InitiatedBy.user.ipAddress))
| extend InitiatingUser = coalesce(
    UserPrincipalName, 
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| summarize 
    EnumerationAttempts = count(),
    EnumerationTypes = make_set(EnumerationType),
    UniqueTargets = dcount(UserPrincipalName),
    TimeSpan = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated)),
    Apps = make_set(AppDisplayName),
    Countries = make_set(LocationDetails.countryOrRegion)
    by InitiatingUser, SourceIP, bin(TimeGenerated, 10m)
| where EnumerationAttempts >= 10 or UniqueTargets >= 5
| extend EnumerationScore = 
    (iff(EnumerationAttempts > 50, 5, 3) +
     iff(UniqueTargets > 20, 3, 1) +
     iff(TimeSpan < 10, 2, 0) +  // Rapid enumeration
     iff(array_length(Countries) > 1, 1, 0))
| project 
    TimeWindow = TimeGenerated,
    InitiatingUser,
    SourceIP,
    EnumerationScore,
    EnumerationAttempts,
    UniqueTargets,
    TimeSpan,
    EnumerationTypes,
    Countries
| order by EnumerationScore desc, EnumerationAttempts desc
```

### Password Spray Attack Detection
**Description**: Detects password spraying attacks across multiple user accounts.  
**MITRE ATT&CK**: T1110.003 (Password Spraying)

```kql
// Password spray attack detection with timeline analysis
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in (50126, 50034, 50053, 50055, 50057)  // Various authentication failures
| extend FailureReason = case(
    ResultType == 50126, "Invalid_Username",
    ResultType == 50034, "Invalid_Password", 
    ResultType == 50053, "Account_Locked",
    ResultType == 50055, "Expired_Password",
    ResultType == 50057, "Disabled_Account",
    "Other_Failure"
)
| summarize 
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    UniqueApps = dcount(AppDisplayName),
    FailureTypes = make_set(FailureReason),
    TimeSpan = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated)),
    TargetUsers = make_set(UserPrincipalName),
    Apps = make_set(AppDisplayName),
    UserAgents = make_set(UserAgent)
    by IPAddress, LocationDetails.countryOrRegion, bin(TimeGenerated, 30m)
| where UniqueUsers >= 5 and FailedAttempts >= 10  // Multiple users, multiple attempts
| extend SprayPattern = case(
    UniqueUsers > 50 and TimeSpan < 60, "Rapid_Wide_Spray",
    UniqueUsers > 20 and TimeSpan < 180, "Medium_Spray", 
    UniqueUsers > 5 and FailedAttempts > 50, "Persistent_Spray",
    "Low_Volume_Spray"
)
| extend SprayScore = 
    (iff(UniqueUsers > 50, 5, 3) +
     iff(FailedAttempts > 100, 3, 1) +
     iff(TimeSpan < 30, 2, 0) +
     iff(array_length(UserAgents) == 1, 1, 0) +  // Single user agent
     iff(countryOrRegion in ("China", "Russia", "Iran", "North Korea"), 1, 0))
| project 
    TimeWindow = TimeGenerated,
    IPAddress,
    Country = countryOrRegion,
    SprayScore,
    SprayPattern,
    UniqueUsers,
    FailedAttempts,
    TimeSpan,
    FailureTypes,
    Apps,
    UserAgents
| order by SprayScore desc, UniqueUsers desc
```

---

## 🛡️ Conditional Access and MFA Bypass Detection

### MFA Bypass Attempts
**Description**: Detects attempts to bypass multi-factor authentication requirements.  
**MITRE ATT&CK**: T1556.006 (Multi-Factor Authentication), T1078.004 (Cloud Accounts)

```kql
// MFA bypass and manipulation detection
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful logins
| extend MFAResult = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| extend MFAMethod = tostring(AuthenticationDetails[0].authenticationMethod)
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize HistoricalMFA = count() by UserPrincipalName
) on UserPrincipalName
| where (
    // User typically uses MFA but current login doesn't require it
    (HistoricalMFA > 0 and AuthenticationRequirement != "multiFactorAuthentication")
    or
    // MFA satisfied in suspicious ways
    (MFAResult has_any ("Previously satisfied", "MFA requirement skipped"))
    or  
    // Legacy authentication bypassing MFA
    (ClientAppUsed in ("Other clients", "Exchange ActiveSync") and AuthenticationRequirement != "multiFactorAuthentication")
)
| extend BypassType = case(
    MFAResult has "Previously satisfied", "Previous_Satisfaction",
    MFAResult has "skipped", "MFA_Skipped",
    ClientAppUsed == "Exchange ActiveSync", "Legacy_Protocol",
    ClientAppUsed == "Other clients", "Other_Client",
    AuthenticationRequirement != "multiFactorAuthentication" and HistoricalMFA > 0, "Conditional_Access_Bypass",
    "Unknown_Bypass"
)
| extend BypassRisk = 
    (iff(BypassType == "Conditional_Access_Bypass", 4, 2) +
     iff(LocationDetails.countryOrRegion != "Kuwait", 2, 0) +  // Change to your primary country
     iff(RiskLevelDuringSignIn in ("high", "medium"), 2, 0) +
     iff(AppDisplayName has_any ("Exchange", "SharePoint", "Teams"), 1, 0))
| where BypassRisk >= 3
| project 
    TimeGenerated,
    UserPrincipalName,
    BypassType,
    BypassRisk,
    MFAMethod,
    MFAResult,
    ClientAppUsed,
    AppDisplayName,
    IPAddress,
    LocationDetails,
    RiskLevelDuringSignIn
| order by BypassRisk desc, TimeGenerated desc
```

### Conditional Access Policy Bypass
**Description**: Identifies attempts to circumvent conditional access policies.  
**MITRE ATT&CK**: T1078.004 (Cloud Accounts), T1484.002 (Trust Modification)

```kql
// Conditional access policy bypass detection
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful logins
| mv-expand ConditionalAccessPolicies
| extend PolicyName = tostring(ConditionalAccessPolicies.displayName)
| extend PolicyResult = tostring(ConditionalAccessPolicies.result)
| where PolicyResult in ("success", "notApplied", "failure")
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | mv-expand ConditionalAccessPolicies
    | extend PolicyName = tostring(ConditionalAccessPolicies.displayName) 
    | extend PolicyResult = tostring(ConditionalAccessPolicies.result)
    | where PolicyResult == "success"
    | summarize HistoricalPolicyHits = count() by UserPrincipalName, PolicyName
) on UserPrincipalName, PolicyName
| where (
    // Policy typically applies but didn't this time
    (HistoricalPolicyHits > 0 and PolicyResult == "notApplied")
    or
    // High-risk sign-ins that bypassed policies
    (RiskLevelDuringSignIn in ("high", "medium") and PolicyResult != "success")
    or
    // Legacy authentication bypassing modern policies
    (ClientAppUsed in ("Exchange ActiveSync", "Other clients", "IMAP", "POP") and PolicyResult == "notApplied")
)
| extend BypassScenario = case(
    PolicyResult == "notApplied" and HistoricalPolicyHits > 0, "Policy_Not_Applied",
    RiskLevelDuringSignIn in ("high", "medium"), "High_Risk_Bypass",
    ClientAppUsed in ("Exchange ActiveSync", "Other clients"), "Legacy_Auth_Bypass",
    "Unknown_Scenario"
)
| summarize 
    BypassCount = count(),
    Scenarios = make_set(BypassScenario),
    Policies = make_set(PolicyName),
    Apps = make_set(AppDisplayName),
    IPs = make_set(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| extend BypassScore = 
    (iff(BypassCount > 5, 3, 1) +
     iff(array_length(Countries) > 1, 2, 0) +
     iff(Scenarios has "High_Risk_Bypass", 3, 0) +
     iff(Scenarios has "Legacy_Auth_Bypass", 2, 0))
| where BypassScore >= 3
| project 
    TimeWindow = TimeGenerated,
    UserPrincipalName,
    BypassScore,
    BypassCount, 
    Scenarios,
    Policies,
    Countries,
    Apps
| order by BypassScore desc, BypassCount desc
```

---

## 🔐 OAuth and Application Security

### OAuth Application Abuse Detection
**Description**: Detects suspicious OAuth applications and consent grants.  
**MITRE ATT&CK**: T1484.002 (Trust Modification), T1550.001 (Application Access Token)

```kql
// OAuth application and consent abuse detection
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any (
    "Consent to application", "Add OAuth2PermissionGrant",
    "Add app role assignment", "Add service principal"
)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend ConsentType = tostring(AdditionalDetails[0].value)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where Permissions has_any (
    "Directory.ReadWrite.All", "Directory.Read.All", "User.ReadWrite.All",
    "Mail.ReadWrite", "Files.ReadWrite.All", "Sites.FullControl.All",
    "offline_access", "openid", "profile"
)
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where AppDisplayName != ""
    | summarize 
        AppUsage = count(),
        UniqueUsers = dcount(UserPrincipalName),
        Countries = make_set(LocationDetails.countryOrRegion)
        by AppDisplayName
) on $left.AppName == $right.AppDisplayName
| extend OAuthRisk = 
    (iff(Permissions has "Directory.ReadWrite.All", 5, 0) +
     iff(Permissions has "Directory.Read.All", 3, 0) +
     iff(Permissions has_any ("Mail.ReadWrite", "Files.ReadWrite.All"), 2, 0) +
     iff(ConsentType == "AllPrincipals", 3, 1) +  // Admin consent vs user consent
     iff(AppUsage < 5, 2, 0) +  // Rarely used apps with high permissions
     iff(array_length(Countries) > 3, 1, 0))
| where OAuthRisk >= 4
| project 
    TimeGenerated,
    AppName,
    InitiatedByUser,
    Permissions,
    ConsentType,
    OAuthRisk,
    AppUsage,
    UniqueUsers,
    Countries,
    Result
| order by OAuthRisk desc, TimeGenerated desc
```

---

## 📊 Identity Security Analytics

### Risk Score Calculation Engine
**Description**: Comprehensive risk scoring for user accounts based on multiple factors.  
**Use Case**: Prioritize security investigations and implement adaptive access controls

```kql
// Comprehensive user risk scoring engine
let UserBaseline = SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| summarize 
    AvgLoginsPerDay = count() / 30,
    CommonCountries = make_set(LocationDetails.countryOrRegion),
    CommonApps = make_set(AppDisplayName),
    CommonIPs = dcount(IPAddress)
    by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(24h)
| summarize 
    TodayLogins = count(),
    TodayFailures = countif(ResultType != 0),
    TodayCountries = make_set(LocationDetails.countryOrRegion),
    TodayApps = make_set(AppDisplayName),
    TodayIPs = dcount(IPAddress),
    RiskEvents = countif(RiskLevelDuringSignIn in ("high", "medium")),
    AfterHours = countif(datetime_part("hour", TimeGenerated) > 20 or datetime_part("hour", TimeGenerated) < 6)
    by UserPrincipalName
| join kind=inner UserBaseline on UserPrincipalName
| extend 
    VolumeAnomaly = iff(TodayLogins > (AvgLoginsPerDay * 3), 3, 0),
    LocationAnomaly = array_length(set_difference(TodayCountries, CommonCountries)) * 2,
    AppAnomaly = array_length(set_difference(TodayApps, CommonApps)),
    IPAnomaly = iff(TodayIPs > (CommonIPs * 2), 2, 0),
    FailureAnomaly = iff(TodayFailures > 5, 2, 0)
| extend ComprehensiveRiskScore = 
    VolumeAnomaly + LocationAnomaly + AppAnomaly + IPAnomaly + 
    FailureAnomaly + RiskEvents + (AfterHours / 2)
| where ComprehensiveRiskScore >= 5
| project 
    UserPrincipalName,
    ComprehensiveRiskScore,
    TodayLogins,
    VolumeAnomaly,
    LocationAnomaly,
    AppAnomaly,
    IPAnomaly,
    TodayCountries,
    RiskEvents,
    AfterHours
| order by ComprehensiveRiskScore desc
```

---

## 🔧 Identity Security Optimization

### Performance Monitoring
```kql
// Identity security query performance template
SigninLogs
| where TimeGenerated > ago(1h)  // Limit time range for detection rules
| where UserPrincipalName has "@company.com"  // Filter to your domain early
| where ResultType == 0  // Focus on successful logins for most queries
| summarize count() by bin(TimeGenerated, 5m), ResultType
| render timechart
```

### Custom Detection Rules
```kql
// Template for identity-based detection rules
SigninLogs
| where TimeGenerated > ago(1h)
| [your identity threat detection logic]
| extend 
    AlertTitle = "Identity Security Alert",
    AlertSeverity = "High",
    Category = "Authentication Anomaly"
| project 
    TimeGenerated,
    AlertTitle,
    AlertSeverity,
    Category,
    UserPrincipalName,
    IPAddress,
    LocationDetails,
    Evidence = strcat("Suspicious authentication from ", IPAddress)
```

### Integration Points
- **Microsoft Sentinel**: Export high-risk users for extended investigation
- **Conditional Access**: Use risk scores to trigger additional controls  
- **Identity Protection**: Supplement built-in risk detection
- **SIEM Integration**: Forward identity alerts to central security platform

---

*These identity security queries provide comprehensive coverage of authentication threats and account compromise scenarios. Regular tuning based on your organization's normal patterns will improve detection accuracy.*
