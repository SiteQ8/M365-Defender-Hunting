# Microsoft Defender Query Management Automation

## Overview
PowerShell automation scripts for managing Microsoft 365 Defender hunting queries and custom detection rules. These scripts help streamline deployment, testing, and maintenance of hunting queries in enterprise environments.

**Author**: Ali AlEnezi - Cybersecurity Specialist, NBK  
**Last Updated**: September 2025  
**Prerequisites**: Microsoft.Graph.Security PowerShell module, appropriate API permissions  

---

## 🚀 Quick Start

### Installation
```powershell
# Install required modules
Install-Module Microsoft.Graph -Force
Install-Module Microsoft.Graph.Security -Force

# Import modules
Import-Module Microsoft.Graph
Import-Module Microsoft.Graph.Security

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityActions.Read.All"
```

---

## 📜 PowerShell Scripts

### 1. Query Deployment Script

**File**: `Deploy-HuntingQueries.ps1`

```powershell
<#
.SYNOPSIS
    Deploys hunting queries from the repository to Microsoft 365 Defender
.DESCRIPTION
    This script reads KQL queries from markdown files and creates custom detection rules
    in Microsoft 365 Defender. Includes error handling and logging.
.AUTHOR
    Ali AlEnezi - Cybersecurity Specialist, NBK Kuwait
.VERSION
    2.0
.EXAMPLE
    .\Deploy-HuntingQueries.ps1 -QueryPath ".\Banking-Specific\" -Environment "Production"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$QueryPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Production", "Staging", "Testing")]
    [string]$Environment = "Testing",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\deployment.log"
)

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry
}

# Extract KQL queries from markdown files
function Extract-KQLQueries {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw
    $queries = @()
    
    # Regex to extract KQL code blocks
    $pattern = '```kql\s*(.*?)```'
    $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    
    foreach ($match in $matches) {
        $queryContent = $match.Groups[1].Value.Trim()
        $queries += $queryContent
    }
    
    return $queries
}

# Create custom detection rule
function New-CustomDetectionRule {
    param(
        [string]$QueryName,
        [string]$KQLQuery,
        [string]$Description,
        [string]$Severity = "Medium"
    )
    
    try {
        $rule = @{
            displayName = $QueryName
            description = $Description
            queryText = $KQLQuery
            severity = $Severity
            enabled = $true
            frequency = "PT1H"  # Run every hour
            lookbackDuration = "P1D"  # Look back 1 day
        }
        
        # Create the rule using Microsoft Graph API
        $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" -Body ($rule | ConvertTo-Json)
        
        Write-Log "Successfully created detection rule: $QueryName" "SUCCESS"
        return $response
    }
    catch {
        Write-Log "Failed to create detection rule $QueryName`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Main deployment function
function Deploy-QueriesFromDirectory {
    param([string]$Directory)
    
    Write-Log "Starting query deployment from directory: $Directory" "INFO"
    
    $mdFiles = Get-ChildItem -Path $Directory -Filter "*.md" -Recurse
    $deployedCount = 0
    $failedCount = 0
    
    foreach ($file in $mdFiles) {
        Write-Log "Processing file: $($file.Name)" "INFO"
        
        $queries = Extract-KQLQueries -FilePath $file.FullName
        
        foreach ($i, $query in [System.Linq.Enumerable]::Range(0, $queries.Count)) {
            $queryName = "$($file.BaseName)_Query_$($i + 1)"
            $description = "Auto-deployed from $($file.Name) - MENA Security Repository"
            
            if ($Environment -ne "Production") {
                $queryName += "_$Environment"
            }
            
            $result = New-CustomDetectionRule -QueryName $queryName -KQLQuery $queries[$i] -Description $description
            
            if ($result) {
                $deployedCount++
            } else {
                $failedCount++
            }
            
            # Rate limiting
            Start-Sleep -Seconds 2
        }
    }
    
    Write-Log "Deployment completed. Success: $deployedCount, Failed: $failedCount" "INFO"
}

# Main execution
try {
    Write-Log "Starting M365 Defender Query Deployment" "INFO"
    Write-Log "Environment: $Environment" "INFO"
    Write-Log "Query Path: $QueryPath" "INFO"
    
    # Validate path
    if (-not (Test-Path $QueryPath)) {
        throw "Query path does not exist: $QueryPath"
    }
    
    # Deploy queries
    Deploy-QueriesFromDirectory -Directory $QueryPath
    
    Write-Log "Deployment process completed successfully" "SUCCESS"
}
catch {
    Write-Log "Deployment failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
```

### 2. Query Testing Script

**File**: `Test-HuntingQueries.ps1`

```powershell
<#
.SYNOPSIS
    Tests hunting queries for performance and accuracy
.DESCRIPTION
    Validates KQL syntax, tests query performance, and generates reports
.AUTHOR
    Ali AlEnezi - Cybersecurity Specialist, NBK Kuwait
.EXAMPLE
    .\Test-HuntingQueries.ps1 -QueryFile ".\Banking-Specific-Queries.md"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$QueryFile,
    
    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 120,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = ".\query-test-report.html"
)

function Test-QueryPerformance {
    param([string]$Query, [string]$QueryName)
    
    try {
        $startTime = Get-Date
        
        # Execute query with timeout
        $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/runHuntingQuery" -Body @{
            Query = $Query
        } -TimeoutSec $TimeoutSeconds
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        $resultCount = $response.results.Count
        
        return @{
            Success = $true
            Duration = $duration
            ResultCount = $resultCount
            Error = $null
        }
    }
    catch {
        return @{
            Success = $false
            Duration = 0
            ResultCount = 0
            Error = $_.Exception.Message
        }
    }
}

function Generate-TestReport {
    param([array]$Results, [string]$OutputPath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Defender Query Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; }
        .failure { color: red; }
        .summary { background-color: #e7f3ff; padding: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>M365 Defender Query Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Queries: $($Results.Count)</p>
        <p>Successful: $($Results | Where-Object {$_.Success} | Measure-Object).Count</p>
        <p>Failed: $($Results | Where-Object {-not $_.Success} | Measure-Object).Count</p>
        <p>Report Generated: $(Get-Date)</p>
    </div>
    
    <h2>Query Results</h2>
    <table>
        <tr>
            <th>Query Name</th>
            <th>Status</th>
            <th>Duration (s)</th>
            <th>Result Count</th>
            <th>Error</th>
        </tr>
"@

    foreach ($result in $Results) {
        $statusClass = if ($result.Success) { "success" } else { "failure" }
        $status = if ($result.Success) { "✓ PASS" } else { "✗ FAIL" }
        
        $html += @"
        <tr>
            <td>$($result.QueryName)</td>
            <td class="$statusClass">$status</td>
            <td>$($result.Duration)</td>
            <td>$($result.ResultCount)</td>
            <td>$($result.Error)</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Main testing logic
try {
    Write-Host "Starting query testing for file: $QueryFile"
    
    $queries = Extract-KQLQueries -FilePath $QueryFile
    $results = @()
    
    for ($i = 0; $i -lt $queries.Count; $i++) {
        $queryName = "Query_$($i + 1)"
        Write-Host "Testing $queryName..."
        
        $testResult = Test-QueryPerformance -Query $queries[$i] -QueryName $queryName
        $testResult.QueryName = $queryName
        $results += $testResult
        
        Write-Host "  Duration: $($testResult.Duration)s, Results: $($testResult.ResultCount)"
    }
    
    Generate-TestReport -Results $results -OutputPath $ReportPath
    Write-Host "Test report generated: $ReportPath"
}
catch {
    Write-Error "Testing failed: $($_.Exception.Message)"
    exit 1
}
```

### 3. Query Management Script

**File**: `Manage-DefenderQueries.ps1`

```powershell
<#
.SYNOPSIS
    Comprehensive query management for Microsoft 365 Defender
.DESCRIPTION
    Provides functions to list, update, disable, and delete hunting queries and detection rules
.AUTHOR
    Ali AlEnezi - Cybersecurity Specialist, NBK Kuwait
#>

# List all custom detection rules
function Get-CustomDetectionRules {
    try {
        $rules = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules"
        
        $rules.value | Select-Object id, displayName, description, enabled, severity, lastModified | 
            Format-Table -AutoSize
    }
    catch {
        Write-Error "Failed to retrieve detection rules: $($_.Exception.Message)"
    }
}

# Update detection rule
function Update-DetectionRule {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RuleId,
        
        [Parameter(Mandatory=$false)]
        [string]$NewQuery,
        
        [Parameter(Mandatory=$false)]
        [bool]$Enabled,
        
        [Parameter(Mandatory=$false)]
        [string]$Severity
    )
    
    try {
        $updateData = @{}
        
        if ($NewQuery) { $updateData.queryText = $NewQuery }
        if ($null -ne $Enabled) { $updateData.enabled = $Enabled }
        if ($Severity) { $updateData.severity = $Severity }
        
        $response = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules/$RuleId" -Body ($updateData | ConvertTo-Json)
        
        Write-Host "Successfully updated detection rule: $RuleId" -ForegroundColor Green
        return $response
    }
    catch {
        Write-Error "Failed to update detection rule: $($_.Exception.Message)"
    }
}

# Disable detection rules by pattern
function Disable-DetectionRulesByPattern {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Pattern
    )
    
    try {
        $rules = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules"
        
        $matchingRules = $rules.value | Where-Object { $_.displayName -like "*$Pattern*" }
        
        foreach ($rule in $matchingRules) {
            Update-DetectionRule -RuleId $rule.id -Enabled $false
            Write-Host "Disabled rule: $($rule.displayName)" -ForegroundColor Yellow
        }
        
        Write-Host "Disabled $($matchingRules.Count) rules matching pattern '$Pattern'" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to disable rules: $($_.Exception.Message)"
    }
}

# Export queries to JSON
function Export-DetectionRulesToJson {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ExportPath
    )
    
    try {
        $rules = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules"
        
        $exportData = @{
            ExportDate = Get-Date
            TotalRules = $rules.value.Count
            Rules = $rules.value
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
        
        Write-Host "Exported $($rules.value.Count) detection rules to $ExportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export rules: $($_.Exception.Message)"
    }
}

# Generate query performance report
function Get-QueryPerformanceReport {
    param(
        [Parameter(Mandatory=$false)]
        [int]$Days = 7
    )
    
    try {
        # Get query execution statistics from the past week
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$Days)
        
        $queryStats = @()
        
        # This would require custom logging or Microsoft 365 Defender API enhancement
        # For now, we'll create a template structure
        
        Write-Host "Query Performance Report (Last $Days days)" -ForegroundColor Cyan
        Write-Host "=" * 50
        Write-Host "Feature requires enhanced API access or custom logging implementation"
        Write-Host "Consider implementing query execution logging in your environment"
    }
    catch {
        Write-Error "Failed to generate performance report: $($_.Exception.Message)"
    }
}

# Main menu function
function Show-MainMenu {
    Write-Host "`n=== M365 Defender Query Management ===" -ForegroundColor Cyan
    Write-Host "1. List all detection rules"
    Write-Host "2. Export rules to JSON"
    Write-Host "3. Disable rules by pattern"
    Write-Host "4. Performance report"
    Write-Host "5. Exit"
    Write-Host "=" * 40
}

# Interactive mode
function Start-InteractiveMode {
    do {
        Show-MainMenu
        $choice = Read-Host "Select an option (1-5)"
        
        switch ($choice) {
            "1" { Get-CustomDetectionRules }
            "2" { 
                $path = Read-Host "Enter export path (default: .\rules-export.json)"
                if ([string]::IsNullOrEmpty($path)) { $path = ".\rules-export.json" }
                Export-DetectionRulesToJson -ExportPath $path
            }
            "3" {
                $pattern = Read-Host "Enter pattern to match rule names"
                Disable-DetectionRulesByPattern -Pattern $pattern
            }
            "4" { Get-QueryPerformanceReport }
            "5" { Write-Host "Goodbye!" -ForegroundColor Green; break }
            default { Write-Host "Invalid option. Please try again." -ForegroundColor Red }
        }
        
        if ($choice -ne "5") {
            Read-Host "Press Enter to continue..."
        }
    } while ($choice -ne "5")
}

# If script is run directly, start interactive mode
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Start-InteractiveMode
}
```

---

## 🎯 Usage Examples

### Deploy Banking Queries
```powershell
# Deploy all banking-specific queries to testing environment
.\Deploy-HuntingQueries.ps1 -QueryPath ".\Banking-Specific\" -Environment "Testing"

# Deploy to production with logging
.\Deploy-HuntingQueries.ps1 -QueryPath ".\Banking-Specific\" -Environment "Production" -LogPath "C:\Logs\deployment.log"
```

### Test Query Performance
```powershell
# Test all queries in a file
.\Test-HuntingQueries.ps1 -QueryFile ".\MENA-Regional-Threats.md" -ReportPath "C:\Reports\test-report.html"

# Test with custom timeout
.\Test-HuntingQueries.ps1 -QueryFile ".\Banking-Specific-Queries.md" -TimeoutSeconds 300
```

### Manage Existing Rules
```powershell
# Import the management module
Import-Module .\Manage-DefenderQueries.ps1

# List all rules
Get-CustomDetectionRules

# Export rules for backup
Export-DetectionRulesToJson -ExportPath "C:\Backup\rules-backup-$(Get-Date -Format 'yyyyMMdd').json"

# Disable testing rules
Disable-DetectionRulesByPattern -Pattern "Testing"
```

---

## 🔧 Configuration

### API Permissions Required
```powershell
# Required Microsoft Graph permissions
$requiredScopes = @(
    "SecurityEvents.Read.All",
    "SecurityActions.Read.All", 
    "SecurityAlert.Read.All",
    "ThreatHunting.Read.All"
)

Connect-MgGraph -Scopes $requiredScopes
```

### Environment Configuration
```powershell
# Set environment variables
$env:M365_TENANT_ID = "your-tenant-id"
$env:M365_CLIENT_ID = "your-client-id" 
$env:M365_CLIENT_SECRET = "your-client-secret"

# Or use certificate authentication
Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertThumbprint
```

---

## 📊 Monitoring and Alerting

### Query Health Monitoring
```powershell
# Monitor query execution health
function Monitor-QueryHealth {
    $failedQueries = Get-CustomDetectionRules | Where-Object { $_.enabled -eq $false }
    
    if ($failedQueries.Count -gt 0) {
        Send-MailMessage -To "security-team@company.com" -Subject "M365 Defender Queries Disabled" -Body "Check disabled queries"
    }
}

# Schedule monitoring (run from Task Scheduler)
Register-ScheduledTask -TaskName "M365QueryHealthCheck" -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Monitor-QueryHealth.ps1") -Trigger (New-ScheduledTaskTrigger -Daily -At 9AM)
```

---

## 🛡️ Security Best Practices

### Secure Script Execution
```powershell
# Enable execution policy for signed scripts only
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Use credential manager for API keys
Install-Module CredentialManager
$creds = Get-StoredCredential -Target "M365DefenderAPI"
```

### Audit Logging
```powershell
# Enable PowerShell logging
$logPath = "C:\Logs\M365-Defender-Scripts.log"
Start-Transcript -Path $logPath -Append

# Your script execution here

Stop-Transcript
```

---

*These automation scripts accelerate Microsoft 365 Defender query deployment and management, supporting your journey toward Microsoft Security MVP recognition by demonstrating automation expertise and community contribution.*