# Contributing to M365-Defender-Hunting-MENA

Thank you for your interest in contributing to this repository! This guide will help you understand how to contribute effectively to our collection of Microsoft 365 Defender hunting queries for the MENA region.

## 📋 Contribution Guidelines

### Types of Contributions We Welcome

- 🔍 **New hunting queries** - KQL queries for detecting specific threats
- 🎯 **Custom detection rules** - Ready-to-deploy detection rules
- 🤖 **Automation scripts** - PowerShell, Python, or other automation tools
- 📚 **Documentation improvements** - Enhanced guides, examples, and explanations
- 🐛 **Bug fixes** - Corrections to existing queries or documentation
- 🌍 **Regional threat intelligence** - MENA-specific IOCs and TTPs

### Before You Contribute

1. **Search existing issues** to avoid duplicates
2. **Test your queries** in a Microsoft 365 Defender environment
3. **Follow our coding standards** outlined below
4. **Document your contributions** thoroughly

---

## 🔍 Query Contribution Standards

### Query Quality Requirements

#### 1. Functional Requirements
- ✅ **Query must execute successfully** in M365 Defender
- ✅ **Performance optimized** - include appropriate time filters
- ✅ **Results must be actionable** - clear indicators of malicious activity
- ✅ **Minimize false positives** - include appropriate exclusions

#### 2. Documentation Requirements
- ✅ **Clear description** of what the query detects
- ✅ **MITRE ATT&CK mapping** - specify relevant tactics and techniques
- ✅ **Use case explanation** - when and why to use this query
- ✅ **Customization notes** - how to adapt for different environments

### Query Template

```kql
// [Query Name] - [Brief Description]
// Author: [Your Name] - [Your Role/Organization]
// MITRE ATT&CK: [Tactics/Techniques]
// Last Updated: [Date]
// Use Case: [When to use this query]
// Customization: [How to customize for different environments]

[Your KQL Query Here]
| where Timestamp > ago(24h)  // Always include time filters
| where [additional filters]   // Performance optimization
| project                     // Select only necessary columns
    Timestamp,
    DeviceName,
    AccountName,
    [other relevant columns]
| order by Timestamp desc
```

### Example Query Submission

```kql
// Banking Trojan Process Injection Detection
// Author: Ali AlEnezi - Cybersecurity Specialist, NBK
// MITRE ATT&CK: T1055 (Process Injection), T1082 (System Information Discovery)
// Last Updated: September 2025
// Use Case: Detect banking trojans injecting into legitimate banking processes
// Customization: Update banking process names for your organization's software

DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "bank", "finance", "payment", "trading"
) and InitiatingProcessCommandLine has_any (
    "svchost.exe", "explorer.exe", "winlogon.exe"
)
| where ProcessCommandLine has_any (
    "inject", "hollow", "dll", "thread"
)
| where not (ProcessCommandLine has_any (
    "LegitimateBank.exe", "AuthorizedTrading.exe"
))
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    ProcessId
| order by Timestamp desc
```

---

## 📝 Documentation Standards

### README Structure for New Categories

```markdown
# [Category Name] Advanced Hunting Queries

## Overview
[Brief description of the threat category and its relevance to MENA region]

**Author**: [Your Name] - [Your Role/Organization]  
**Last Updated**: [Date]  
**MITRE ATT&CK Coverage**: [List relevant tactics/techniques]  

---

## [Subcategory 1]

### [Query Name]
**Description**: [What the query detects]  
**MITRE ATT&CK**: [Specific techniques]  
**Regional Relevance**: [Why important for MENA]

[Your KQL Query]

### Performance Notes
- [Performance considerations]
- [Recommended time ranges]
- [Expected result volumes]

### Customization Guide
- [How to adapt for different environments]
- [Organization-specific modifications]

---
```

---

## 🚀 Submission Process

### Step-by-Step Contribution Guide

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YourUsername/M365-Defender-Hunting-MENA.git
   cd M365-Defender-Hunting-MENA
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/new-banking-queries
   ```

3. **Add Your Contribution**
   - Place queries in appropriate category folders
   - Follow naming convention: `ThreatName-Detection.md`
   - Update main README.md if adding new categories

4. **Test Your Queries**
   - Validate syntax in M365 Defender portal
   - Test with sample data if available
   - Document any limitations or requirements

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add banking trojan detection queries for MENA region"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/new-banking-queries
   ```

7. **Create Pull Request**
   - Use descriptive title and detailed description
   - Reference any related issues
   - Include testing results

### Pull Request Template

```markdown
## Description
[Brief description of changes]

## Type of Change
- [ ] New hunting query
- [ ] Bug fix
- [ ] Documentation update  
- [ ] Performance improvement
- [ ] Regional threat intelligence

## Testing
- [ ] Query executes successfully in M365 Defender
- [ ] Results are actionable and relevant
- [ ] Performance is acceptable (< 30 seconds for 24h queries)
- [ ] False positive rate is minimal

## MITRE ATT&CK Mapping
- **Tactics**: [List tactics]
- **Techniques**: [List techniques with IDs]

## Regional Relevance
[Explain why this is relevant for MENA cybersecurity landscape]

## Checklist
- [ ] Code follows repository standards
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Query tested in non-production environment
```

---

## 🎯 Regional Focus Areas

### Priority Threat Categories for MENA

1. **Banking and Financial Services**
   - ATM malware and jackpotting
   - SWIFT network attacks
   - Mobile banking fraud
   - Cryptocurrency threats

2. **Government and Critical Infrastructure**
   - APT groups targeting government
   - Energy sector (oil, gas, renewables)
   - Telecommunications infrastructure
   - Transportation and logistics

3. **Geopolitical Cyber Activities**
   - State-sponsored campaigns
   - Regional conflict-related threats
   - Influence operations
   - Information warfare

4. **Regional Malware Families**
   - Agent Tesla variants
   - Lokibot campaigns
   - Remote access trojans
   - Mobile malware

### Regional Threat Intelligence Sources

- **GCC CERT** - Gulf Cooperation Council Computer Emergency Response Team
- **CERT-Kuwait** - National CERT for Kuwait
- **NCSC-UAE** - UAE National Cyber Security Council
- **NCA-KSA** - Saudi National Cybersecurity Authority
- **Q-CERT** - Qatar Computer Emergency Response Team

---

## 🔧 Development Environment Setup

### Prerequisites

1. **Microsoft 365 Defender Portal Access**
   - Advanced hunting permissions
   - Custom detection rule permissions
   - API access (for automation scripts)

2. **Development Tools**
   - VS Code with KQL extension
   - Git for version control
   - PowerShell 5.1 or 7.x
   - Python 3.8+ (for automation scripts)

### Local Testing Environment

```powershell
# Install KQL extension for VS Code
code --install-extension ms-kusto.kusto

# Clone repository
git clone https://github.com/YourUsername/M365-Defender-Hunting-MENA.git
cd M365-Defender-Hunting-MENA

# Set up branch
git checkout -b feature/your-contribution
```

---

## 📊 Query Performance Guidelines

### Performance Best Practices

1. **Time Range Optimization**
   ```kql
   // Always specify time ranges
   | where Timestamp > ago(24h)  // For real-time detection
   | where Timestamp > ago(7d)   // For trend analysis
   ```

2. **Filtering Efficiency**
   ```kql
   // Filter early and often
   DeviceProcessEvents
   | where Timestamp > ago(24h)           // Time filter first
   | where DeviceName has "SERVER"        // Device filter second
   | where ProcessCommandLine has "cmd"   // Content filter third
   ```

3. **Result Set Limitation**
   ```kql
   // Limit results to prevent timeouts
   | take 1000                    // Limit to 1000 results
   | top 100 by Timestamp desc    // Top 100 most recent
   ```

4. **Join Optimization**
   ```kql
   // Use appropriate join types
   | join kind=inner     // When you need matches in both tables
   | join kind=leftouter // When you need all left table records
   ```

### Performance Testing

Before submitting, test your queries with:
- **24-hour time range** - Should complete within 30 seconds
- **7-day time range** - Should complete within 2 minutes  
- **30-day time range** - Should complete within 5 minutes

---

## 🛡️ Security and Privacy Considerations

### Data Privacy Guidelines

1. **No Sensitive Data in Examples**
   - Use example.com for domain names
   - Use 192.168.1.x for IP addresses
   - Use placeholder user names like "user@domain.com"

2. **Anonymization Requirements**
   ```kql
   // Anonymize sensitive information
   | extend AnonymizedUser = hash_sha256(AccountName)
   | project-away AccountName  // Remove original sensitive field
   ```

3. **Compliance Considerations**
   - Ensure queries comply with local data protection laws
   - Consider data retention policies
   - Respect privacy regulations (GDPR, local equivalents)

### Responsible Disclosure

- **No live malware samples** in the repository
- **No active C2 domains** or IP addresses
- **Historical threat indicators only** (>30 days old)
- **Coordinate with vendors** for 0-day disclosures

---

## 🏆 Recognition and Attribution

### Contributor Recognition

Contributors will be recognized through:
- **Author attribution** in query headers
- **Contributors section** in main README
- **Release notes** for significant contributions
- **LinkedIn recommendations** for substantial contributions

### Quality Standards for Recognition

**Bronze Contributor** (1-5 quality queries)
- Queries execute successfully
- Proper documentation
- MITRE ATT&CK mapping

**Silver Contributor** (6-15 quality queries)  
- Performance optimized queries
- Regional threat intelligence integration
- Community feedback incorporation

**Gold Contributor** (16+ quality queries)
- Innovative detection techniques
- Automation script contributions
- Mentoring other contributors

---

## 📞 Getting Help

### Support Channels

1. **GitHub Issues** - For bug reports and feature requests
2. **GitHub Discussions** - For questions and community discussion
3. **Email** - [site@hotmail.com](mailto:site@hotmail.com) for direct contact
4. **LinkedIn** - [Ali AlEnezi](https://www.linkedin.com/in/alenizi/) for professional networking

### Common Issues and Solutions

**Query Performance Issues**
```kql
// Add appropriate time filters
| where Timestamp > ago(24h)

// Use efficient filtering
| where DeviceName in ("Server1", "Server2")  // Use 'in' for multiple values
```

**False Positive Reduction**
```kql
// Add exclusion filters
| where not (ProcessCommandLine has_any ("legitimate.exe", "approved.exe"))

// Use statistical thresholds
| where ConnectionCount > 100  // Adjust based on environment
```

**Documentation Standards**
- Always include MITRE ATT&CK mapping
- Provide customization guidance
- Explain regional relevance
- Include performance notes

---

## 🚀 Future Roadmap

### Planned Enhancements

- **Automated testing pipeline** for query validation
- **Integration with MISP** for threat intelligence
- **Mobile app** for query reference
- **Training materials** and webinars
- **Multi-language support** (Arabic documentation)

### Community Requests

We're actively seeking contributions in:
- **SOAR integration** playbooks
- **Threat intelligence** feed integration
- **Compliance mapping** (PCI DSS, ISO 27001)
- **Regional customization** templates

---

**Thank you for contributing to the MENA cybersecurity community! 🛡️**

Together, we're building a stronger defense against regional cyber threats.

---

*For questions or support, contact Ali AlEnezi - [site@hotmail.com](mailto:site@hotmail.com)*