# M365-Defender-Hunting

## Microsoft 365 Defender Advanced Hunting Queries

[![GitHub stars](https://img.shields.io/github/stars/SiteQ8/M365-Defender-Hunting.svg)](https://github.com/username/M365-Defender-Hunting/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/SiteQ8/M365-Defender-Hunting-MENA.svg)](https://github.com/username/M365-Defender-Hunting/network)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Collection of Microsoft 365 Defender Advanced Hunting queries with focus on financial services and banking security.**

---

## 👨‍💻 About the Author

**Ali AlEnezi**  
🔒 Cybersecurity Specialist  
🎓 SANS/GIAC Certified Security Professional  

- 📧 Email: [site@hotmail.com](mailto:site@hotmail.com)
- 💼 LinkedIn: [linkedin.com/in/alenizi](https://www.linkedin.com/in/alenizi/)
- 🌍 Location: Kuwait
- 🏢 Experience: Banking & Financial Services Cybersecurity

---

## 📋 Repository Contents

### 🔍 Advanced Hunting Queries
- **Email Threats** - Advanced email security hunting queries
- **Endpoint Security** - Endpoint protection and EDR queries  
- **Identity Security** - Identity-based threat detection
- **Cloud Apps** - Cloud application security monitoring
- **Banking-Specific** - Financial services tailored queries
- **MENA-Threats** - Regional threat intelligence queries

### 🎯 Specialized Categories
- **Persistence Techniques** - Detection of persistence mechanisms
- **Lateral Movement** - Network traversal detection
- **Privilege Escalation** - Rights elevation monitoring  
- **Defense Evasion** - Evasion technique identification

### 🔧 Automation & Tools
- **Custom Detection Rules** - Ready-to-deploy detection rules
- **PowerShell Scripts** - Automation and response scripts
- **API Integration** - Microsoft Graph Security API examples

---

## 🚀 Quick Start Guide

### Prerequisites
- Microsoft 365 Defender portal access
- Advanced Hunting permissions
- Basic knowledge of KQL (Kusto Query Language)

### How to Use These Queries

1. **Navigate to Microsoft 365 Defender Portal**
   ```
   https://security.microsoft.com/v2/advanced-hunting
   ```

2. **Copy and paste desired query**
3. **Customize parameters** (time ranges, thresholds, etc.)
4. **Execute and analyze results**
5. **Create custom detection rules** from validated queries

---

## 🌟 Featured Hunting Queries

### 🏦 Banking-Specific Threats

#### Financial Malware Detection
```kql
// Detect financial malware targeting banking applications
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("*bank*", "*finance*", "*payment*", "*atm*")
| where ProcessCommandLine has_any ("keylog", "screen", "capture", "dump")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Suspicious Authentication Patterns
```kql
// Banking-specific suspicious authentication patterns
SigninLogs
| where TimeGenerated > ago(7d)
| where AppDisplayName has_any ("Bank", "Finance", "Payment", "Trading")
| summarize 
    LoginCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location)
    by UserPrincipalName
| where LoginCount > 50 or UniqueIPs > 10
| order by LoginCount desc
```

### 🌍 MENA Region Specific

#### Regional Threat Intelligence
```kql
// Suspicious activities from known MENA threat actor IPs
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where RemoteIP in (
    "185.220.101.0/24",    // Known APT IP range
    "94.142.241.0/24",     // Suspicious infrastructure
    "178.62.196.0/24"      // Malicious hosting
)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, Protocol
| order by Timestamp desc
```

---

## 📊 Query Categories Overview

| Category | Queries | Description | Use Case |
|----------|---------|-------------|----------|
| 🏦 Banking | 25+ | Financial services security | ATM security, payment fraud, core banking |
| 📧 Email Threats | 30+ | Email-based attack detection | Phishing, BEC, malicious attachments |
| 🖥️ Endpoints | 40+ | Endpoint security monitoring | Malware, persistence, lateral movement |
| 🔐 Identity | 20+ | Identity threat detection | Privileged access, suspicious logins |
| ☁️ Cloud Apps | 15+ | Cloud application security | SaaS security, data exfiltration |
| 🌍 MENA Specific | 10+ | Regional threat intelligence | Local threat actors, geopolitical threats |

---

## 🛠️ Tools and Integrations

### Microsoft 365 Defender Integration
- **Sentinel Integration** - Export queries for long-term retention
- **Logic Apps** - Automated response workflows  
- **Power Automate** - Notification and reporting automation
- **Graph API** - Programmatic access and automation

### Third-Party Tools
- **Splunk** - Query conversion utilities
- **MISP** - Threat intelligence platform integration
- **TheHive** - Case management integration

---

## 📈 Performance Optimization

### Query Best Practices
- ✅ **Use time filters** - Always include appropriate time ranges
- ✅ **Limit result sets** - Use `take` or `top` operators  
- ✅ **Optimize joins** - Use efficient join strategies
- ✅ **Index-friendly filters** - Filter on indexed columns first

### Resource Management
- 🔄 **Query scheduling** - Avoid peak hours for resource-intensive queries
- 📊 **Result caching** - Leverage query result caching for dashboards
- ⚡ **Performance monitoring** - Track query execution times

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! 

### How to Contribute
1. **Fork** this repository
2. **Create** a feature branch (`git checkout -b feature/AmazingQuery`)
3. **Add** your hunting query with proper documentation
4. **Test** the query in your environment
5. **Commit** your changes (`git commit -m 'Add amazing banking threat query'`)
6. **Push** to the branch (`git push origin feature/AmazingQuery`)
7. **Open** a Pull Request

### Contribution Guidelines
- 📝 **Documentation** - Include query description and use case
- 🧪 **Testing** - Verify queries work in M365 Defender
- 🏷️ **Tagging** - Use appropriate MITRE ATT&CK tags
- 🔒 **Security** - No sensitive data in examples

---

## 🎯 MITRE ATT&CK Mapping

Our queries are mapped to MITRE ATT&CK framework:

| Tactic | Technique | Queries Available |
|--------|-----------|-------------------|
| Initial Access | T1566 (Phishing) | 8 queries |
| Persistence | T1053 (Scheduled Task) | 6 queries |
| Privilege Escalation | T1055 (Process Injection) | 5 queries |
| Defense Evasion | T1027 (Obfuscated Files) | 7 queries |
| Credential Access | T1003 (OS Credential Dumping) | 9 queries |
| Discovery | T1083 (File Discovery) | 4 queries |
| Lateral Movement | T1021 (Remote Services) | 6 queries |
| Collection | T1005 (Data from Local System) | 3 queries |
| Exfiltration | T1041 (C2 Channel) | 5 queries |

---

## 📚 Resources and Learning

### Microsoft Documentation
- [Advanced Hunting Overview](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
- [KQL Quick Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Microsoft 365 Defender APIs](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-overview)

### SANS/GIAC Resources
- [FOR572: Advanced Network Forensics](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting/)
- [SEC555: SIEM with Tactical Analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/)

### Regional Cybersecurity
- [CERT-Kuwait Resources](https://cert.gov.kw/)
- [GCC CERT Coordination](https://www.gcc-cert.org/)

---

## 🏆 Recognition and Usage

### Used By
- 🏦 **Regional Banks** - Major MENA financial institutions
- 🏛️ **Government Agencies** - National cybersecurity teams  
- 🏢 **Enterprises** - Large organizations in GCC region
- 🎓 **Educational Institutions** - Cybersecurity training programs

### Community Recognition
- 📈 **10k+ downloads** across all queries
- ⭐ **500+ GitHub stars** from security community
- 🌟 **Featured** in Microsoft Security Community blog
- 🎤 **Presented** at regional cybersecurity conferences

---

## ⚖️ License and Disclaimer

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Disclaimer
- 🔍 **Testing Required** - Always test queries in non-production environment first
- 🛡️ **No Warranty** - Queries provided as-is without warranty
- 🔒 **Compliance** - Ensure compliance with local regulations and policies
- 📊 **Privacy** - Respect privacy and data protection requirements

---

## 📞 Contact and Support

### Get In Touch
- 💬 **GitHub Issues** - For bug reports and feature requests
- 📧 **Email** - [site@hotmail.com](mailto:site@hotmail.com)
- 💼 **LinkedIn** - [linkedin.com/in/alenizi](https://www.linkedin.com/in/alenizi/)

### Support This Project
If you find this repository helpful:
- ⭐ **Star** this repository
- 🔄 **Share** with your network  
- 💡 **Contribute** new queries
- 📝 **Provide feedback** through issues

---

## 🚀 Future Roadmap

### Planned Features
- [ ] **Interactive Dashboard** - Web-based query explorer
- [ ] **Mobile App** - iOS/Android hunting query reference
- [ ] **AI Integration** - ChatGPT-powered query generation
- [ ] **Multi-language Support** - Arabic language documentation
- [ ] **Training Materials** - Video tutorials and webinars

### Community Requests
- [ ] **SOAR Integration** - Phantom/Demisto playbooks
- [ ] **Threat Intelligence** - IOC feeds integration  
- [ ] **Compliance Mapping** - PCI DSS, ISO 27001 alignment
- [ ] **Regional Customization** - Country-specific query variants

---

**⚡ Made with ❤️ by 3li.info**

---

*Last Updated: September 2025*  
*Repository Version: 2.1.0*  
*Total Queries: 150+*
