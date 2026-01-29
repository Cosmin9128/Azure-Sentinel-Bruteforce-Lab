# Azure Sentinel Brute Force Detection Lab

Hands-on lab for detecting brute-force login attempts and analyzing security incidents using Microsoft Sentinel and KQL.

---

## Project Overview

This project demonstrates how to build a detection workflow in Microsoft Sentinel to identify multiple failed sign-in attempts that may indicate a brute-force attack against an Azure Active Directory account.

The lab simulates a realistic SOC scenario and focuses on:

- Log ingestion
- KQL query development
- Analytics rule creation
- Incident generation
- Incident investigation using Microsoft Defender

---

## Architecture

### Components Used

- Azure Active Directory (Entra ID)  
- Microsoft Sentinel  
- Log Analytics Workspace  
- Sign-in Logs data connector  
- Scheduled Analytics Rule  
- Microsoft Defender Incident Management  

---

## Detection Logic

The detection is based on Azure AD **SigninLogs** and identifies users with multiple failed authentication attempts within a short time window.

### KQL Query

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
| sort by TimeGenerated desc
```

## Query Explanation

- Filters failed authentication attempts  
- Aggregates failed logins per user in 5-minute windows  
- Triggers when three or more failures are detected  

---

## Analytics Rule Configuration

- Rule type: Scheduled  
- Query frequency: Every 5 minutes  
- Lookup period: Last 5 minutes  
- Alert threshold: Greater than 0 results  
- MITRE ATT&CK mapping: T1110 - Brute Force  
- Incident creation: Enabled  
- Alert grouping: Disabled (each detection creates a new incident)  

---

## Simulation Steps

- Created a test user in Azure Active Directory  
- Generated multiple failed login attempts using incorrect credentials  
- Verified that SignInLogs captured the authentication failures  
- Validated the KQL query returned matching events  
- Confirmed the analytics rule triggered successfully  
- Investigated the incident in Microsoft Defender  

---

## Incident Investigation

### The generated incident contains:

- Detection source: Microsoft Sentinel  
- Category: Credential Access  
- MITRE technique: T1110  
- Impacted user entity  
- Timeline of failed sign-in attempts  

### The incident was analyzed using:

- Incident graph visualization  
- Alert details  
- Entity relationships  
- Timeline validation  

---

## Screenshots

Screenshots are available in the `/screenshots` folder:

- `rule.png` - Analytics rule configuration  
- `kql_results_1.png` - KQL query results  
- `incident_list.png` - Incident created in Defender  
- `incident_graph.png` - Incident graph visualization  

---

## Skills Demonstrated

- Microsoft Sentinel configuration  
- KQL query development  
- Azure AD sign-in log analysis  
- SIEM detection engineering  
- Incident investigation  
- MITRE ATT&CK mapping  
- Cloud security monitoring  
