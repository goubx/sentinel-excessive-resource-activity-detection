# Detecting Excessive Azure Resource Activity in Microsoft Sentinel

A detection engineering and incident response lab built in Microsoft Sentinel. This project creates a scheduled analytics rule to flag accounts performing a high volume of Azure resource creations or deletions, then triages the flagged callers and works the incident to closure following the NIST SP 800-61 lifecycle.

> Note: caller identities and source IP addresses have been sanitized. The accounts belong to a shared training environment and the IPs are legitimate user addresses, not attacker indicators, so they are not published.

| | |
|---|---|
| **SIEM** | Microsoft Sentinel |
| **Telemetry source** | Azure activity log (AzureActivity) |
| **Query Language** | KQL |
| **IR Framework** | NIST SP 800-61 |
| **Tactic** | Impact |
| **MITRE Techniques** | T1485 Data Destruction, T1496 Resource Hijacking |
| **Outcome** | Sampled callers reviewed, all benign positives (authorized admin activity). No containment needed. Rule tuning recommended |

## Contents

- [Overview](#overview)
- [How the Detection Works](#how-the-detection-works)
- [Part 1: The Analytics Rule](#part-1-the-analytics-rule)
- [Part 2: Triggering the Alert](#part-2-triggering-the-alert)
- [Part 3: Working the Incident (NIST SP 800-61)](#part-3-working-the-incident-nist-sp-800-61)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Lessons Learned](#lessons-learned)
- [Files](#files)

## Overview

A high volume of resource creation or deletion in Azure can be a sign of trouble: a compromised account, misconfigured automation, or resource abuse like spinning up VMs for crypto mining. It can just as easily be a busy administrator doing legitimate work. This detection flags the high-volume callers so an analyst can decide which it is.

Like impossible travel, the rule is a starting point, not a verdict. The work is in the triage, pivoting from a flagged caller to what they actually did and judging whether it fits their role.

## How the Detection Works

When a user or service creates or deletes resources in Azure, the operation is recorded in the `AzureActivity` table, which forwards into the Log Analytics workspace behind Microsoft Sentinel. A scheduled analytics rule counts successful write and delete operations per caller and flags any caller crossing the threshold. Sentinel's own alert-rule and incident operations are excluded so routine SOC administration does not generate noise.

## Part 1: The Analytics Rule

The detection flags any caller with 5 or more successful resource creations or deletions, excluding Sentinel alert-rule and incident operations.

```kql
let ResourceCreations = AzureActivity
    | extend ClaimsJson = parse_json(Claims)
    | extend ObjectIdentifier = tostring(ClaimsJson["http://schemas.microsoft.com/identity/claims/objectidentifier"])
    | where OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/ALERTRULES"
        and OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/INCIDENTS"
    | where OperationNameValue endswith "WRITE"
        and ActivityStatusValue == "Success"
    | summarize NumberOfResourceCreations = count() by Caller, ObjectIdentifier, CallerIpAddress;
let ResourceDeletions = AzureActivity
    | extend ClaimsJson = parse_json(Claims)
    | extend ObjectIdentifier = tostring(ClaimsJson["http://schemas.microsoft.com/identity/claims/objectidentifier"])
    | where OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/ALERTRULES"
        and OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/INCIDENTS"
    | where OperationNameValue endswith "DELETE"
        and ActivityStatusValue == "Success"
    | summarize NumberOfResourceDeletions = count() by Caller, ObjectIdentifier, CallerIpAddress;
ResourceCreations
| join kind=fullouter ResourceDeletions on ObjectIdentifier, Caller, CallerIpAddress
| project ObjectIdentifier, Caller, CallerIpAddress,
          NumberOfResourceCreations, NumberOfResourceDeletions
| where NumberOfResourceCreations >= 5 or NumberOfResourceDeletions >= 5
| order by NumberOfResourceCreations desc, NumberOfResourceDeletions desc
```

**Rule configuration:**

| Setting | Value |
|---------|-------|
| Status | Enabled |
| Run frequency | Every 4 hours |
| Detection window | 7 days |
| Threshold | 5 or more successful writes or deletes |
| Incident creation | Automatic |
| Alert grouping | Single incident per 24 hours |
| Stop query after alert | Yes |

**Entity mappings:**

| Entity | Identifier | Value |
|--------|-----------|-------|
| Account | Sid | ObjectIdentifier |
| IP | Address | CallerIpAddress |

**MITRE mapping on the rule:** T1485 Data Destruction, T1496 Resource Hijacking.

## Part 2: Triggering the Alert

Resource creation and deletion happens constantly in an active Azure environment, so the rule had ample data to evaluate. Repeatedly creating and deleting a VM and its associated resources is enough to cross the threshold, and existing activity from other callers triggered the rule as well.

## Part 3: Working the Incident (NIST SP 800-61)

### Preparation

Tooling and procedures were in place ahead of the investigation: Microsoft Sentinel for detection and incident management, the Azure activity log as the evidence source, and Entra ID available for account containment if a real threat were confirmed.

### Detection and Analysis

The rule flagged more than 300 callers with elevated resource creation or deletion activity, which is a clear sign that the threshold is loose for this environment. Three flagged source IPs were selected for review as a sample.

Each flagged IP was resolved to its user account and object ID with this query, which pivots from the address to the identity behind it:

```kql
AzureActivity
| where CallerIpAddress == "<caller-ip>"
| where TimeGenerated > ago(7d)
| extend ClaimsJson = parse_json(Claims)
| extend UPN = tostring(ClaimsJson["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"])
| extend OID = tostring(ClaimsJson["http://schemas.microsoft.com/identity/claims/objectidentifier"])
| project TimeGenerated, Caller, UPN, OID, OperationNameValue
| distinct Caller, UPN, OID
```

Once each caller was identified, their full create and delete history was reviewed to judge whether the activity matched their role.

**Triage results:**

| Account | Activity | Disposition |
|---------|----------|-------------|
| Account 1 | Created multiple virtual machines over several days, consistent with legitimate provisioning or application scaling | Benign positive |
| Account 2 | Created virtual machines and modified Network Security Groups over several days, no unauthorized activity identified | Benign positive |
| Account 3 | Created virtual machines and modified Network Security Groups as part of routine administrative work, no malicious indicators | Benign positive |

All three were real, high-volume activity that the rule correctly detected, but each fit normal administrative behavior. That makes them benign positives rather than false positives: the detection was accurate, the activity was just authorized.

### Containment, Eradication, and Recovery

- No containment was needed. All three accounts were reviewed and their activity was verified by management as routine and authorized.
- No accounts were disabled, since disabling a legitimate administrator mid-work would cause needless disruption with no security benefit.

### Post-Incident Activities

- The volume of flagged callers (more than 300) shows the rule needs tuning for this environment. Resource creation and deletion is normal here, so a flat threshold catches mostly legitimate work.
- Azure Policy could be used to restrict or govern resource creation where appropriate, though in many cases the practical answer is to tune the rule and triage alerts as they come.
- Findings and dispositions were recorded with the incident.

### Closure

The incident was worked to closure and classified as a **Benign Positive**. The rule fired correctly on genuine high-volume resource activity, but the sampled accounts were all confirmed as authorized administrative work, so no threat was present. Continued monitoring was recommended to confirm that future provisioning and Network Security Group changes stay consistent with policy and each user's responsibilities.

## MITRE ATT&CK Mapping

These are the techniques the rule is designed to surface. No malicious activity was confirmed in this investigation, so they describe the threat model rather than observed attacker behavior.

| Tactic | Technique | ID | Relevance |
|--------|-----------|----|----|
| Impact | Data Destruction | T1485 | High-volume resource deletion could indicate destructive activity against the environment |
| Impact | Resource Hijacking | T1496 | High-volume resource creation could indicate an account spinning up resources for abuse |

## Lessons Learned

**What this detection catches, and its limits:**

- The rule surfaces callers doing a lot of resource creation or deletion, which is the right signal for catching a compromised account or runaway automation. Its weakness is that the same behavior is normal for administrators, so in an active environment it flags a large number of legitimate users.
- With more than 300 callers flagged, this rule is only useful alongside triage and tuning. On its own it produces too much noise to act on directly.

**What would prevent or reduce the risk:**

- Azure Policy can restrict who can create or delete certain resource types, limiting the blast radius of a compromised account.
- Scoping the rule to sensitive resource types, or to unusual patterns like mass deletion in a short window, would focus it on the activity that actually matters.

**What would sharpen the detection:**

- Raise the threshold and exclude known service principals and automation accounts, which are responsible for much of the legitimate volume.
- Alert on deletion bursts specifically, since mass deletion is a stronger destruction signal than steady provisioning.

## Files

- `README.md` - this writeup
- `analytics-rule.kql` - the detection query behind the Sentinel rule
- `investigation.kql` - the query used to resolve a flagged IP to its account

---

Part of an ongoing series of threat hunting and SOC investigations by Mohamed Yagoub.
