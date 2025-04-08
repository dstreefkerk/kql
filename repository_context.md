<!--
This file contains a complete list of KQL queries from git://github.com/dstreefkerk/kql.git.
Generated automatically using Repomix.
-->

This file is a merged representation of a subset of the codebase, containing specifically included files, combined into a single document by Repomix.
The content has been processed where content has been compressed (code blocks are separated by ⋮---- delimiter).

# Directory Structure
```
SentinelHealth/
  SentinelHealth - Get RestApiPoller HealthStatus logs.kql
SigninLogs/
  SigninLogs - Device Code Flow authentication detection.kql
```

# Files

## File: SentinelHealth/SentinelHealth - Get RestApiPoller HealthStatus logs.kql
```
// -----------------------------------------------------------------------------
// Use Case: Monitoring Azure Sentinel API Poller Health
// -----------------------------------------------------------------------------
// https://github.com/dstreefkerk/kql
//
// Purpose:
// This KQL query is designed to monitor the operational health of API-based 
// data connectors using the "RestApiPoller" type within Microsoft Sentinel. 
// It provides visibility into poller execution status, data ingestion volumes, 
// and any associated failures or warnings.
//
// Problem Statement:
// API-based data ingestion in Sentinel can silently fail or degrade in 
// performance, leading to gaps in security visibility. This query helps SOC 
// teams proactively identify and triage poller-related issues.
//
// Key Features:
// - Filters for API Polling connectors (RestApiPoller)
// - Extracts operational metadata from ExtendedProperties
// - Calculates data fetch duration for performance insights
// - Derives health status (Healthy, Warning, Failure)
// - Extracts first failure type, code, and message for diagnostics
// - Sorts by most recent polling events
//
// Usage Context:
// Run this query within Microsoft Sentinel to populate dashboards or drive 
// alerts for connector health. Integrate with workbooks or scheduled analytics 
// for proactive monitoring.
//
// Requirements:
// - SentinelHealth table must be enabled and collecting telemetry
// - Connectors must be configured with ExtendedProperties logging
//
// Last Updated: 2025-04-08
// -----------------------------------------------------------------------------
SentinelHealth
| where Type == "SentinelHealth"
| where SentinelResourceKind == "ApiPolling"
| where isnotempty(ExtendedProperties)
// Filter for RestApiPoller specifically
| extend ConnectorDataType = tostring(ExtendedProperties.ConnectorDataType)
| where ConnectorDataType == "RestApiPoller"
// Extract additional details from ExtendedProperties
| extend 
    StartTime = todatetime(ExtendedProperties.StartTime),
    EndTime = todatetime(ExtendedProperties.EndTime),
    TotalRecordCount = toint(ExtendedProperties.TotalRecordCount),
    HasFailures = isnotempty(ExtendedProperties.FailureSummary),
    HasWarnings = isnotempty(ExtendedProperties.WarningCount) and toint(ExtendedProperties.WarningCount) > 0,
    FailureSummary = ExtendedProperties.FailureSummary,
    WarningDetails = ExtendedProperties.WarningDetails
// Add a connector name that strips out the "ApiPolling-" prefix for better readability
| extend ConnectorName = replace_regex(SentinelResourceName, @"^ApiPolling-", "")
// Add duration calculation for performance monitoring
| extend FetchDurationMinutes = datetime_diff('minute', EndTime, StartTime)
// Add health status classification for better filtering
| extend HealthStatus = case(
    Status == "Success", "Healthy",
    Status == "Warning" or HasWarnings, "Warning",
    HasFailures, "Failure",
    "Unknown"
)
// Add failure type classification for analytics
| extend FailureType = iif(
    HasFailures and array_length(FailureSummary) > 0,
    tostring(FailureSummary[0].HealthResultType),
    ""
)
// Add error code extraction for analytics
| extend ErrorCode = iif(
    HasFailures and array_length(FailureSummary) > 0,
    tostring(FailureSummary[0].StatusCode),
    ""
)
// Add error message for details
| extend ErrorMessage = iif(
    HasFailures and array_length(FailureSummary) > 0,
    tostring(FailureSummary[0].StatusMessage),
    ""
)
// Sort by most recent first
| sort by TimeGenerated desc
// Project final columns in a logical order
| project
    TimeGenerated,
    ConnectorName,
    OperationName,
    HealthStatus,
    Status,
    TotalRecordCount,
    FetchDurationMinutes,
    FailureType,
    ErrorCode,
    ErrorMessage,
    StartTime,
    EndTime,
    SentinelResourceType,
    SentinelResourceKind,
    ExtendedProperties
```

## File: SigninLogs/SigninLogs - Device Code Flow authentication detection.kql
```
// -----------------------------------------------------------------------------
// Use Case: Application Using Device Code Authentication Flow
// -----------------------------------------------------------------------------
// https://github.com/dstreefkerk/kql
//
// Purpose:
// This KQL query identifies authentication events using the OAuth 2.0 
// Device Code Flow—intended for input-constrained devices like smart TVs 
// or IoT hardware. In non-device scenarios, its use may signal 
// misconfigured apps or unauthorized access attempts.
//
// Problem Statement:
// Device Code Flow enables user authentication without browser interaction. 
// When observed outside of legitimate use cases, it could indicate malicious 
// actors abusing the flow to bypass normal security controls.
//
// Key Features:
// - Filters authentication logs for 'deviceCode' protocol or transfer method
// - Projects relevant identity, app, location, and device details
// - Flags suspicious events with explanatory context for SOC triage
// - Includes MITRE ATT&CK technique mapping for T1078: Valid Accounts
//
// Usage Context:
// Deploy in Microsoft Sentinel as part of identity monitoring analytics. 
// Use for alerting, hunting, or continuous detection dashboards to catch 
// suspicious OAuth flows involving the device code mechanism.
//
// Requirements:
// - SigninLogs table must be enabled and available in Sentinel
// - Logging must capture AuthenticationProtocol and OriginalTransferMethod fields
//
// Attribution:
// Original Sigma rule by Mark Morowczynski '@markmorow' and Bailey Bercik '@baileybercik' 
// (via Microsoft documentation). KQL adaptation and formatting for SOC use case by [Your Name or Team].
//
// Reference: https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-authentication-flows
//
// Last Updated: 2025-04-08
// -----------------------------------------------------------------------------
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationProtocol =~ "deviceCode" 
    or OriginalTransferMethod =~ "deviceCodeFlow"
| project TimeGenerated,
    UserPrincipalName,
    UserDisplayName,
    UserId,
    IPAddress,
    Location,
    AppDisplayName,
    ClientAppUsed,
    AuthenticationProtocol,
    OriginalTransferMethod,
    DeviceDetail,
    Status,
    ResourceDisplayName
| extend AlertDetails = pack(
    "UserId", UserId,
    "ClientApp", ClientAppUsed,
    "AppDisplayName", AppDisplayName,
    "Protocol", AuthenticationProtocol,
    "TransferMethod", OriginalTransferMethod,
    "DeviceInfo", DeviceDetail
)
| extend Reason = "Device Code Authentication Flow detected which may indicate unauthorized access if not used with input-constrained devices"
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
```
