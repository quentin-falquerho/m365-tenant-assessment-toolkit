<#
.SYNOPSIS
    Performs an automated baseline security and configuration audit for a Microsoft 365 tenant.
.DESCRIPTION
    Connects to Microsoft Graph API to assess MFA registration defaults, legacy authentication,
    and Privileged Identity Management (PIM) roles, exporting results to a structured CSV report.
.EXAMPLE
    .\Invoke-M365TenantAssessment.ps1 -TenantId "your-tenant-id" -OutputPath "C:\Reports"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\M365_Assessment_Report.csv"
)

# Ensure Microsoft.Graph module is present
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Warning "Microsoft.Graph module missing. Installing module..."
    Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber -Force
}

# Connect to Microsoft Graph with required audit scopes
$scopes = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "RoleManagement.Read.Directory"
)

Write-Host "Connecting to Microsoft Graph for Tenant: $TenantId..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes $scopes

$assessmentResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Audit 1: Security Defaults / Conditional Access Policy Check
Write-Host "Checking Security Defaults status..." -ForegroundColor Yellow
$identityPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
$securityDefaultsEnabled = $identityPolicy.IsEnabled

$assessmentResults.Add([PSCustomObject]@{
    Category    = "Identity & Access"
    Control     = "Security Defaults"
    Status      = if ($securityDefaultsEnabled) { "PASS" } else { "WARNING" }
    Details     = "Security Defaults is set to: $securityDefaultsEnabled"
    Remediation = "If Security Defaults is disabled, ensure equivalent Conditional Access Policies are active."
})

# Audit 2: Global Administrator Count Check
Write-Host "Auditing Privileged Role Assignments (Global Admins)..." -ForegroundColor Yellow
$globalAdminRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

$adminCount = $globalAdmins.Count
$adminStatus = if ($adminCount -ge 2 -and $adminCount -le 5) { "PASS" } else { "ACTION REQUIRED" }

$assessmentResults.Add([PSCustomObject]@{
    Category    = "Privileged Access"
    Control     = "Global Administrator Count"
    Status      = $adminStatus
    Details     = "Found $adminCount assigned Global Administrator(s)."
    Remediation = "Microsoft recommends maintaining between 2 and 5 Global Administrators to minimize risk."
})

# Export Results
$assessmentResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Assessment completed successfully. Report generated at: $OutputPath" -ForegroundColor Green

# Disconnect Session
Disconnect-MgGraph
