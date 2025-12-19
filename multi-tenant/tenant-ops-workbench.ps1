# EXO MULTI-TENANT AUDIT WITH BITWARDEN CREDENTIAL LOOKUP
# UPN LIST DRIVES BOTH EXO LOGINS AND BITWARDEN USERNAME SEARCH
#>
Autokill logins and enumerate across "upn-list.csv" 
Link to Bitwarden CLI to auto complete logins

<#

[CmdletBinding()]
param(
    [switch]$ResumeFromStatus,
    [int]$StartFromIndex = -1
)

# -------------------------------
# DIRECTORIES
# -------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$InputCsvPath = Join-Path $ScriptDir 'upn-list.csv'
$OutDir       = Join-Path $ScriptDir 'Reports'
$LogPath      = Join-Path $ScriptDir 'log.txt'
$StatusPath   = Join-Path $ScriptDir 'status.txt'

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# -------------------------------
# LOGGING
# -------------------------------
function Write-Log {
    param(
        [string]$Message
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[${ts}] $Message"
    Add-Content -Path $LogPath -Value $line
}

Write-Log 'Run start.'

# ============================================================
# BITWARDEN INTEGRATION
# ============================================================
function Initialize-BitwardenSession {
    # Interactive Bitwarden login and unlock.
    # You enter email, master password, and MFA in the bw prompts.
    # Script only keeps the session token for this run.

    $bwCmd = Get-Command -Name 'bw' -ErrorAction SilentlyContinue
    if (-not $bwCmd) {
        throw 'Bitwarden CLI ''bw'' not found in PATH. Install it before running this script.'
    }

    Write-Host ''
    Write-Host '[Bitwarden] Interactive login starting...' -ForegroundColor Yellow
    Write-Host 'You will be prompted by Bitwarden (email, master password, MFA).' -ForegroundColor Gray
    Write-Host 'The script only keeps the session token for this run.' -ForegroundColor Gray

    # Manual login
    bw login | Out-Null

    # Manual unlock, returns session token
    $session = bw unlock --raw

    if ([string]::IsNullOrWhiteSpace($session)) {
        throw '[Bitwarden] Unlock failed - no session token received.'
    }

    $script:BwSessionToken = $session
    $env:BW_SESSION        = $session

    Remove-Variable -Name 'session' -ErrorAction SilentlyContinue

    Write-Host '[Bitwarden] Vault unlocked. Session active for this script run.' -ForegroundColor Green
    Write-Log '[Bitwarden] Session initialized.'
}

function Get-BitwardenCredentialByUsername {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    if (-not $script:BwSessionToken -and -not $env:BW_SESSION) {
        throw 'Bitwarden session not initialized. Call Initialize-BitwardenSession first.'
    }

    # Search items using the username string
    $itemsJson = bw list items --search $Username --raw 2>$null
    if (-not $itemsJson) {
        throw "No Bitwarden items found for username '$Username'."
    }

    $items = $itemsJson | ConvertFrom-Json

    # Normalize single object to array
    if ($items -isnot [System.Collections.IEnumerable] -or $items -is [string]) {
        $items = @($items)
    }

    if ($items.Count -gt 1) {
        throw "More than one Bitwarden item matched username '$Username'. Make usernames unique."
    }

    $item = $items[0]

    $plainPassword = $item.login.password
    if (-not $plainPassword) {
        throw "Bitwarden item for '$Username' has no password."
    }

    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    $plainPassword = $null
    $item.login.password = $null

    $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
    return $credential
}

function Close-BitwardenSession {
    # Lock Bitwarden vault and clear session data.

    Write-Host ''
    Write-Host '[Bitwarden] Closing session...' -ForegroundColor Yellow

    try {
        bw lock | Out-Null
        Write-Host '[Bitwarden] Vault locked (session invalidated).' -ForegroundColor Green
        Write-Log '[Bitwarden] Vault locked.'
    }
    catch {
        Write-Host "[Bitwarden] Failed to lock vault: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "[Bitwarden] ERROR locking vault: $($_.Exception.Message)"
    }

    try {
        Remove-Item -Path 'Env:\BW_SESSION' -ErrorAction SilentlyContinue
        if (Get-Variable -Name 'BwSessionToken' -Scope Script -ErrorAction SilentlyContinue) {
            Remove-Variable -Name 'BwSessionToken' -Scope Script -ErrorAction SilentlyContinue
        }
        Write-Log '[Bitwarden] Session token removed from environment and memory.'
    }
    catch {
        Write-Log "[Bitwarden] ERROR removing session token variables: $($_.Exception.Message)"
    }
}

trap {
    Write-Log "[Trap] Unhandled error: $($_.Exception.Message)"
    Write-Host '[Script] Unhandled error occurred. Cleaning up Bitwarden session...' -ForegroundColor Red
    Close-BitwardenSession
    break
}

# -------------------------------
# READ UPN LIST
# -------------------------------
if (-not (Test-Path $InputCsvPath)) {
    Write-Host 'Missing upn-list.csv'
    exit
}

$raw = Import-Csv -Path $InputCsvPath
$UPNs = @()
foreach ($row in $raw) {
    if ($row.UPN -and $row.UPN.Contains('@')) {
        $UPNs += $row.UPN.Trim()
    }
}

if ($UPNs.Count -eq 0) {
    Write-Host 'No valid UPNs found.'
    exit
}
Write-Log ("Valid UPN count: $($UPNs.Count)")

# -------------------------------
# RESUME LOGIC
# -------------------------------
$StartIndex = 0

if ($StartFromIndex -ge 0) {
    $StartIndex = $StartFromIndex
}
elseif ($ResumeFromStatus) {
    if (Test-Path $StatusPath) {
        $last = Select-String -Pattern 'COMPLETE' -Path $StatusPath | Select-Object -Last 1
        if ($last) {
            $parts = $last.Line.Split('|')
            foreach ($p in $parts) {
                $t = $p.Trim()
                if ($t.StartsWith('index=')) {
                    $num = $t.Replace('index=', '')
                    $StartIndex = [int]$num + 1
                }
            }
        }
    }
}

if ($StartIndex -ge $UPNs.Count) {
    Write-Host 'Start index beyond UPN list.'
    exit
}

# -------------------------------
# SAFE GROUP FUNCTIONS
# -------------------------------
function Get-SafeGroups {
    try {
        return Get-EXOGroup -ResultSize Unlimited
    }
    catch {
        try {
            return Get-UnifiedGroup -ResultSize Unlimited
        }
        catch {
            try {
                return Get-DistributionGroup -ResultSize Unlimited
            }
            catch {
                return @()
            }
        }
    }
}

function Get-SafeGroupMembers {
    param(
        $Identity
    )
    try {
        return Get-EXOGroupMember -Identity $Identity
    }
    catch {
        try {
            return Get-UnifiedGroupLinks -Identity $Identity -LinkType Members
        }
        catch {
            try {
                return Get-DistributionGroupMember -Identity $Identity
            }
            catch {
                return @()
            }
        }
    }
}

function Get-SafeGroupOwners {
    param(
        $Identity
    )
    try {
        return Get-EXOGroupOwner -Identity $Identity
    }
    catch {
        try {
            return Get-UnifiedGroupLinks -Identity $Identity -LinkType Owners
        }
        catch {
            return @()
        }
    }
}

# ------------------------------------------------
# UNIVERSAL SCHEMA TEMPLATE
# ------------------------------------------------
function New-Row {
    param(
        $TenantUPN,
        $Domain,
        $Type,
        $Display,
        $SMTP,
        $Forward,
        $Deliver,
        $Archive,
        $License,
        $Members,
        $Owners,
        $Teams
    )
    $obj = [PSCustomObject]@{
        TenantUPN                  = $TenantUPN
        TenantDomain               = $Domain
        ObjectType                 = $Type
        DisplayName                = $Display
        PrimarySmtpAddress         = $SMTP
        ForwardingSmtpAddress      = $Forward
        DeliverToMailboxAndForward = $Deliver
        ArchiveEnabled             = $Archive
        LicensingType              = $License
        Members                    = $Members
        Owners                     = $Owners
        IsTeamsEnabled             = $Teams
    }
    return $obj
}

# ============================================================
# INITIALIZE BITWARDEN SESSION (ONE-TIME)
# ============================================================
Initialize-BitwardenSession

# ============================================================
# MAIN TENANT LOOP
# ============================================================
for ($i = $StartIndex; $i -lt $UPNs.Count; $i++) {

    $upn = $UPNs[$i]
    $domain = $upn.Split('@')[1]

    Write-Host ''
    Write-Host "Tenant: $upn"
    Write-Host '[Enter] Continue    [S] Skip    [X] Exit'
    $choice = Read-Host '>'

    if ($choice -eq 'X') {
        Write-Log ("User exit requested at index=$i upn=$upn")
        Close-BitwardenSession
        exit
    }
    if ($choice -eq 'S') {
        Write-Log ("Skipped tenant index=$i upn=$upn")
        $statusLine = (Get-Date).ToString() + " | SKIPPED | index=$i | upn=$upn"
        Add-Content -Path $StatusPath -Value $statusLine
        continue
    }

    Write-Log ("Tenant start index=$i upn=$upn")

    # EXO Connect using Bitwarden credential resolved by UPN
    try {
        $cred = Get-BitwardenCredentialByUsername -Username $upn
        Write-Log ("Bitwarden credential resolved for $upn")

        Connect-ExchangeOnline -Credential $cred -ShowBanner:$false -ErrorAction Stop
        Write-Log ("Connected as $upn")
    }
    catch {
        Write-Log ("ERROR connecting $upn : $($_.Exception.Message)")
        $statusLine = (Get-Date).ToString() + " | FAILED | index=$i | upn=$upn"
        Add-Content -Path $StatusPath -Value $statusLine
        continue
    }

    # Prepare per-tenant CSV path
    $TenantCsv = Join-Path $OutDir ($domain + '.csv')

    # Row buffer
    $Rows = New-Object System.Collections.ArrayList

    # MAILBOX PULL
    try {
        $mbx = Get-EXOMailbox -ResultSize Unlimited
    }
    catch {
        Write-Log ("Mailbox pull failed: $($_.Exception.Message)")
        $mbx = @()
    }
    Write-Log ("Mailbox count: $($mbx.Count)")

    foreach ($m in $mbx) {
        $row = New-Row `
            $upn `
            $domain `
            $m.RecipientTypeDetails `
            $m.DisplayName `
            $m.PrimarySmtpAddress `
            $m.ForwardingSmtpAddress `
            $m.DeliverToMailboxAndForward `
            $m.ArchiveEnabled `
            $m.SkuAssigned `
            '[]' `
            '[]' `
            ''
        [void]$Rows.Add($row)
    }

    # SHARED MAILBOX PERMISSIONS
    $shared = $mbx | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }
    foreach ($s in $shared) {
        try {
            $p = Get-EXOMailboxPermission -Identity $s.PrimarySmtpAddress
            $v = $p | Where-Object { $_.User -notlike 'NT AUTHORITY*' }
            $u = $v.User

            $target = $Rows | Where-Object { $_.PrimarySmtpAddress -eq $s.PrimarySmtpAddress }
            if ($target) {
                $target.Members = ($u | ConvertTo-Json -Compress)
            }
        }
        catch {
            Write-Log ("Shared perm fail for $($s.PrimarySmtpAddress)")
        }
    }

    # GROUPS
    $groups = Get-SafeGroups
    Write-Log ("Group count: $($groups.Count)")

    foreach ($g in $groups) {

        $members = Get-SafeGroupMembers -Identity $g.Identity
        $owners  = Get-SafeGroupOwners -Identity $g.Identity

        $isUnified = $false
        $isTeams   = $false

        if ($g.GroupType) {
            if ($g.GroupType -contains 'Unified') { $isUnified = $true }
            if ($g.GroupType -contains 'Team')    { $isTeams   = $true }
        }

        $otype = 'DistributionList'
        if ($isUnified) { $otype = 'M365Group' }

        $row = New-Row `
            $upn `
            $domain `
            $otype `
            $g.DisplayName `
            $g.PrimarySmtpAddress `
            '' `
            '' `
            '' `
            '' `
            ($members.PrimarySmtpAddress | ConvertTo-Json -Compress) `
            ($owners.PrimarySmtpAddress  | ConvertTo-Json -Compress) `
            $isTeams

        [void]$Rows.Add($row)
    }

    Disconnect-ExchangeOnline -Confirm:$false

    # EXPORT TENANT CSV
    $Rows | Export-Csv -Path $TenantCsv -NoTypeInformation
    Write-Log ("Exported $TenantCsv")

    $statusLine = (Get-Date).ToString() + " | COMPLETE | index=$i | upn=$upn"
    Add-Content -Path $StatusPath -Value $statusLine
}

Write-Host ''
Write-Host 'Audit finished.'
Write-Log 'Run complete.'

Close-BitwardenSession

[void][System.Console]::ReadLine()
