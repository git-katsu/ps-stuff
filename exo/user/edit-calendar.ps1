# Ensure EXO module
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Force
}
Import-Module ExchangeOnlineManagement

# Check existing session
$exoSession = Get-ConnectionInformation | Where-Object Service -eq 'Exchange Online'
if ($exoSession) {
    Write-Host "Already connected to Exchange Online as $($exoSession.Account) — skipping login." -ForegroundColor Green
} else {
    $adminUPN = Read-Host "Enter your admin UPN (e.g., admin@domain.com)"
    Connect-ExchangeOnline -UserPrincipalName $adminUPN
}

do {
    # --- STATE: Mailbox Selection ---
    Write-Host "`n==================== MAILBOX SELECTION MODE ====================" -ForegroundColor Cyan
    $mailboxInput = (Read-Host "Enter target mailbox alias/display name/email (or 'exit' to quit)").Trim().TrimEnd(',')
    if ($mailboxInput -ieq 'exit') { break }

    # Always force array to avoid "1-" bug
    $searchResults = @(Get-Recipient -ResultSize Unlimited | Where-Object {
        $_.DisplayName -like "*$mailboxInput*" -or
        $_.PrimarySmtpAddress -like "*$mailboxInput*" -or
        $_.Alias -like "*$mailboxInput*"
    })

    $mailboxRecipient = $null

    # Handle no matches
    if ($searchResults.Count -eq 0) {
        Write-Host "No matches found for '$mailboxInput'." -ForegroundColor Red
        continue
    }
    elseif ($searchResults.Count -eq 1) {
        $mailboxRecipient = $searchResults[0]
    }
    else {
        # Multiple matches → show numbered list
        Write-Host "`nMultiple matches found:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $searchResults.Count; $i++) {
            Write-Host "[$($i+1)] $($searchResults[$i].DisplayName) ($($searchResults[$i].PrimarySmtpAddress))" -ForegroundColor Cyan
        }

        while ($true) {
            $choice = Read-Host "Enter number (1-$($searchResults.Count)) or 'r' to retry"
            if ($choice -ieq 'r') {
                Write-Host "Retrying search..." -ForegroundColor Yellow
                $mailboxRecipient = $null
                break
            }
            elseif ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $searchResults.Count) {
                $mailboxRecipient = $searchResults[[int]$choice - 1]
                break
            }
            else {
                Write-Host "Invalid selection. Please enter a valid number or 'r'." -ForegroundColor Yellow
            }
        }

        if (-not $mailboxRecipient) { continue }
    }

    # Confirm mailbox
    $confirm = Read-Host "Did you mean $($mailboxRecipient.DisplayName) ($($mailboxRecipient.PrimarySmtpAddress))? (Y/N)"
    if ($confirm -notin @('Y','y')) {
        Write-Host "Cancelled selection. Please enter again." -ForegroundColor Yellow
        continue
    }

    $mailbox = $mailboxRecipient.PrimarySmtpAddress.ToString()

    # --- Banner ---
    Write-Host "`n>>> EDITING: $($mailboxRecipient.DisplayName) ($mailbox) <<<" -ForegroundColor Green

    # Show current permissions
    Write-Host "`nCurrent permissions on ${mailbox}:`n" -ForegroundColor Cyan
    Get-MailboxFolderPermission -Identity "${mailbox}:\Calendar" |
        Select-Object User, AccessRights |
        Format-Table -AutoSize

    # Summary counters
    $addedCount = 0
    $removedCount = 0
    $skippedCount = 0

    do {
        Write-Host "`n-------------------- EDITING ${mailbox} --------------------" -ForegroundColor Magenta
        $actionsInput = Read-Host "Enter commands (e.g., 'add user1, remove user2') or 'q' to finish editing"
        if ($actionsInput -ieq 'q' -or $actionsInput -ieq 'exit') { break }

        $actions = $actionsInput -split '\s*,\s*' | Where-Object { $_ -ne "" }

        foreach ($action in $actions) {
            $action = $action.Trim()

            if ($action -match '^(add|remove)\s+(.+)$') {
                $mode = $Matches[1].ToLower()
                $rawUser = $Matches[2].Trim()

                # Resolve alias/display/email to primary SMTP
                $recipient = Get-Recipient $rawUser -ErrorAction SilentlyContinue
                if (-not $recipient) {
                    Write-Host "Skipping '$rawUser' — not found in EXO." -ForegroundColor Yellow
                    $skippedCount++
                    continue
                }

                $resolvedUser = $recipient.PrimarySmtpAddress.ToString()

                # Skip self
                if ($resolvedUser -ieq $mailbox) {
                    Write-Host "Skipping self-entry for $resolvedUser (owner permissions unaffected)." -ForegroundColor Green
                    $skippedCount++
                    continue
                }

                try {
                    if ($mode -eq 'add') {
                        Add-MailboxFolderPermission -Identity "${mailbox}:\Calendar" -User $resolvedUser -AccessRights Editor -ErrorAction Stop
                        Write-Host "Granted Editor to $resolvedUser on ${mailbox}’s calendar." -ForegroundColor Green
                        $addedCount++
                    }
                    elseif ($mode -eq 'remove') {
                        Remove-MailboxFolderPermission -Identity "${mailbox}:\Calendar" -User $resolvedUser -Confirm:$false -ErrorAction Stop
                        Write-Host "Removed $resolvedUser from ${mailbox}’s calendar." -ForegroundColor Green
                        $removedCount++
                    }
                }
                catch {
                    Write-Host ("Failed to process {0} for {1}: {2}" -f $mode, $resolvedUser, $_) -ForegroundColor Red
                }
            }
            else {
                Write-Host "Invalid command format: '$action'. Use 'add <user>' or 'remove <user>'." -ForegroundColor Yellow
                $skippedCount++
            }
        }
    } while ($true)

    # --- Summary ---
    Write-Host "`n=== Summary for ${mailbox} ===" -ForegroundColor Cyan
    Write-Host "Added:   $addedCount" -ForegroundColor Green
    Write-Host "Removed: $removedCount" -ForegroundColor Green
    Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow

    # Show final permissions
    Write-Host "`nUpdated permissions on ${mailbox}:`n" -ForegroundColor Cyan
    Get-MailboxFolderPermission -Identity "${mailbox}:\Calendar" |
        Select-Object User, AccessRights |
        Format-Table -AutoSize

} while ($true)
