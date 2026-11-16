# firewall_rules.ps1
# The hands of webui/firewall_rules.py: one verb per call, every value a named parameter.
#
# It is run as   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File firewall_rules.ps1 -Op <verb> ...
# With -File the arguments reach the parameters below as plain strings. Nothing in here evaluates
# them, and nothing is built from them but the arguments of one cmdlet. The caller never uses -Command,
# because that joins the arguments into one line of PowerShell and parses it.
#
# Verbs:
#   Profiles            [{"Name","Enabled","DefaultOutboundAction"}] of the three profiles, as in force
#   Enable              switch the three profiles on
#   List                {"profiles": [...], "rules": [...]}: every rule named TDC-FW-*
#   Get -Name           the one rule as JSON, or no output at all when there is none
#   Create -Name -Action [-Program] [-RemoteAddress a,b] [-RemotePort] [-Protocol]
#                       an outbound rule. Exit 3: a profile is off (nothing is written). Exit 4: the rule is already there.
#   Remove -Name        remove the rule (no error when it is not there)
#   SetDefaultOutbound -DefaultOutboundAction [-Profiles Domain,Private]
#   AllowOut            {"rules": [{"Name","DisplayName","Group","Source"}]}: every enabled outbound Allow rule in
#                       force (ActiveStore) that is not TDC's. DefaultOutboundAction Block governs only traffic that no
#                       rule matches, so each of these still lets traffic out. Source is PolicyStoreSourceType: only
#                       Local rules (the PersistentStore) can be switched here; a GroupPolicy rule cannot.
#   DisableAllowOut -Names <base64>, EnableAllowOut -Names <base64>
#                       switch the named local outbound Allow rules off or on. -Names is base64 of a UTF-8 JSON list
#                       of rule names, so no name is ever a wildcard or a parameter. Only outbound Allow rules of the
#                       PersistentStore that are not TDC-FW-* are touched; {"done": [...], "failed": [{"Name","Error"}],
#                       "missing": [...]} says what happened to each.
#
# Exit codes: 0 done, 1 failed (the first line of stderr says why), 3 a profile is off, 4 the rule exists.
# Rules are only ever named TDC-FW-<letters, digits, hyphens>; a name with a wildcard or a trailing newline is refused.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Profiles', 'Enable', 'List', 'Get', 'Create', 'Remove', 'SetDefaultOutbound', 'AllowOut',
                 'DisableAllowOut', 'EnableAllowOut')]
    [string]$Op,
    [string]$Names,
    [string]$Name,
    [string]$Program,
    [string]$RemoteAddress,
    [string]$RemotePort,
    [string]$Protocol,
    [ValidateSet('Block', 'Allow')]
    [string]$Action,
    [string]$Profiles,
    [ValidateSet('Allow', 'Block', 'NotConfigured')]
    [string]$DefaultOutboundAction
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$AllProfiles = @('Domain', 'Private', 'Public')

function Assert-OurName {
    param([string]$Value)
    if ($Value -notmatch '^TDC-FW-[A-Za-z0-9-]{1,40}\z' -or [WildcardPattern]::ContainsWildcardCharacters($Value)) {
        throw "not a TDC rule name: $Value"
    }
}

function Get-ProfileStates {
    @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            Enabled = ([string]$_.Enabled -eq 'True')
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
        }
    })
}

function Get-RuleView {
    param([string]$RuleName)
    $rule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    if (-not $rule) { return $null }
    $app = $rule | Get-NetFirewallApplicationFilter
    $addr = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    [pscustomobject]@{
        Name = [string]$rule.Name
        Enabled = ([string]$rule.Enabled -eq 'True')
        Action = [string]$rule.Action
        Direction = [string]$rule.Direction
        Profile = [string]$rule.Profile
        Program = [string]$app.Program
        RemoteAddress = @($addr.RemoteAddress | ForEach-Object { [string]$_ })
        RemotePort = @($port.RemotePort | ForEach-Object { [string]$_ })
        Protocol = [string]$port.Protocol
    }
}

function Get-ProfileList {
    param([string]$Text)
    if (-not $Text) { return $AllProfiles }
    $list = @($Text.Split(',') | ForEach-Object { $_.Trim() })
    foreach ($p in $list) {
        if ($AllProfiles -notcontains $p) { throw "not a profile: $p" }
    }
    return $list
}

# Not filtered by Get-NetFirewallRule's own -Direction/-Action/-Enabled: with those, "no rule matches" is an
# error, and telling it apart from a real one would be a guess. A list that cannot be read must fail, never
# read as "nothing is let out".
function Get-ForeignAllowOut {
    @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
        [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow' -and [string]$_.Enabled -eq 'True' -and
        -not ([string]$_.Name).StartsWith('TDC-FW-')
    } | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            DisplayName = [string]$_.DisplayName
            Group = [string]$_.DisplayGroup
            Source = [string]$_.PolicyStoreSourceType
        }
    })
}

function Get-NameList {
    param([string]$Text)
    if ($Text -notmatch '^[A-Za-z0-9+/]+={0,2}\z') { throw '-Names must be base64' }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text))
    $list = @(ConvertFrom-Json -InputObject $json)
    foreach ($n in $list) {
        if (-not ($n -is [string]) -or -not $n -or $n.StartsWith('TDC-FW-')) { throw 'not a usable rule name' }
    }
    return $list
}

function Set-AllowOut {
    param([string]$Text, [bool]$On)
    $want = @{}
    foreach ($n in @(Get-NameList $Text)) { $want[$n] = $true }
    $found = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
        $want.ContainsKey([string]$_.Name) -and [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow'
    })
    $done = @()
    $failed = @()
    foreach ($rule in $found) {
        try {
            if ($On) { $rule | Enable-NetFirewallRule -ErrorAction Stop } else { $rule | Disable-NetFirewallRule -ErrorAction Stop }
            $done += [string]$rule.Name
        } catch {
            $failed += [pscustomobject]@{ Name = [string]$rule.Name; Error = [string]$_.Exception.Message }
        }
    }
    $seen = @($found | ForEach-Object { [string]$_.Name })
    $missing = @($want.Keys | Where-Object { $seen -notcontains $_ })
    ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ done = $done; failed = $failed; missing = $missing })
}

try {
    switch ($Op) {
        'Profiles' {
            ConvertTo-Json -Compress -Depth 3 -InputObject (Get-ProfileStates)
        }
        'Enable' {
            Set-NetFirewallProfile -Profile $AllProfiles -Enabled True
        }
        'List' {
            $views = @(Get-NetFirewallRule -Name 'TDC-FW-*' -ErrorAction SilentlyContinue | ForEach-Object { Get-RuleView $_.Name })
            $out = [pscustomobject]@{ profiles = (Get-ProfileStates); rules = $views }
            ConvertTo-Json -Compress -Depth 5 -InputObject $out
        }
        'Get' {
            Assert-OurName $Name
            $view = Get-RuleView $Name
            if ($view) { ConvertTo-Json -Compress -Depth 4 -InputObject $view }
        }
        'Create' {
            Assert-OurName $Name
            if (-not $Action) { throw 'Create needs -Action' }
            $off = @((Get-ProfileStates) | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
            if ($off.Count -gt 0) {
                [Console]::Error.WriteLine($off -join ', ')
                exit 3
            }
            if (Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue) { exit 4 }
            $splat = @{
                Name = $Name
                DisplayName = $Name
                Direction = 'Outbound'
                Action = $Action
                Enabled = 'True'
                Profile = 'Any'
            }
            if ($Program) { $splat['Program'] = $Program }
            if ($RemoteAddress) { $splat['RemoteAddress'] = @($RemoteAddress.Split(',')) }
            if ($RemotePort) { $splat['RemotePort'] = $RemotePort }
            if ($Protocol) { $splat['Protocol'] = $Protocol }
            New-NetFirewallRule @splat | Out-Null
        }
        'Remove' {
            Assert-OurName $Name
            Remove-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
        }
        'SetDefaultOutbound' {
            if (-not $DefaultOutboundAction) { throw 'SetDefaultOutbound needs -DefaultOutboundAction' }
            Set-NetFirewallProfile -Profile (Get-ProfileList $Profiles) -DefaultOutboundAction $DefaultOutboundAction
        }
        'AllowOut' {
            ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ rules = @(Get-ForeignAllowOut) })
        }
        'DisableAllowOut' {
            Set-AllowOut -Text $Names -On $false
        }
        'EnableAllowOut' {
            Set-AllowOut -Text $Names -On $true
        }
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
exit 0
