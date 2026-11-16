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
#
# Exit codes: 0 done, 1 failed (the first line of stderr says why), 3 a profile is off, 4 the rule exists.
# Rules are only ever named TDC-FW-<letters, digits, hyphens>; a name with a wildcard or a trailing newline is refused.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Profiles', 'Enable', 'List', 'Get', 'Create', 'Remove', 'SetDefaultOutbound')]
    [string]$Op,
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
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
exit 0
