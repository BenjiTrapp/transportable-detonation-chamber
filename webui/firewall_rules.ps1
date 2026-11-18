# firewall_rules.ps1
# The hands of webui/firewall_rules.py: one verb per call, every value a named parameter.
#
# It is run as   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File firewall_rules.ps1 -Op <verb> ...
# With -File the arguments reach the parameters below as plain strings. Nothing in here evaluates
# them, and nothing is built from them but the arguments of one cmdlet. The caller never uses -Command,
# because that joins the arguments into one line of PowerShell and parses it.
#
# Verbs:
#   Profiles            [{"Name","Enabled","DefaultOutboundAction","Configured","Via"[,"Fallback"]}] of the three profiles:
#                       DefaultOutboundAction as in force (ActiveStore), Configured as set (PersistentStore). Via is
#                       "fast" (COM and CIM, without the NetSecurity module) or "cmdlet"; Fallback says why the fast
#                       way did not answer. The verbs that write read the profiles through the cmdlets, without Via.
#   Compare             reads the profiles and TDC's rules both ways and holds them up against each other, field by
#                       field: {"ok","checked","differences":[{"what","fast","cmdlet"}]}. Every TDC-FW-* rule with every
#                       field of List, as List and as Get read it fast; a rule only one way finds is a difference. Exit 0
#                       when they agree, 1 when not (or when the cmdlets cannot be read; then stderr says why). Writes nothing.
#   Enable              switch the three profiles on
#   List                {"profiles": [...], "rules": [...], "Via"[, "Fallback"]}: the profiles as Profiles gives them,
#                       and every rule named TDC-FW-* as {"Name","Enabled","Action","Direction","Profile","Program",
#                       "RemoteAddress","RemotePort","Protocol"}. Via is "fast" only when both were read without the module.
#   Get -Name           the one rule as JSON, as List gives it plus "Via"[, "Fallback"], or no output at all when there is none
#   Create -Name -Action [-Program] [-RemoteAddress a,b] [-RemotePort] [-Protocol]
#                       an outbound rule. Exit 3: a profile is off (nothing is written). Exit 4: the rule is already there.
#   Remove -Name        remove the rule (no error when it is not there)
#   SetDefaultOutbound -DefaultOutboundAction [-Profiles Domain,Private]
#                       in the PersistentStore, then the three profiles as Profiles gives them, read back
#   AllowOut            {"profiles": [...], "rules": [{"Name","DisplayName","Group","Source"}]}: the profiles as
#                       Profiles gives them, and every enabled outbound Allow rule in
#                       force (ActiveStore) that is not TDC's. DefaultOutboundAction Block governs only traffic that no
#                       rule matches, so each of these still lets traffic out. Source is PolicyStoreSourceType: only
#                       Local rules (the PersistentStore) can be switched here; a GroupPolicy rule cannot.
#   DisableAllowOut -Names <base64>, EnableAllowOut -Names <base64>
#                       switch the named local outbound Allow rules off or on. -Names is base64 of a UTF-8 JSON list
#                       of rule names, so no name is ever a wildcard or a parameter. Only outbound Allow rules of the
#                       PersistentStore that are not TDC-FW-* are touched; {"done": [...], "failed": [{"Name","Error"}],
#                       "missing": [...]} says what happened to each. All of them go through one pipeline; a rule
#                       the pipeline did not change is tried once more on its own, for its own error.
#   RemoveIsolate       remove every rule named TDC-FW-ISO-*: {"removed": [...], "still": [...]}, read back
#   Cut                 the panic cut: one outbound Block rule for every program and address, named TDC-FW-ISO-cut,
#                       written if it is not there, brought to that shape in place (Set-NetFirewallRule, never removed
#                       and written again: that would open the egress for a moment) if it is there disabled or narrower,
#                       then read back as Get gives it. Takes no parameter. Exit 3: a profile is off (nothing is written).
#                       There is no exit 4: a rule that already stands is the wanted result. A repair that fails is
#                       said on stderr with exit 0; the view that follows is what the caller judges.
#                       It is one verb where profile check, write and read back could be three calls, because loading the
#                       NetSecurity module costs 1-2 s per call and the cut has to stand in 3 s or less.
#
# Exit codes: 0 done, 1 failed (the first line of stderr says why), 3 a profile is off, 4 the rule exists.
# Rules are only ever named TDC-FW-<letters, digits, hyphens>; a name with a wildcard or a trailing newline is refused.
#
# Reading without the NetSecurity module. Loading it is most of the cost of a call (measured on the VM: 1.65 s for
# Get-NetFirewallRule against 0.36 s for a bare powershell.exe), and Get-NetFirewallProfile is only a CDXML shell around
# the CIM provider. A read verb therefore asks COM and CIM first, and it takes two sources because neither can answer
# both stores; do not simplify this back to one:
#   - COM (HNetCfg.FwPolicy2) answers what is IN FORCE, and only that. It has no NotConfigured: measured, COM said
#     DefaultOutboundAction 1 (Allow) where the PersistentStore said NotConfigured. Fed into Configured, NotConfigured
#     would become Allow, and ISOLATED would put the host back configured differently from how it found it.
#   - Raw CIM (MSFT_NetFirewallProfile) answers what is CONFIGURED, and only that. It cannot reach the ActiveStore:
#     measured, a query with PolicyStore='ActiveStore' is refused ("Die Anfrage ist ungueltig"), and the plain query
#     answers from the PersistentStore (Domain 0 = NotConfigured).
# Every number of either is translated through a map written out below, number by number, as measured against the
# cmdlets; the Compare verb is what confirms them on a machine. A number that is not in its map, a profile that is
# missing, an empty answer or any error is not guessed at: the verb answers through the cmdlets instead and says so
# (Via "cmdlet", Fallback the reason).
# TDC's rules come from COM too (HNetCfg.FwPolicy2.Rules), for List and Get; the verbs that write read their rule back
# through the cmdlets as before. COM's rule Name is what the cmdlets call DisplayName, not the Name a rule is looked up
# by: the two are one for TDC's rules only because Create and Cut write DisplayName = Name, and Compare holds both lists
# against each other, so a rule whose two names differ shows there.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Profiles', 'Enable', 'List', 'Get', 'Create', 'Remove', 'SetDefaultOutbound', 'AllowOut',
                 'DisableAllowOut', 'EnableAllowOut', 'RemoveIsolate', 'Cut', 'Compare')]
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

# Why the fast way did not answer, as one line of at most 200 characters: it goes into JSON and into the call log.
function Get-ShortReason {
    param($ErrorRecord)
    $reason = ([string]$ErrorRecord.Exception.Message -split "`r?`n")[0]
    if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 200) }
    if (-not $reason) { $reason = 'the fast way failed without a message' }
    return $reason
}

# Two stores, two questions; do not collapse them into one read.
#   DefaultOutboundAction: the ActiveStore, what is IN FORCE. NotConfigured resolves there (to Allow, or to what a
#     group policy sets). "Is ISOLATED in force?", Enabled and everything that is claimed read this.
#   Configured: the PersistentStore, what this machine has CONFIGURED, NotConfigured included. It is the store
#     SetDefaultOutbound writes, so it is what ISOLATED remembers and puts back, and what a write is checked against.
# Without -Fast this is the cmdlet read it always was, and the rows carry no Via: the verbs that write use it so.
# With -Fast it tries Read-FastProfileStates first, and every row says which way answered.
function Get-ProfileStates {
    param([switch]$Fast)
    $fallback = $null
    if ($Fast) {
        try {
            $rows = @(Read-FastProfileStates)
            return $rows
        } catch {
            $fallback = Get-ShortReason $_
        }
    }
    $configured = @{}
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore PersistentStore)) {
        $configured[[string]$p.Name] = [string]$p.DefaultOutboundAction
    }
    @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        $row = [ordered]@{
            Name = [string]$_.Name
            Enabled = ([string]$_.Enabled -eq 'True')
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            Configured = $configured[[string]$_.Name]
        }
        if ($Fast) {
            $row.Via = 'cmdlet'
            $row.Fallback = $fallback
        }
        [pscustomobject]$row
    })
}

# The profiles without the NetSecurity module, in the shape of Get-ProfileStates. In force (Enabled,
# DefaultOutboundAction) from COM, configured from CIM: see the head of this file for why it takes both. Throws on
# anything it cannot vouch for, and emits nothing until all three profiles are read.
function Read-FastProfileStates {
    # The numbers of the fast way, each one written out: derived from a measurement on the VM against the cmdlets,
    # not from documentation, and confirmed only by Compare. No arithmetic on them; a number that is not here throws.
    # NET_FW_PROFILE_TYPE2 of COM, in the order the cmdlets give the profiles.
    $ComProfileType = [ordered]@{ Domain = 1; Private = 2; Public = 4 }
    # COM DefaultOutboundAction (in force). There is no NotConfigured: COM can only say what is in force.
    $ComOutbound = @{ '0' = 'Block'; '1' = 'Allow' }
    # CIM MSFT_NetFirewallProfile.DefaultOutboundAction (the PersistentStore, what is configured).
    $CimOutbound = @{ '0' = 'NotConfigured'; '2' = 'Allow'; '4' = 'Block' }
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $inForce = @{}
    foreach ($name in $ComProfileType.Keys) {
        $type = $ComProfileType[$name]
        $on = $policy.FirewallEnabled($type)
        if (-not ($on -is [bool])) { throw "COM FirewallEnabled of $name is not a boolean: '$on'" }
        $comNumber = [string]$policy.DefaultOutboundAction($type)
        if (-not $ComOutbound.ContainsKey($comNumber)) { throw "COM DefaultOutboundAction of $name is not a known number: '$comNumber'" }
        $inForce[$name] = @{ Enabled = $on; Outbound = $ComOutbound[$comNumber] }
    }
    $set = @{}
    foreach ($cim in @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetFirewallProfile' -ErrorAction Stop)) {
        $name = [string]$cim.Name
        if (-not $ComProfileType.Contains($name)) { throw "CIM names a profile that is not known: '$name'" }
        if ($set.ContainsKey($name)) { throw "CIM names the profile $name twice" }
        $cimNumber = [string]$cim.DefaultOutboundAction
        if (-not $CimOutbound.ContainsKey($cimNumber)) { throw "CIM DefaultOutboundAction of $name is not a known number: '$cimNumber'" }
        $set[$name] = $CimOutbound[$cimNumber]
    }
    $rows = @()
    foreach ($name in $ComProfileType.Keys) {
        if (-not $set.ContainsKey($name)) { throw "CIM does not name the profile $name" }
        $rows += [pscustomobject]@{
            Name = $name
            Enabled = $inForce[$name].Enabled
            DefaultOutboundAction = $inForce[$name].Outbound
            Configured = $set[$name]
            Via = 'fast'
        }
    }
    return $rows
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

# TDC's rules through the cmdlets, as List and Get always read them: every TDC-FW-* rule, or with -RuleName that one.
function Read-CmdletRuleViews {
    param([string]$RuleName)
    if ($RuleName) { return @(Get-RuleView $RuleName | Where-Object { $_ }) }
    return @(Get-NetFirewallRule -Name 'TDC-FW-*' -ErrorAction SilentlyContinue | ForEach-Object { Get-RuleView $_.Name })
}

# TDC's rules without the NetSecurity module, in the shape of Get-RuleView: every rule whose COM name begins TDC-FW-,
# or with -RuleName the one rule of that name (compared whole, never as a pattern; Get has checked it with
# Assert-OurName). The collection is enumerated, not queried, so every rule costs one read, its Name, and only TDC's
# rules are read further: eight more reads each. Throws on anything it cannot vouch for, and emits nothing until every
# rule is read.
function Read-FastRuleViews {
    param([string]$RuleName)
    # The numbers of COM's rules, each written out like those of Read-FastProfileStates and, like them, confirmed only
    # by Compare. No arithmetic on them; a number that is not here throws.
    # NET_FW_RULE_DIRECTION, as the cmdlets print Direction.
    $ComDirection = @{ '1' = 'Inbound'; '2' = 'Outbound' }
    # NET_FW_ACTION, as the cmdlets print Action.
    $ComAction = @{ '0' = 'Block'; '1' = 'Allow' }
    # Profiles is a bitmask of 1 Domain, 2 Private, 4 Public, spelled as the cmdlets print their Profile flags. A rule
    # on every profile is NET_FW_PROFILE2_ALL, which the cmdlets print Any. 7, the three named one by one, is left out:
    # how the cmdlets print that has not been seen.
    $ComProfiles = @{ '1' = 'Domain'; '2' = 'Private'; '3' = 'Domain, Private'; '4' = 'Public'; '5' = 'Domain, Public'; '6' = 'Private, Public'; '2147483647' = 'Any' }
    # The IP protocol number, 256 for any, as the cmdlets print the Protocol TDC writes.
    $ComProtocol = @{ '6' = 'TCP'; '17' = 'UDP'; '256' = 'Any' }
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $views = @()
    $seen = @{}
    $count = 0
    foreach ($rule in $policy.Rules) {
        $count += 1
        $name = [string]$rule.Name
        if ($RuleName) {
            if ($name -ne $RuleName) { continue }
        } elseif (-not $name.StartsWith('TDC-FW-', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        if ($seen.ContainsKey($name)) { throw "COM names the rule $name twice" }
        $seen[$name] = $true
        $enabled = $rule.Enabled
        if (-not ($enabled -is [bool])) { throw "COM Enabled of $name is not a boolean: '$enabled'" }
        $action = [string]$rule.Action
        if (-not $ComAction.ContainsKey($action)) { throw "COM Action of $name is not a known number: '$action'" }
        $direction = [string]$rule.Direction
        if (-not $ComDirection.ContainsKey($direction)) { throw "COM Direction of $name is not a known number: '$direction'" }
        $profileMask = [string]$rule.Profiles
        if (-not $ComProfiles.ContainsKey($profileMask)) { throw "COM Profiles of $name is not a known number: '$profileMask'" }
        $protocol = [string]$rule.Protocol
        if (-not $ComProtocol.ContainsKey($protocol)) { throw "COM Protocol of $name is not a known number: '$protocol'" }
        # No program is null in COM and Any in the cmdlets; a program is the path as written.
        $app = $rule.ApplicationName
        if ($null -eq $app) { $program = 'Any' }
        elseif ($app -is [string] -and $app) { $program = $app }
        else { throw "COM ApplicationName of $name is neither null nor a path: '$app'" }
        # Every address is * in COM and Any in the cmdlets. A single IPv4 host COM spells with the host mask
        # /255.255.255.255, the cmdlets without it; an IPv6 host as it is. A subnet, a range or a keyword is a spelling
        # that has not been compared, and so is not passed on.
        $remote = $rule.RemoteAddresses
        if (-not ($remote -is [string]) -or -not $remote) { throw "COM RemoteAddresses of $name is empty" }
        if ($remote -eq '*') { $addresses = @('Any') }
        else {
            $addresses = @(foreach ($token in $remote.Split(',')) {
                if ($token -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/255\.255\.255\.255\z') { $Matches[1] }
                elseif ($token -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z') { $token }
                elseif ($token -match '^[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\z') { $token }
                else { throw "COM RemoteAddresses of $name has a spelling that is not known: '$token'" }
            })
        }
        # Every port is * in COM, or nothing where the protocol has no ports, and Any in the cmdlets; a port is its
        # number. A range or a keyword is not passed on.
        $remotePorts = $rule.RemotePorts
        if ($null -eq $remotePorts -or $remotePorts -eq '*') { $ports = @('Any') }
        elseif ($remotePorts -is [string]) {
            $ports = @(foreach ($token in $remotePorts.Split(',')) {
                if ($token -match '^\d{1,5}\z') { $token }
                else { throw "COM RemotePorts of $name has a spelling that is not known: '$token'" }
            })
        }
        else { throw "COM RemotePorts of $name is not text: '$remotePorts'" }
        $views += [pscustomobject]@{
            "Name" = $name
            "Enabled" = $enabled
            "Action" = $ComAction[$action]
            "Direction" = $ComDirection[$direction]
            "Profile" = $ComProfiles[$profileMask]
            "Program" = $program
            "RemoteAddress" = $addresses
            "RemotePort" = $ports
            "Protocol" = $ComProtocol[$protocol]
        }
    }
    if ($count -eq 0) { throw 'COM gives no rules at all' }
    return $views
}

# TDC's rules for List (every TDC-FW-* rule) and Get (-RuleName), with the way they were read: {Views, Via, Fallback}.
# The fast way first; on any doubt the cmdlet read, and Fallback says why.
function Get-OurRuleViews {
    param([string]$RuleName)
    try {
        $views = @(Read-FastRuleViews -RuleName $RuleName)
        return [pscustomobject]@{ Views = $views; Via = 'fast'; Fallback = $null }
    } catch {
        $fallback = Get-ShortReason $_
    }
    $views = @(Read-CmdletRuleViews -RuleName $RuleName)
    return [pscustomobject]@{ Views = $views; Via = 'cmdlet'; Fallback = $fallback }
}

# Whether one field read two ways is the same: the same type and the same text, a list element by element, in order.
function Test-SameValue {
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A -is [array] -or $B -is [array]) {
        if (-not ($A -is [array] -and $B -is [array]) -or $A.Count -ne $B.Count) { return $false }
        for ($i = 0; $i -lt $A.Count; $i++) {
            if (-not (Test-SameValue $A[$i] $B[$i])) { return $false }
        }
        return $true
    }
    return ($A.GetType() -eq $B.GetType() -and [string]$A -ceq [string]$B)
}

# The catch-all block of the cut, as Get-RuleView shows it: an enabled outbound Block rule for every program, address,
# port and protocol, on every profile.
function Test-CutShape {
    param($View)
    if (-not $View) { return $false }
    return [bool]($View.Enabled -and $View.Action -eq 'Block' -and $View.Direction -eq 'Outbound' -and
        $View.Profile -eq 'Any' -and $View.Program -eq 'Any' -and $View.Protocol -eq 'Any' -and
        @($View.RemoteAddress).Count -eq 1 -and @($View.RemoteAddress)[0] -eq 'Any' -and
        @($View.RemotePort).Count -eq 1 -and @($View.RemotePort)[0] -eq 'Any')
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
    # The inner parentheses matter: Windows PowerShell 5.1 emits a JSON array as one object without enumerating
    # it, so wrapping the call alone in @() gives a list of one list. Evaluated in parentheses first, it unrolls.
    $list = @((ConvertFrom-Json -InputObject $json))
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
    $target = if ($On) { 'True' } else { 'False' }
    # One pipeline for all of them: one cmdlet invocation, not one per rule (each of those cost a fraction of a
    # second, and the Store apps bring dozens of rules). -PassThru gives back the rules it changed, as they are now;
    # an error on one rule does not stop the others.
    $took = @{}
    if ($found.Count -gt 0) {
        $changed = if ($On) {
            @($found | Enable-NetFirewallRule -PassThru -ErrorAction SilentlyContinue)
        } else {
            @($found | Disable-NetFirewallRule -PassThru -ErrorAction SilentlyContinue)
        }
        foreach ($r in $changed) {
            if ([string]$r.Enabled -eq $target) { $took[[string]$r.Name] = $true }
        }
    }
    $done = @()
    $failed = @()
    foreach ($rule in $found) {
        $name = [string]$rule.Name
        if ($took.ContainsKey($name)) { $done += $name; continue }
        # Not among what the pipeline gave back: once more on its own, so that its own error is said
        try {
            if ($On) { $rule | Enable-NetFirewallRule -ErrorAction Stop } else { $rule | Disable-NetFirewallRule -ErrorAction Stop }
            $done += $name
        } catch {
            $failed += [pscustomobject]@{ Name = $name; Error = [string]$_.Exception.Message }
        }
    }
    $seen = @($found | ForEach-Object { [string]$_.Name })
    $missing = @($want.Keys | Where-Object { $seen -notcontains $_ })
    ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ done = $done; failed = $failed; missing = $missing })
}

# The rules named TDC-FW-ISO-*. "None there" is an empty list; any other error is raised, so that a list that
# cannot be read never reads as "all removed".
function Get-IsolateRules {
    try {
        @(Get-NetFirewallRule -Name 'TDC-FW-ISO-*' -ErrorAction Stop |
            Where-Object { [string]$_.Name -match '^TDC-FW-ISO-[A-Za-z0-9-]{1,36}\z' })
    } catch {
        if ([string]$_.CategoryInfo.Category -eq 'ObjectNotFound') { @() } else { throw }
    }
}

# Every rule named TDC-FW-ISO-* (the per-fetch allow rules, their stand-ins, and the rules of older versions),
# removed in one call and read back.
function Remove-IsolateRules {
    $rules = @(Get-IsolateRules)
    $names = @($rules | ForEach-Object { [string]$_.Name })
    if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    $still = @(Get-IsolateRules | ForEach-Object { [string]$_.Name })
    ConvertTo-Json -Compress -Depth 3 -InputObject ([pscustomobject]@{ removed = @($names | Where-Object { $still -notcontains $_ }); still = $still })
}

try {
    switch ($Op) {
        'Profiles' {
            ConvertTo-Json -Compress -Depth 3 -InputObject (Get-ProfileStates -Fast)
        }
        'Compare' {
            # Both ways side by side; this reads and changes nothing. A fast way that cannot answer is a difference
            # too: what it did not say has not been confirmed.
            $cmdlet = @{}
            foreach ($row in @(Get-ProfileStates)) { $cmdlet[[string]$row.Name] = $row }
            $fast = @{}
            $differences = @()
            try {
                foreach ($row in @(Read-FastProfileStates)) { $fast[[string]$row.Name] = $row }
            } catch {
                $differences += [pscustomobject]@{ what = 'profiles'; fast = "error: $(Get-ShortReason $_)"; cmdlet = 'read' }
            }
            $checked = 0
            if ($differences.Count -eq 0) {
                foreach ($name in $AllProfiles) {
                    foreach ($field in @('Enabled', 'DefaultOutboundAction', 'Configured')) {
                        $checked += 1
                        $a = if ($fast.ContainsKey($name)) { $fast[$name].$field } else { $null }
                        $b = if ($cmdlet.ContainsKey($name)) { $cmdlet[$name].$field } else { $null }
                        if ($null -eq $a -or $null -eq $b -or $a.GetType() -ne $b.GetType() -or [string]$a -cne [string]$b) {
                            $differences += [pscustomobject]@{ what = "profile $name $field"; fast = $a; cmdlet = $b }
                        }
                    }
                }
            }
            # TDC's rules: every one either way finds, as the fast List reads it and as the fast Get reads it alone,
            # against the cmdlets. A rule only one way finds is a difference, so is a field that is not the same.
            $cmdletRules = @{}
            foreach ($view in @(Read-CmdletRuleViews)) { $cmdletRules[[string]$view.Name] = $view }
            $fastWays = [ordered]@{ List = @{}; Get = @{} }
            $rulesRead = $true
            try {
                foreach ($view in @(Read-FastRuleViews)) { $fastWays.List[[string]$view.Name] = $view }
                foreach ($name in @(@($fastWays.List.Keys) + @($cmdletRules.Keys) | Sort-Object -Unique)) {
                    foreach ($view in @(Read-FastRuleViews -RuleName $name)) { $fastWays.Get[$name] = $view }
                }
            } catch {
                $rulesRead = $false
                $differences += [pscustomobject]@{ what = 'rules'; fast = "error: $(Get-ShortReason $_)"; cmdlet = 'read' }
            }
            if ($rulesRead) {
                $ruleNames = @(@($fastWays.List.Keys) + @($cmdletRules.Keys) | Sort-Object -Unique)
                foreach ($way in $fastWays.Keys) {
                    $fastRules = $fastWays[$way]
                    foreach ($name in $ruleNames) {
                        $checked += 1
                        $inFast = $fastRules.ContainsKey($name)
                        $inCmdlet = $cmdletRules.ContainsKey($name)
                        if (-not ($inFast -and $inCmdlet)) {
                            $differences += [pscustomobject]@{
                                what = "$way rule $name"
                                fast = $(if ($inFast) { 'present' } else { 'absent' })
                                cmdlet = $(if ($inCmdlet) { 'present' } else { 'absent' })
                            }
                            continue
                        }
                        foreach ($field in @('Name', 'Enabled', 'Action', 'Direction', 'Profile', 'Program', 'RemoteAddress', 'RemotePort', 'Protocol')) {
                            $checked += 1
                            $a = $fastRules[$name].$field
                            $b = $cmdletRules[$name].$field
                            if (-not (Test-SameValue $a $b)) {
                                $differences += [pscustomobject]@{ what = "$way rule $name $field"; fast = $a; cmdlet = $b }
                            }
                        }
                    }
                }
            }
            $ok = ($differences.Count -eq 0)
            ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]@{ ok = $ok; checked = $checked; differences = $differences })
            if (-not $ok) { exit 1 }
        }
        'Enable' {
            Set-NetFirewallProfile -Profile $AllProfiles -Enabled True
        }
        'List' {
            $read = Get-OurRuleViews
            $states = @(Get-ProfileStates -Fast)
            # One way for the whole answer: fast only when the rules and the profiles were both read without the module.
            $out = [ordered]@{ profiles = $states; rules = $read.Views; Via = 'fast' }
            if ($read.Via -ne 'fast') {
                $out.Via = 'cmdlet'
                $out.Fallback = $read.Fallback
            } elseif ($states[0].Via -ne 'fast') {
                $out.Via = 'cmdlet'
                $out.Fallback = $states[0].Fallback
            }
            ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]$out)
        }
        'Get' {
            Assert-OurName $Name
            $read = Get-OurRuleViews -RuleName $Name
            $view = @($read.Views) | Select-Object -First 1
            if ($view) {
                $view | Add-Member -NotePropertyName Via -NotePropertyValue $read.Via
                if ($read.Via -ne 'fast') { $view | Add-Member -NotePropertyName Fallback -NotePropertyValue $read.Fallback }
                ConvertTo-Json -Compress -Depth 4 -InputObject $view
            }
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
        'Cut' {
            $cut = 'TDC-FW-ISO-cut'
            Assert-OurName $cut
            $off = @((Get-ProfileStates) | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
            if ($off.Count -gt 0) {
                [Console]::Error.WriteLine($off -join ', ')
                exit 3
            }
            $view = Get-RuleView $cut
            if (-not $view) {
                New-NetFirewallRule -Name $cut -DisplayName $cut -Direction Outbound -Action Block -Enabled True -Profile Any | Out-Null
                $view = Get-RuleView $cut
            } elseif (-not (Test-CutShape $view)) {
                # A rule of this name that is disabled or narrower than the catch-all (a crash, an older version, a sample
                # with admin rights) is brought to the wanted shape in place: Set-NetFirewallRule changes the rule under its
                # own name, so there is never a moment without it. Remove and New would open the egress in between.
                # A repair that fails is said on stderr, and the view below is what the caller judges.
                try {
                    $want = @{
                        Name = $cut; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any'
                        Program = 'Any'; RemoteAddress = 'Any'; RemotePort = 'Any'; Protocol = 'Any'
                    }
                    Set-NetFirewallRule @want
                } catch {
                    [Console]::Error.WriteLine($_.Exception.Message)
                }
                $view = Get-RuleView $cut
            }
            ConvertTo-Json -Compress -Depth 4 -InputObject $view
        }
        'Remove' {
            Assert-OurName $Name
            Remove-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
        }
        'SetDefaultOutbound' {
            if (-not $DefaultOutboundAction) { throw 'SetDefaultOutbound needs -DefaultOutboundAction' }
            # The PersistentStore (the default of Set-NetFirewallProfile, named so it is not mistaken for the ActiveStore)
            Set-NetFirewallProfile -PolicyStore PersistentStore -Profile (Get-ProfileList $Profiles) -DefaultOutboundAction $DefaultOutboundAction
            ConvertTo-Json -Compress -Depth 3 -InputObject (Get-ProfileStates)
        }
        'AllowOut' {
            ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ profiles = (Get-ProfileStates); rules = @(Get-ForeignAllowOut) })
        }
        'RemoveIsolate' {
            Remove-IsolateRules
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
