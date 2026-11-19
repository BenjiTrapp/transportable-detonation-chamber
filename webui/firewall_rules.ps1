# firewall_rules.ps1
# The hands of webui/firewall_rules.py: one verb per call, every value a named parameter.
#
# It is run as   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File firewall_rules.ps1 -Op <verb> ...
# With -File the arguments reach the parameters below as plain strings. Nothing in here evaluates
# them, and nothing is built from them but the arguments of one cmdlet. The caller never uses -Command,
# because that joins the arguments into one line of PowerShell and parses it.
#
# Verbs:
#   Profiles            [{"Name","Enabled","DefaultOutboundAction","Configured","Via"[,"Fallback"]}] of the three
#                       profiles: DefaultOutboundAction as in force (ActiveStore), Configured as set (PersistentStore).
#                       Via is "fast" (CIM with the PolicyStore option, without the NetSecurity module) or "cmdlet", and
#                       then Fallback says why; see "Profiles over CIM with the PolicyStore option" below.
#   Compare             reads the profiles and TDC's rules both ways and holds them up against each other, field by
#                       field: {"ok","rules","checked":{"profiles","displayNames","names","fields"},
#                       "differences":[{"what","fast","cmdlet"}]}. Every profile's Enabled, DefaultOutboundAction and
#                       Configured as Read-FastProfileStates and as the cmdlets read them; every TDC-FW-* rule with
#                       every field of List, as List and as Get read it fast. A rule only one way finds is a difference.
#                       rules is how many TDC rules either way found, and each kind of check is counted on its own: 0
#                       means nothing of that kind was compared, whatever ok says. Exit 0 when they agree, 1 when not
#                       (or when the cmdlets cannot be read; then stderr says why). Writes nothing.
#   Enable              switch the three profiles on
#   List                {"profiles": [...], "rules": [...], "Via"[, "Fallback"]}: the profiles as Profiles gives them,
#                       and every rule named TDC-FW-* as {"Name","Enabled","Action","Direction","Profile","Program",
#                       "RemoteAddress","RemotePort","Protocol"}. Via is the way the rules were read: "fast" (COM,
#                       without the NetSecurity module) or "cmdlet", and then Fallback says why.
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
# Get-NetFirewallRule against 0.36 s for a bare powershell.exe). List and Get read TDC's rules over COM
# (HNetCfg.FwPolicy2.Rules) first; every number COM gives is translated through a map written out in
# Read-FastRuleViews, number by number, as measured against the cmdlets, and the Compare verb is what confirms them on a
# machine. A number that is not in its map, a spelling that is not known, an empty answer or any error is not guessed
# at: the verb answers through the cmdlets instead and says so (Via "cmdlet", Fallback the reason). The verbs that
# write read their rule back through the cmdlets as before.
# Which store each way reads, as measured (see "Profiles over CIM with the PolicyStore option" for the experiment):
#   - COM reads the local store, the PersistentStore, and not what is in force: a group policy's value is not in
#     what COM says.
#   - Get-NetFirewallRule without -PolicyStore reads its default, the PersistentStore too. Create and Cut write there
#     (New-NetFirewallRule's default store), so TDC's own rules live there.
#   For TDC's rules both ways therefore read the same store, and that is why Compare agrees with them field by field.
#   The one bounded residual: a rule named TDC-FW-* that a group policy sets is not in the PersistentStore, so the
#   cmdlet read does not see it. Should COM's rule collection show it (for rules that is not measured), the fast read
#   sees it and the cmdlet read does not, and Compare's check of the set of names is what shows it. Should COM not show
#   it, neither way sees it, as List never did before COM. The cmdlet
#   fallback of List and Get stays on the PersistentStore, as it always read: a fallback answers what it answered
#   before, never another store.
# COM's rule Name is what the cmdlets call DisplayName, not the Name a rule is looked up by: the two are one for TDC's
# rules only because Create and Cut write DisplayName = Name, and Compare checks exactly that for every TDC rule.
#
# Profiles over CIM with the PolicyStore option. Its in-force value is what verified, the ISOLATED band and
# startup_state rest on, so the fast way may only ever answer what the cmdlets would: a configured value given out as
# in force is the one failure this file exists to prevent. What does not reach the ActiveStore, measured on the VM:
#   - COM (HNetCfg.FwPolicy2 DefaultOutboundAction) reads the local store, not what is in force. Measured with the
#     local GPO store written through Set-NetFirewallProfile -PolicyStore <computer name>:
#       local GPO (Domain outbound)  = Allow
#       PersistentStore              = Block
#       ActiveStore (in force)       = Allow   (the policy wins)
#       COM                          = 0 = Block
#     So where a group policy sets outbound Allow over the local Block that ISOLATED writes, a COM read reports Block,
#     closed, while the egress is open. Compare found exactly this, and the COM read of the profiles was reverted.
#   - Raw CIM (MSFT_NetFirewallProfile) without an option answers the PersistentStore, what is configured. Neither a
#     namespace (root/standardcimv2/ActiveStore is "Ungueltiger Namespace") nor a query filter
#     (PolicyStore='ActiveStore' is "Die Anfrage ist ungueltig") reaches the ActiveStore.
# What does: -PolicyStore as a CIM operation option, the mechanism of the NetSecurity module itself (its CDXML declares
# <Option OptionName="PolicyStore">), set directly with CimOperationOptions.SetCustomOption. Measured on the VM, in the
# policy state above:
#       no option                    Domain = 4 = Block   538 rules   the PersistentStore
#       option 'ActiveStore'         Domain = 2 = Allow   539 rules   the ActiveStore, what is in force
#       option 'PersistentStore'     Domain = 4 = Block   538 rules   the PersistentStore
#       cmdlets                      ActiveStore Allow, PersistentStore Block
#   Both stores in a fresh process: 0.61 s against 1.20 s through the cmdlets (213 ms of it inside the process, the
#   second store only +39 ms on the warm session), and the NetSecurity module is not loaded. The session is
#   CimSession::Create('.'); Create($null) fails with "Der Parameter ist ungueltig".
# The option cannot be forced: SetCustomOption with mustComply $true is refused for every call by the WS-Man WMI
# plug-in ("unterstuetzt das angegebene OptionSet-Element nicht"), so it is set with $false. A provider that ignored it
# would silently answer the PersistentStore, and TDC would give a configured value out as in force. The sentinel stands
# in for mustComply: before any store is read, Read-FastProfileStates reads a store that cannot exist. Measured, that
# fails ("Der Netzwerkpfad wurde nicht gefunden", in 140 ms; the real read after it costs 34 ms). Should it answer, the
# option is being ignored, and the fast way throws instead of answering. It is a proof per call, not a promise of the
# API, and it proves something only when it comes before the first value that is used.
# Every value is translated through a map written out in Read-FastProfileStates and matched case-exactly. A value not in
# its map, a profile missing or named twice, an empty answer, CIM not being there at all, or any other error is not
# guessed at: Profiles answers through the cmdlets instead and says so (Via "cmdlet", Fallback the reason). Compare
# holds the two ways up against each other; no test off Windows can confirm what the option reads on a machine.
# The verbs that write (Create, Cut, SetDefaultOutbound) check and read back the profiles through the cmdlets, as they
# always did.

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

# The profiles without the NetSecurity module, in the shape of the rows of Get-ProfileStates: in force (Enabled,
# DefaultOutboundAction) from the ActiveStore, configured (Configured) from the PersistentStore, both over CIM with the
# PolicyStore operation option (see "Profiles over CIM with the PolicyStore option" at the head of this file). Each
# store fills a table of its own, and each table is filled in one line that names its store, so that no row can take a
# value from the other store. Throws on anything it cannot vouch for, and emits nothing until all three profiles are
# read from both stores.
function Read-FastProfileStates {
    # The values of MSFT_NetFirewallProfile, each one written out: measured on the VM against the cmdlets, not taken
    # from documentation, and confirmed only by Compare. No arithmetic on them; a value that is not here throws.
    # DefaultOutboundAction, as the cmdlets print it. The numbers were measured on this path (all three, 2 included);
    # the names came back from the same class on the same VM through the way this script read it before, for a reason
    # not known. Both forms are accepted, each written out, and matched case-exactly by $mapped.
    $CimOutbound = @{ '0' = 'NotConfigured'; '2' = 'Allow'; '4' = 'Block'; 'NotConfigured' = 'NotConfigured'; 'Allow' = 'Allow'; 'Block' = 'Block' }
    # Enabled is 0 and 1 on this path, measured with the Public profile's firewall switched off; not the 1 and 2 of
    # the WMI convention. Nothing else is accepted, not even a spelling of true or false.
    $CimEnabled = @{ '0' = $false; '1' = $true }
    # One value through its map, or a throw. A PowerShell hashtable ignores case, so ContainsKey alone would let a
    # `block` through that is not listed; the key must also be one of the map's own, compared case-exactly.
    $mapped = {
        param($Map, $Row, [string]$Field)
        $Value = [string]$Row.$Field
        if (-not ($Map.ContainsKey($Value) -and @($Map.Keys) -ccontains $Value)) { throw "CIM $($Row.Store) $Field of $($Row.Name) is not a known value: '$Value'" }
        $Map[$Value]
    }
    # Create('.'), the local machine: Create($null) fails with "Der Parameter ist ungueltig".
    $session = [Microsoft.Management.Infrastructure.CimSession]::Create('.')
    try {
        # One store's profiles, as CIM gives them. mustComply is $false because the WS-Man WMI plug-in refuses every
        # call that sets it $true; the sentinel below is what stands in for it.
        $enumerate = {
            param([string]$Store)
            $options = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
            $options.SetCustomOption('PolicyStore', $Store, $false)
            @($session.EnumerateInstances('root/StandardCimv2', 'MSFT_NetFirewallProfile', $options))
        }
        # One store's three profiles in the order of $AllProfiles, their values not yet mapped, or a throw.
        $readStore = {
            param([string]$Store)
            $rows = @{}
            foreach ($p in @(& $enumerate $Store)) {
                $name = [string]$p.CimInstanceProperties['Name'].Value
                if (-not ($AllProfiles -ccontains $name)) { throw "CIM $Store names a profile that is not known: '$name'" }
                if ($rows.ContainsKey($name)) { throw "CIM $Store names the profile $name twice" }
                $rows[$name] = [pscustomobject]@{ Store = $Store; Name = $name; Enabled = $p.CimInstanceProperties['Enabled'].Value; DefaultOutboundAction = $p.CimInstanceProperties['DefaultOutboundAction'].Value }
            }
            foreach ($name in $AllProfiles) {
                if (-not $rows.ContainsKey($name)) { throw "CIM $Store does not name the profile $name" }
            }
            @(foreach ($name in $AllProfiles) { $rows[$name] })
        }
        # The sentinel, before any store is read: a store that cannot exist must fail. If it answers at all, even with
        # nothing, the option is being ignored and every read below would be the PersistentStore under another name.
        # Moved behind a real read, it would prove nothing about that read.
        $honoured = $false
        try { $null = & $enumerate 'TDC-NoSuchStore' } catch { $honoured = $true }
        if (-not $honoured) { throw 'the PolicyStore option is ignored: the store TDC-NoSuchStore answered, so no store read here can be trusted' }
        $inForce = @{}
        $configured = @{}
        foreach ($p in @(& $readStore 'ActiveStore')) { $inForce[$p.Name] = @{ Enabled = (& $mapped $CimEnabled $p 'Enabled'); Outbound = (& $mapped $CimOutbound $p 'DefaultOutboundAction') } }
        foreach ($p in @(& $readStore 'PersistentStore')) { $configured[$p.Name] = & $mapped $CimOutbound $p 'DefaultOutboundAction' }
        $states = @(foreach ($name in $AllProfiles) {
            [pscustomobject]@{
                Name = $name
                Enabled = $inForce[$name].Enabled
                DefaultOutboundAction = $inForce[$name].Outbound
                Configured = $configured[$name]
            }
        })
        return $states
    } finally {
        $session.Dispose()
    }
}

# Two stores, two questions; do not collapse them into one read.
#   DefaultOutboundAction: the ActiveStore, what is IN FORCE. NotConfigured resolves there (to Allow, or to what a
#     group policy sets). "Is ISOLATED in force?", Enabled and everything that is claimed read this.
#   Configured: the PersistentStore, what this machine has CONFIGURED, NotConfigured included. It is the store
#     SetDefaultOutbound writes, so it is what ISOLATED remembers and puts back, and what a write is checked against.
# Every verb reads the profiles through here, as {Rows, Via, Fallback}. The fast way first (Read-FastProfileStates); on
# any doubt the cmdlet read it always was, and Fallback says why. With -CmdletsOnly the cmdlets alone: the verbs that
# write check and read back through them as before, and Compare holds them up against the fast way; Fallback is null.
function Get-ProfileStates {
    param([switch]$CmdletsOnly)
    $fallback = $null
    if (-not $CmdletsOnly) {
        try {
            $rows = @(Read-FastProfileStates)
            return [pscustomobject]@{ Rows = $rows; Via = 'fast'; Fallback = $null }
        } catch {
            $fallback = Get-ShortReason $_
        }
    }
    $configured = @{}
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore PersistentStore)) {
        $configured[[string]$p.Name] = [string]$p.DefaultOutboundAction
    }
    $rows = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            Enabled = ([string]$_.Enabled -eq 'True')
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            Configured = $configured[[string]$_.Name]
        }
    })
    return [pscustomobject]@{ Rows = $rows; Via = 'cmdlet'; Fallback = $fallback }
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
    # The numbers of COM's rules, each one written out: derived from a measurement on the VM against the cmdlets, not
    # from documentation, and confirmed only by Compare. No arithmetic on them; a number that is not here throws.
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
        # An invariant carries this match. COM's Name is what the cmdlets call DisplayName, not their Name (the ID
        # that the cmdlets' -Name, so TDC's Get and Remove and the tdc-unisolate hatch, look a rule up by).
        # The two are one for TDC's rules only because Create and Cut write DisplayName = Name. Should that ever stop
        # being true (netsh's name= sets only the DisplayName and leaves the ID a GUID), this reads a rule that TDC
        # can report but not remove by name, and a catch-all Block that cannot be removed keeps the VM off the network.
        # Compare checks the invariant: the set of names both ways find must be the same.
        # The other direction fails without a fallback: a rule whose DisplayName was renamed is not matched here, so the
        # fast Get answers "not there" with Via fast. cut_stands then says False while the cut is in force: wrong, but in
        # the safe direction (TDC claims less isolation than there is, never more).
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
        # Every address is * in COM and Any in the cmdlets. COM writes a single address of either family as a range
        # from it to itself, the cmdlets write it once; both measured on the VM: 1.1.1.1-1.1.1.1 for 1.1.1.1 and
        # 2606:4700:4700::1111-2606:4700:4700::1111 for 2606:4700:4700::1111. So a token is either one address, or two
        # ends split on - that are the same text, and that one end must then be an IPv4 or an IPv6 host. A range with
        # different ends throws: TDC never writes one, and collapsing it to one address would be a lie about what the
        # rule covers. A subnet or a keyword throws too, as a spelling that has not been compared.
        $remote = $rule.RemoteAddresses
        if (-not ($remote -is [string]) -or -not $remote) { throw "COM RemoteAddresses of $name is empty" }
        if ($remote -eq '*') { $addresses = @('Any') }
        else {
            $addresses = @(foreach ($token in $remote.Split(',')) {
                $ends = $token.Split('-')
                if ($ends.Count -eq 1) { $single = $token }
                elseif ($ends.Count -eq 2 -and $ends[0] -ceq $ends[1]) { $single = $ends[0] }
                else { throw "COM RemoteAddresses of $name has a spelling that is not known: '$token'" }
                if ($single -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z') { $single }
                elseif ($single -match '^[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\z') { $single }
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

# AllowOut stays on the cmdlets, module load and all; do not move it to CIM or COM. It must read the ActiveStore, what
# is in force, group policy included, and neither fast source can:
#   - COM has no PolicyStoreSourceType, so a group-policy rule could not be told from a local one.
#   - Raw CIM has no route to the ActiveStore. Measured on the VM: root/standardcimv2/ActiveStore is "Ungueltiger
#     Namespace", and the PolicyStoreSource of all 538 rules raw CIM gives is PersistentStore. The counts agreed
#     (cmdlet ActiveStore 135, cmdlet PersistentStore 135, CIM 135) only because that VM has no group-policy rules.
#     On a host that has them, they are in the ActiveStore and not in the PersistentStore: read over CIM, they would
#     vanish from allowed_out, and ISOLATED would say closed while they let traffic out. No guard can catch that,
#     because seeing the difference takes a read of the ActiveStore.
# It gains little besides: AllowOut runs only while ISOLATED is on and during a convergence, never in a tab's polls.
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
            $read = Get-ProfileStates
            foreach ($row in $read.Rows) {
                $row | Add-Member -NotePropertyName Via -NotePropertyValue $read.Via
                if ($read.Via -ne 'fast') { $row | Add-Member -NotePropertyName Fallback -NotePropertyValue $read.Fallback }
            }
            ConvertTo-Json -Compress -Depth 3 -InputObject $read.Rows
        }
        'Compare' {
            # The profiles and TDC's rules both ways side by side; this reads and changes nothing. A fast way that
            # cannot answer is a difference too: what it did not say has not been confirmed. Each kind of check is
            # counted on its own, so that a pass over no profile or no rule at all reads as one.
            $checked = [ordered]@{ profiles = 0; displayNames = 0; names = 0; fields = 0 }
            $differences = @()
            # Every profile's in-force and configured values, read on their own both ways: the fast reader itself, not
            # Get-ProfileStates, which answers one way only, against the cmdlets alone.
            $cmdletProfiles = @{}
            foreach ($row in @((Get-ProfileStates -CmdletsOnly).Rows)) { $cmdletProfiles[[string]$row.Name] = $row }
            $fastProfiles = @{}
            $profilesRead = $true
            try {
                foreach ($row in @(Read-FastProfileStates)) { $fastProfiles[[string]$row.Name] = $row }
            } catch {
                $profilesRead = $false
                $differences += [pscustomobject]@{ what = 'profiles'; fast = "error: $(Get-ShortReason $_)"; cmdlet = 'read' }
            }
            if ($profilesRead) {
                foreach ($name in @(@($AllProfiles) + @($cmdletProfiles.Keys) + @($fastProfiles.Keys) | Select-Object -Unique)) {
                    foreach ($field in @('Enabled', 'DefaultOutboundAction', 'Configured')) {
                        $checked.profiles += 1
                        $a = $fastProfiles[$name].$field
                        $b = $cmdletProfiles[$name].$field
                        if (-not (Test-SameValue $a $b)) {
                            $differences += [pscustomobject]@{ what = "profile $name $field"; fast = $a; cmdlet = $b }
                        }
                    }
                }
            }
            # Every rule either way finds, as the fast List reads it and as the fast Get reads it alone, against the
            # cmdlets. A rule only one way finds is a difference, so is a field that is not the same.
            $cmdletRules = @{}
            foreach ($view in @(Read-CmdletRuleViews)) { $cmdletRules[[string]$view.Name] = $view }
            # The invariant itself: the fast way matches a rule by COM's Name, which is the cmdlets' DisplayName, so
            # every TDC rule must carry its Name as its DisplayName. Two rules with swapped names give equal name sets
            # below; they do not get past this.
            foreach ($rule in @(Get-NetFirewallRule -Name 'TDC-FW-*' -ErrorAction SilentlyContinue)) {
                $checked.displayNames += 1
                if (-not ([string]$rule.DisplayName -ceq [string]$rule.Name)) {
                    $differences += [pscustomobject]@{
                        what = "rule $([string]$rule.Name) DisplayName is not its Name"
                        fast = [string]$rule.DisplayName
                        cmdlet = [string]$rule.Name
                    }
                }
            }
            $fastWays = [ordered]@{ List = @{}; Get = @{} }
            $rulesRead = $true
            $ruleNames = @($cmdletRules.Keys)
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
                # The set of names, a check of its own: COM's Name is the cmdlets' DisplayName, and the two ways find
                # the same rules only while TDC writes DisplayName = Name (see Read-FastRuleViews). A rule found by
                # one side only is said, with the side that found it.
                foreach ($way in $fastWays.Keys) {
                    foreach ($name in $ruleNames) {
                        $checked.names += 1
                        $inFast = $fastWays[$way].ContainsKey($name)
                        $inCmdlet = $cmdletRules.ContainsKey($name)
                        if ($inFast -ne $inCmdlet) {
                            $differences += [pscustomobject]@{
                                what = "$way rule names: $name found by one side only"
                                fast = $(if ($inFast) { 'found' } else { 'not found' })
                                cmdlet = $(if ($inCmdlet) { 'found' } else { 'not found' })
                            }
                        }
                    }
                }
                # Then every field of every rule both sides found.
                foreach ($way in $fastWays.Keys) {
                    $fastRules = $fastWays[$way]
                    foreach ($name in $ruleNames) {
                        if (-not ($fastRules.ContainsKey($name) -and $cmdletRules.ContainsKey($name))) { continue }
                        foreach ($field in @('Name', 'Enabled', 'Action', 'Direction', 'Profile', 'Program', 'RemoteAddress', 'RemotePort', 'Protocol')) {
                            $checked.fields += 1
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
            ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]@{
                ok = $ok; rules = $ruleNames.Count; checked = [pscustomobject]$checked; differences = $differences
            })
            if (-not $ok) { exit 1 }
        }
        'Enable' {
            Set-NetFirewallProfile -Profile $AllProfiles -Enabled True
        }
        'List' {
            $read = Get-OurRuleViews
            # Via is the way of the rules alone: the profiles may have come either way, and List does not yet say which.
            $out = [ordered]@{ profiles = (Get-ProfileStates).Rows; rules = $read.Views; Via = $read.Via }
            if ($read.Via -ne 'fast') { $out.Fallback = $read.Fallback }
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
            } else {
                # No rule: stdout stays empty, which the caller reads as "not there". The way goes to stderr, so that
                # the call log names it even here, the commonest Get (the cut_stands poll).
                $marker = [ordered]@{ Via = $read.Via }
                if ($read.Via -ne 'fast') { $marker.Fallback = $read.Fallback }
                [Console]::Error.WriteLine((ConvertTo-Json -Compress -InputObject ([pscustomobject]$marker)))
            }
        }
        'Create' {
            Assert-OurName $Name
            if (-not $Action) { throw 'Create needs -Action' }
            $off = @((Get-ProfileStates -CmdletsOnly).Rows | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
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
            $off = @((Get-ProfileStates -CmdletsOnly).Rows | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
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
            ConvertTo-Json -Compress -Depth 3 -InputObject (Get-ProfileStates -CmdletsOnly).Rows
        }
        'AllowOut' {
            ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ profiles = (Get-ProfileStates).Rows; rules = @(Get-ForeignAllowOut) })
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
