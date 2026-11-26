# measure-secondary-addresses.ps1
# Measures what a secondary IPv4 address on the real adapter costs and how many the adapter carries. It changes
# nothing permanently and installs nothing: it adds addresses out of 198.18.0.0/15, times each one, and removes
# every address it added in a finally block.
#
# This settles an open question of the fake internet design
# (docs/superpowers/specs/2026-11-25-fake-internet-design.md): whether every faked name can have its own address.
# If it can, a fake server knows from the destination address which name was meant - without SNI and without a Host
# header, which is the only way a raw protocol with no name in it can be attributed. If it cannot, the fallback is a
# single address with the name taken from SNI or Host, and raw protocols lose that.
#
# Run it in an elevated PowerShell on the detonation VM, with the chamber idle, on both hypervisors: x64 and ARM64
# behave differently on the network, so one measurement answers for one of them only.
#
#     powershell -ExecutionPolicy Bypass -File measure-secondary-addresses.ps1
#
# What it reports, as one JSON object at the end:
#   rounds[]                               per batch: median, min and max milliseconds per address, and three
#                                          controls measured after the batch - how long the address list takes to
#                                          read, a listening socket takes to bind, and a name takes to resolve. An
#                                          address that slows the rest of the stack is expensive even when adding it
#                                          is fast.
#   addresses_carried                      how many the adapter took before an add failed
#   skipassource_honoured                  whether every added address kept SkipAsSource. If this is false the
#                                          design does not hold: outbound connections could leave the guest with a
#                                          198.18 source address.
#   source_address_for_public_destination  which source the routing table picks for a public destination - it must
#                                          still be the real one
#   add_by_cmdlet_ms                       New-NetIPAddress once, for comparison with netsh
#   remove_total_s, addresses_left_behind  what the cleanup cost and whether it was complete
#
# Written for PowerShell 5.1, which is what Windows ships.

[CmdletBinding()]
param(
    # Measured in growing batches: the cost per address is not expected to be
    # constant, and the point where it stops being flat is the interesting one.
    [int[]] $Batches = @(1, 9, 40, 50, 100, 200, 300, 300),
    # 198.18.0.0/15 is the benchmarking range of RFC 2544: routable nowhere.
    [string] $Prefix = "198.18",
    [string] $Mask = "255.255.0.0"
)

$ErrorActionPreference = "Stop"

function Fail($message) {
    Write-Host "SPIKE ABORTED: $message" -ForegroundColor Red
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "needs an elevated PowerShell - adding an address is an administrative operation"
}

# The adapter that carries the default route is the one the fake internet would
# use. Picking it by the route, not by name, keeps this working on both
# hypervisors (UTM/ARM64 and Hyper-V/x64 name their adapters differently).
$route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object -Property RouteMetric |
    Select-Object -First 1
if (-not $route) { Fail "no default route - cannot tell which adapter the guest talks through" }

$ifIndex = $route.InterfaceIndex
$adapter = Get-NetAdapter -InterfaceIndex $ifIndex
$real = @(Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "$Prefix.*" })

Write-Host "adapter      : $($adapter.Name) (index $ifIndex, $($adapter.LinkSpeed))"
Write-Host "real address : $(($real | ForEach-Object { $_.IPAddress }) -join ', ')"
Write-Host "range        : $Prefix.x.x / $Mask, skipassource=true"
Write-Host ""

# Leftovers from an interrupted earlier run would distort every measurement.
$stale = @(Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like "$Prefix.*" })
if ($stale.Count -gt 0) {
    Write-Host "removing $($stale.Count) leftover address(es) from an earlier run"
    foreach ($s in $stale) {
        & netsh interface ipv4 delete address $ifIndex $s.IPAddress 2>&1 | Out-Null
    }
}

# --- what each round measures besides the address itself ---------------------
#
# An address is useless if it makes the rest of the stack slow. Three controls
# run after every batch, because a cost that only shows up elsewhere is still a
# cost:
#   enumerate  - how long Get-NetIPAddress takes (the diverter will poll the
#                TCP table and the address list while a session runs)
#   bind       - how long binding a listening socket takes (the fake servers
#                bind one per port, and later per port per address)
#   resolve    - how long a lookup of a name that does not exist takes (the
#                sample's own lookups go through the same stack)
function Measure-Controls($index) {
    $enumerate = (Measure-Command {
        Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 | Out-Null
    }).TotalMilliseconds

    $bind = (Measure-Command {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 0)
        $listener.Start()
        $listener.Stop()
    }).TotalMilliseconds

    $resolve = (Measure-Command {
        try { [System.Net.Dns]::GetHostAddresses("spike-does-not-exist.invalid") | Out-Null }
        catch { }
    }).TotalMilliseconds

    $controls = [ordered]@{}
    $controls["enumerate_ms"] = [math]::Round($enumerate, 1)
    $controls["bind_ms"] = [math]::Round($bind, 1)
    $controls["resolve_ms"] = [math]::Round($resolve, 1)
    return $controls
}

# --- the two ways to add an address -----------------------------------------
#
# The design assumed netsh. New-NetIPAddress is the PowerShell cmdlet for the
# same thing and goes through WMI, which may be slower or faster; measuring
# both decides it rather than guessing. Only netsh drives the batches; the
# cmdlet is sampled once, for comparison.
function Add-ByNetsh($index, $address, $netmask) {
    $out = & netsh interface ipv4 add address $index $address $netmask skipassource=true 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh: $out" }
}

function Next-Address($n) {
    # starts at 198.18.1.1, skips .0 and .255 in the last octet
    $third = 1 + [math]::Floor($n / 254)
    $fourth = 1 + ($n % 254)
    return "$Prefix.$third.$fourth"
}

$added = New-Object System.Collections.Generic.List[string]
$rounds = New-Object System.Collections.Generic.List[object]
$result = [ordered]@{}

try {
    # One address by the cmdlet, for comparison only.
    $probe = Next-Address 60000
    $cmdletMs = $null
    try {
        $elapsed = Measure-Command {
            New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $probe -PrefixLength 16 `
                -SkipAsSource $true -ErrorAction Stop | Out-Null
        }
        $cmdletMs = [math]::Round($elapsed.TotalMilliseconds, 1)
        $added.Add($probe)
    } catch {
        $cmdletMs = "failed: $($_.Exception.Message)"
    }

    $total = 0
    foreach ($batch in $Batches) {
        $times = New-Object System.Collections.Generic.List[double]
        $failed = 0
        $firstError = ""
        for ($i = 0; $i -lt $batch; $i++) {
            $address = Next-Address $total
            try {
                $elapsed = Measure-Command { Add-ByNetsh $ifIndex $address $Mask }
                $times.Add($elapsed.TotalMilliseconds)
                $added.Add($address)
            } catch {
                $failed++
                if (-not $firstError) { $firstError = $_.Exception.Message }
            }
            $total++
        }

        $sorted = @($times | Sort-Object)
        $median = $null
        $minimum = $null
        $maximum = $null
        if ($sorted.Count -gt 0) {
            $median = [math]::Round($sorted[[int][math]::Floor($sorted.Count / 2)], 1)
            $minimum = [math]::Round($sorted[0], 1)
            $maximum = [math]::Round($sorted[$sorted.Count - 1], 1)
        }
        $per = [ordered]@{}
        $per["median"] = $median
        $per["min"] = $minimum
        $per["max"] = $maximum

        $sum = ($times | Measure-Object -Sum).Sum
        if ($null -eq $sum) { $sum = 0 }

        $round = [ordered]@{}
        $round["addresses_after"] = $added.Count
        $round["batch"] = $batch
        $round["failed"] = $failed
        $round["per_address_ms"] = $per
        $round["batch_total_s"] = [math]::Round($sum / 1000, 2)
        $round["controls"] = Measure-Controls $ifIndex
        if ($firstError) { $round["first_error"] = $firstError }
        $rounds.Add($round)

        $note = ""
        if ($failed -gt 0) { $note = "  FAILED $failed" }
        Write-Host ("{0,6} addresses: {1,7} ms median, batch {2,7} s, enumerate {3,7} ms, bind {4,6} ms, resolve {5,7} ms{6}" -f
            $round["addresses_after"], $median, $round["batch_total_s"],
            $round["controls"]["enumerate_ms"], $round["controls"]["bind_ms"],
            $round["controls"]["resolve_ms"], $note)

        if ($failed -eq $batch) {
            Write-Host "every add in this batch failed - stopping here" -ForegroundColor Yellow
            break
        }
    }

    # Does skipassource actually hold? If it does not, outbound connections of
    # the guest could leave with a 198.18 source address, and approach A is not
    # usable as designed.
    $ours = @(Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -like "$Prefix.*" })
    $notSkipped = @($ours | Where-Object { -not $_.SkipAsSource })

    # And does the real address still win as the source? Asking the routing
    # table which source it would choose for a public destination is the
    # cheapest honest check, and needs no traffic.
    $chosen = "unknown"
    try {
        $found = @(Find-NetRoute -RemoteIPAddress "9.9.9.9" -ErrorAction Stop |
            Where-Object { $_.IPAddress } | Select-Object -First 1)
        if ($found.Count -gt 0) { $chosen = $found[0].IPAddress }
    } catch {
        $chosen = "unknown: $($_.Exception.Message)"
    }

    $result["adapter"] = $adapter.Name
    $result["real_address"] = @($real | ForEach-Object { $_.IPAddress })
    $result["add_by_cmdlet_ms"] = $cmdletMs
    $result["rounds"] = $rounds
    $result["addresses_carried"] = $added.Count
    $result["skipassource_honoured"] = ($notSkipped.Count -eq 0)
    $result["addresses_without_skipassource"] = $notSkipped.Count
    $result["source_address_for_public_destination"] = $chosen
}
finally {
    Write-Host ""
    Write-Host "removing $($added.Count) address(es)"
    $removeStart = Get-Date
    $removeFailed = 0
    foreach ($address in $added) {
        & netsh interface ipv4 delete address $ifIndex $address 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $removeFailed++ }
    }
    $left = @(Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like "$Prefix.*" })
    $result["remove_total_s"] = [math]::Round(((Get-Date) - $removeStart).TotalSeconds, 2)
    $result["remove_failed"] = $removeFailed
    $result["addresses_left_behind"] = $left.Count
    Write-Host "removal took $($result["remove_total_s"]) s, $($left.Count) left behind"
    if ($left.Count -gt 0) {
        Write-Host "LEFTOVERS - remove them with:" -ForegroundColor Yellow
        foreach ($l in $left) {
            Write-Host "  netsh interface ipv4 delete address $ifIndex $($l.IPAddress)"
        }
    }
    Write-Host ""
    Write-Host "----- paste this back -----"
    $result | ConvertTo-Json -Depth 6
}
