$cred = New-Object PSCredential('vagrant', (ConvertTo-SecureString 'vagrant' -AsPlainText -Force))
$result = Invoke-Command -ComputerName 172.17.251.7 -Credential $cred -ScriptBlock {
    # Check if VS installer is still running
    $installer = Get-Process -Name "vs_installer*","vs_setup*","setup" -ErrorAction SilentlyContinue
    if ($installer) {
        Write-Output "VS Installer still running: $($installer.Name -join ', ')"
    } else {
        Write-Output "No VS installer processes running"
    }
    
    # Check if MSBuild exists now
    $paths = @(
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { Write-Output "MSBUILD_FOUND: $p"; return }
    }
    Write-Output "MSBUILD: NOT_FOUND"
    
    # Check choco install log
    $chocoLog = Get-Content "C:\ProgramData\chocolatey\logs\chocolatey.log" -Tail 20 -ErrorAction SilentlyContinue
    if ($chocoLog) {
        Write-Output "=== Last 20 lines of choco log ==="
        $chocoLog | ForEach-Object { Write-Output $_ }
    }
}
$result | ForEach-Object { Write-Host $_ }
