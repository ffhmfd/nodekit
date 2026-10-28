param(
    [Parameter(Mandatory=$true)][string]$OneHost,
    [Parameter(Mandatory=$true)][string]$OneKey,
    [Parameter(Mandatory=$true)][string]$TwoHost,
    [Parameter(Mandatory=$true)][string]$TwoKey,
    [string]$OneUser='root', [int]$OnePort=22,
    [string]$TwoUser='ubuntu', [int]$TwoPort=22,
    [switch]$Reverse,[switch]$SystemLifecycle,[switch]$Cloudflare,
    [string]$Build='/var/tmp/nodekit-build-public',[string]$Version='v0.2.0',
    [string]$LegacyArchive=''
)
$ErrorActionPreference = 'Stop'
if ($Build -notmatch '^/var/tmp/nodekit-build-[a-zA-Z0-9-]+$' -or $Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Invalid build/version' }
$mode = if ($Cloudflare) { 'cloudflare' } else { 'direct' }
foreach ($address in @($OneHost,$TwoHost)) { $ip=$null; if (-not [System.Net.IPAddress]::TryParse($address,[ref]$ip) -or $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'Cross-test hosts must be IPv4 addresses' } }
foreach ($login in @($OneUser,$TwoUser)) { if ($login -notmatch '^[a-z_][a-z0-9_-]*$') { throw 'Invalid SSH username' } }
if ($LegacyArchive -and $LegacyArchive -notmatch '^/[a-zA-Z0-9/_.,-]+$') { throw 'Invalid legacy archive path' }
$tempBase = [System.IO.Path]::GetTempPath()
if (Test-Path -LiteralPath (Join-Path $tempBase 'opencode')) { $tempBase = Join-Path $tempBase 'opencode' }
$temp = Join-Path $tempBase ('nodekit-cross-' + [guid]::NewGuid().ToString('N'))
$serverStarted = $false
try {
    New-Item -ItemType Directory -Path $temp | Out-Null
    $acl = Get-Acl -LiteralPath $temp
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $temp -AclObject $acl
    Copy-Item -LiteralPath $OneKey -Destination (Join-Path $temp 'one.key')
    Copy-Item -LiteralPath $TwoKey -Destination (Join-Path $temp 'two.key')
    $one = @{ HostName=$OneHost; User=$OneUser; Port=$OnePort; Key=(Join-Path $temp 'one.key'); Test='integration-amd64.test'; Sudo=$(if ($OneUser -eq 'root') {''} else {'sudo -n '}) }
    $two = @{ HostName=$TwoHost; User=$TwoUser; Port=$TwoPort; Key=(Join-Path $temp 'two.key'); Test='integration-arm64.test'; Sudo=$(if ($TwoUser -eq 'root') {''} else {'sudo -n '}) }
    function Remote($hostInfo,[string]$command) {
        $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command.Replace("`r",'')))
        & ssh -i $hostInfo.Key -p $hostInfo.Port -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 "$($hostInfo.User)@$($hostInfo.HostName)" "printf %s '$base64' | base64 -d | bash"
        if ($LASTEXITCODE -ne 0) { throw "Remote test failed ($($hostInfo.HostName)): $LASTEXITCODE" }
    }
    function CopyFrom($hostInfo,[string]$remote,[string]$local) {
        & scp -q -i $hostInfo.Key -P $hostInfo.Port -o BatchMode=yes -o StrictHostKeyChecking=yes "$($hostInfo.User)@$($hostInfo.HostName):$remote" $local
        if ($LASTEXITCODE -ne 0) { throw 'Test file download failed' }
    }
    function CopyTo($hostInfo,[string]$local,[string]$remote) {
        & scp -q -i $hostInfo.Key -P $hostInfo.Port -o BatchMode=yes -o StrictHostKeyChecking=yes $local "$($hostInfo.User)@$($hostInfo.HostName):$remote"
        if ($LASTEXITCODE -ne 0) { throw 'Test file upload failed' }
    }
    $prepare = @'
set -e
root=BUILD_ROOT
if [ -d "$root" ] && [ ! -f "$root/.nodekit-build" ]; then exit 73; fi
umask 077
mkdir -p "$root/bin"
touch "$root/.nodekit-build"
if [ ! -x "$root/bin/mihomo" ]; then
curl -fLsS --retry 2 https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1-v1.19.33.gz -o "$root/core.gz"
printf '%s  %s\n' 8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524 "$root/core.gz" | sha256sum -c -
gzip -dc "$root/core.gz" > "$root/bin/mihomo"
chmod 700 "$root/bin/mihomo"
rm "$root/core.gz"
fi
'@
    Remote $one $prepare.Replace('BUILD_ROOT',$build)
    CopyFrom $two "$build/bin/integration-amd64.test" (Join-Path $temp 'integration.test')
    CopyTo $one (Join-Path $temp 'integration.test') "$build/bin/integration-amd64.test"
    Remote $one "chmod 700 '$build/bin/integration-amd64.test'"
    if ($SystemLifecycle) {
        Remote $one "test ! -e /opt/nodekit && test ! -e /etc/nodekit && test ! -e /var/lib/nodekit"
        try {
            CopyFrom $two "$build/dist/nodekit-$Version-linux-amd64.tar.gz" (Join-Path $temp 'release.tar.gz')
            CopyTo $one (Join-Path $temp 'release.tar.gz') "$build/release.tar.gz"
            CopyTo $one (Join-Path (Split-Path $PSScriptRoot -Parent) 'install.sh') "$build/install.sh"
            if ($Cloudflare) {
                if (-not $LegacyArchive) { throw 'Cloudflare lifecycle test requires -LegacyArchive on the build host' }
                CopyFrom $two $LegacyArchive (Join-Path $temp 'legacy.tar.gz')
                CopyTo $one (Join-Path $temp 'legacy.tar.gz') "$build/legacy.tar.gz"
            }
            Remote $one "NODEKIT_SYSTEM_MODE=$mode NODEKIT_LEGACY_ARCHIVE=$build/legacy.tar.gz NODEKIT_SYSTEM_TEST=1 NODEKIT_INSTALL_SCRIPT=$build/install.sh NODEKIT_RELEASE_ARCHIVE=$build/release.tar.gz $build/bin/integration-amd64.test -test.run TestSystemLifecycle -test.v"
        } finally {
            Remote $one "rm -f '$build/release.tar.gz' '$build/install.sh' '$build/legacy.tar.gz'"
        }
        return
    }
    if ($Reverse) { $server=$two; $client=$one } else { $server=$one; $client=$two }
    Remote $server "set -e`ntest ! -e '$build/cross.json'`nrm -f '$build/cross.status' '$build/cross.json.stop'`nnohup bash -c 'NODEKIT_CROSS_MODE=$mode NODEKIT_CORE_BIN=$build/bin/mihomo NODEKIT_CROSS_EXPORT=$build/cross.json NODEKIT_CROSS_ADDRESS=$($server.HostName) $build/bin/$($server.Test) -test.run=TestCrossHostServer -test.v; echo `$? > $build/cross.status' > '$build/cross.log' 2>&1 < /dev/null &`necho `$! > '$build/cross.pid'`n"
    $serverStarted=$true
    Remote $server "for i in `$(seq 1 100); do if [ -s '$build/cross.json' ]; then exit 0; fi; if [ -f '$build/cross.status' ]; then cat '$build/cross.log'; exit 1; fi; sleep 0.1; done; exit 1"
    CopyFrom $server "$build/cross.json" (Join-Path $temp 'cross.json')
    $fixture=Get-Content -LiteralPath (Join-Path $temp 'cross.json') -Raw | ConvertFrom-Json
    $rules=@()
    foreach ($protocol in $fixture.Config.protocols) {
        $networks = switch ($protocol.type) { 'ss' { @('tcp','udp') }; 'tuic' { @('udp') }; 'hysteria2' { @('udp') }; default { @('tcp') } }
        foreach ($network in $networks) { $rules += "-s $($client.HostName) -p $network --dport $($protocol.port) -m comment --comment nodekit-cross-test -j ACCEPT" }
    }
    $ruleScript="set -e`n"
    foreach ($rule in $rules) { $ruleScript += "$($server.Sudo)iptables -I INPUT 1 $rule`n" }
    Remote $server $ruleScript
    CopyTo $client (Join-Path $temp 'cross.json') "$build/cross-import.json"
    Remote $client "NODEKIT_CORE_BIN=$build/bin/mihomo NODEKIT_CROSS_IMPORT=$build/cross-import.json $build/bin/$($client.Test) -test.run=TestCrossHostClient -test.v"
} finally {
    if ($serverStarted) {
        try {
            Remote $server "touch '$build/cross.json.stop'"
            $cleanup="set -e`n"
            foreach ($rule in $rules) { $cleanup += "if $($server.Sudo)iptables -C INPUT $rule 2>/dev/null; then $($server.Sudo)iptables -D INPUT $rule; fi`n" }
            $cleanup += "for i in `$(seq 1 100); do if [ -f '$build/cross.status' ]; then cat '$build/cross.log'; rm -f '$build/cross.pid' '$build/cross.status' '$build/cross.log'; exit 0; fi; sleep 0.1; done; exit 1`n"
            Remote $server $cleanup
            Remote $client "rm -f '$build/cross-import.json'"
        } catch { Write-Warning "Cross-test cleanup needs inspection: $_" }
    }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
