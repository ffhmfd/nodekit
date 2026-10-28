param(
    [ValidateSet('probe','sync','run','fetch','format','clean')][string]$Action = 'run',
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][string]$User,
    [Parameter(Mandatory=$true)][string]$Key,
    [int]$Port = 22,
    [string]$RemoteDir = '/var/tmp/nodekit-build-20261027',
    [string]$Command = '',
    [ValidateSet('go.mod','go.sum')][string]$File = 'go.sum'
)
$ErrorActionPreference = 'Stop'
if ($RemoteDir -notmatch '^/var/tmp/nodekit-build-[a-zA-Z0-9-]+$') { throw 'Invalid private build directory' }
$tempBase = [System.IO.Path]::GetTempPath()
if (Test-Path -LiteralPath (Join-Path $tempBase 'opencode')) { $tempBase = Join-Path $tempBase 'opencode' }
$temp = Join-Path $tempBase ('nodekit-' + [guid]::NewGuid().ToString('N'))
$root = Split-Path $PSScriptRoot -Parent
try {
    New-Item -ItemType Directory -Path $temp | Out-Null
    $acl = Get-Acl -LiteralPath $temp
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $temp -AclObject $acl
    $copy = Join-Path $temp 'ssh.key'
    Copy-Item -LiteralPath $Key -Destination $copy
    $sshArgs = @('-i',$copy,'-p',"$Port",'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=15',"$User@$HostName")
    function Invoke-Remote([string]$Script) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Script.Replace("`r",''))
        $encoded = [Convert]::ToBase64String($bytes)
        $encoded | & ssh @sshArgs 'base64 --decode --ignore-garbage | bash'
        if ($LASTEXITCODE -ne 0) { throw "Remote command exited $LASTEXITCODE" }
    }
    if ($Action -eq 'probe') {
        Invoke-Remote "set -e`nuname -m`ncommand -v go || true`ncommand -v git || true`ncommand -v python3 || true`ncommand -v openssl || true`nsudo -n true`nss -lntu`nsudo -n iptables -S INPUT`n"
    } elseif ($Action -eq 'sync') {
        Invoke-Remote "set -e`nif [ -e '$RemoteDir' ] && [ ! -f '$RemoteDir/.nodekit-build' ]; then exit 73; fi`numask 077`nmkdir -p '$RemoteDir/src'`ntouch '$RemoteDir/.nodekit-build'`n"
        $archive = Join-Path $temp 'source.tar'
        & tar -cf $archive --exclude=.git --exclude=.superpowers --exclude=.worktrees --exclude=dist --exclude=build --exclude=nodekit.local.json -C $root .
        if ($LASTEXITCODE -ne 0) { throw 'Source archive failed' }
        & scp -q -i $copy -P $Port -o BatchMode=yes -o StrictHostKeyChecking=yes $archive "${User}@${HostName}:$RemoteDir/source.tar"
        if ($LASTEXITCODE -ne 0) { throw 'Upload failed' }
        Invoke-Remote "set -e`ntar -xf '$RemoteDir/source.tar' -C '$RemoteDir/src'`nrm '$RemoteDir/source.tar'`n"
    } elseif ($Action -eq 'format') {
        Invoke-Remote "set -e`ncd '$RemoteDir/src'`nfind . -name '*.go' -exec `"`$(go env GOROOT)/bin/gofmt`" -w {} +`nfind . -name '*.go' -print0 | tar --null -T - -cf '$RemoteDir/formatted.tar'`n"
        $archive = Join-Path $temp 'formatted.tar'
        & scp -q -i $copy -P $Port -o BatchMode=yes -o StrictHostKeyChecking=yes "${User}@${HostName}:$RemoteDir/formatted.tar" $archive
        if ($LASTEXITCODE -ne 0) { throw 'Formatted sources download failed' }
        & tar -xf $archive -C $root
        if ($LASTEXITCODE -ne 0) { throw 'Formatted sources extraction failed' }
        Invoke-Remote "rm '$RemoteDir/formatted.tar'"
    } elseif ($Action -eq 'fetch') {
        & scp -q -i $copy -P $Port -o BatchMode=yes -o StrictHostKeyChecking=yes "${User}@${HostName}:$RemoteDir/src/$File" (Join-Path $root $File)
        if ($LASTEXITCODE -ne 0) { throw 'Generated dependency file download failed' }
    } elseif ($Action -eq 'clean') {
        Invoke-Remote "set -e`ntest -f '$RemoteDir/.nodekit-build'`nfind '$RemoteDir' -type d -exec chmod u+w {} +`nrm -rf -- '$RemoteDir'`n"
    } else {
        Invoke-Remote $Command
    }
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
