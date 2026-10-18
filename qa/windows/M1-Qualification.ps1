#Requires -Version 7.4
<#
Native Windows NTFS, ACL, reparse-point and concurrency qualification.
Not GitHub CI. Disposable fixture only. The protected-DACL implementation is
present but NOT release-qualified until these native checks run. Native Windows execution and an
independent security reviewer are required before merge approval.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$ArtifactDir = (Join-Path ([IO.Path]::GetTempPath()) ("openscion-native-qa-" + [guid]::NewGuid().ToString("N"))),
    [ValidateRange(2,32)][int]$Contenders = 20
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows) { throw 'NOT_RUN: native Windows is required; Wine and cross-compilation do not qualify NTFS' }
$Bin = (Resolve-Path -LiteralPath $Binary).Path
$Artifacts = [IO.Path]::GetFullPath($ArtifactDir)
[IO.Directory]::CreateDirectory($Artifacts) | Out-Null
$Drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Artifacts))
if ($Drive.DriveFormat -ne 'NTFS') { throw "NOT_RUN: NTFS required; found $($Drive.DriveFormat)" }
$script:Results = [Collections.Generic.List[object]]::new()
$script:Failures = [Collections.Generic.List[string]]::new()
$Fixture = Join-Path $Artifacts 'fixture'
New-Item -ItemType Directory -Path $Fixture | Out-Null
New-Item -ItemType Directory -Path (Join-Path $Fixture 'src') | Out-Null
$Source = Join-Path $Fixture 'src\main.rs'
[IO.File]::WriteAllBytes($Source,[Text.Encoding]::UTF8.GetBytes("fn main() {}" + [char]10))
$Meta = Join-Path $Fixture '.openscion'

function Invoke-Observed {
    param([string]$Name,[string[]]$Arguments,[int]$Expect,[string]$Code = '')
    if ($Name -notmatch '^[a-z0-9-]+$') { throw 'Invalid artifact name' }
    $stdout = Join-Path $Artifacts ($Name + '.stdout')
    $stderr = Join-Path $Artifacts ($Name + '.stderr')
    & $Bin @Arguments 1> $stdout 2> $stderr
    $rc = $LASTEXITCODE
    $txt = Get-Content -LiteralPath $stdout -Raw
    $actualCode = ''
    try {
        $response = $txt | ConvertFrom-Json -ErrorAction Stop
        if ($response.PSObject.Properties['code']) { $actualCode = [string]$response.code }
    } catch { $actualCode = '<invalid-json>' }
    $pass = ($rc -eq $Expect -and (($Code -eq '') -or ($actualCode -eq $Code)))
    $script:Results.Add([pscustomobject]@{
        Name=$Name; ActualExit=$rc; ExpectedExit=$Expect
        ActualCode=$actualCode; ExpectedCode=$Code; Result=$(if($pass){'PASS'}else{'FAIL'})
        StdoutSHA256=(Get-FileHash -Algorithm SHA256 -LiteralPath $stdout).Hash
        StderrSHA256=(Get-FileHash -Algorithm SHA256 -LiteralPath $stderr).Hash
    })
    Write-Host ("{0} {1}: rc={2}, expected={3}, code={4}" -f $(if($pass){'PASS'}else{'FAIL'}),$Name,$rc,$Expect,$actualCode)
    if (-not $pass) { $script:Failures.Add($Name) }
    return [pscustomobject]@{ Pass=$pass; Text=$txt; ExitCode=$rc; Code=$actualCode }
}
function Save-ACL {
    param([string]$Path,[string]$Name)
    Get-Acl -LiteralPath $Path | Format-List * | Out-File -LiteralPath (Join-Path $Artifacts ($Name+'.acl.txt'))
    & icacls.exe $Path 1> (Join-Path $Artifacts ($Name+'.icacls.stdout')) 2> (Join-Path $Artifacts ($Name+'.icacls.stderr'))
}
function Assert-PrivateDACL {
    param([string]$Name, [string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $expected = @($user, 'S-1-5-18', 'S-1-5-32-544')
    $isDirectory = (Get-Item -LiteralPath $Path -Force).PSIsContainer
    $flags = if ($isDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ok = $acl.AreAccessRulesProtected -and ($owner -eq $user) -and ($rules.Count -eq 3)
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        $ok = $ok -and ($sid -in $expected) -and $seen.Add($sid)
        $ok = $ok -and (-not $rule.IsInherited)
        $ok = $ok -and ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
        $ok = $ok -and ([int]$rule.FileSystemRights -eq 0x001f01ff)
        $ok = $ok -and ($rule.InheritanceFlags -eq $flags)
        $ok = $ok -and ($rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None)
    }
    $ok = $ok -and ($seen.Count -eq 3)
    $script:Results.Add([pscustomobject]@{
        Name=$Name; Result=$(if($ok){'PASS'}else{'FAIL'})
        Expected='owner+SYSTEM+Administrators protected, explicit and full-control only'
        ActualOwner=$owner; Protected=$acl.AreAccessRulesProtected; AceCount=$rules.Count
    })
    Write-Host ("{0} {1}: protected={2}, aceCount={3}, owner={4}" -f $(if($ok){'PASS'}else{'FAIL'}), $Name, $acl.AreAccessRulesProtected, $rules.Count, $owner)
    if (-not $ok) { $script:Failures.Add($Name) }
}

function Test-DACL {
    param([string]$Name,[string]$Path,[string[]]$Arguments,[int]$ExpectedExit,[string]$ExpectedCode)
    $original = Get-Acl -LiteralPath $Path
    try {
        $modified = Get-Acl -LiteralPath $Path
        $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        # Modify only this fixture path; never propagate a test ACE to children.
        $inherit = [Security.AccessControl.InheritanceFlags]::None
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $everyone,[Security.AccessControl.FileSystemRights]::Modify,
            $inherit,[Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $modified.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $modified
        Save-ACL $Path ($Name+'-tainted')
        Invoke-Observed $Name $Arguments $ExpectedExit $ExpectedCode | Out-Null
    } finally {
        Set-Acl -LiteralPath $Path -AclObject $original
        Save-ACL $Path ($Name+'-restored')
        Assert-PrivateDACL ($Name+'-restored') $Path
    }
}
function Invoke-Racing {
    param([string]$Name,[string[]]$Arguments,[int]$Count)
    # Drain stdout and stderr asynchronously before waiting. Synchronous
    # ReadToEnd can block forever if a child hangs or fills the other pipe.
    $processes = @()
    $outcomes = @()
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    try {
        for ($i=0; $i -lt $Count; $i++) {
            $info = [Diagnostics.ProcessStartInfo]::new($Bin)
            $info.UseShellExecute = $false
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
            $p = [Diagnostics.Process]::Start($info)
            if ($null -eq $p) { throw 'Concurrent process failed to start' }
            $processes += [pscustomobject]@{
                Process=$p
                StdoutTask=$p.StandardOutput.ReadToEndAsync()
                StderrTask=$p.StandardError.ReadToEndAsync()
            }
        }
        # One deadline for the entire operation, not Count times 30 seconds.
        foreach ($entry in $processes) {
            $p = $entry.Process
            $remaining = [int][Math]::Max(0, [Math]::Ceiling(30000 - $deadline.Elapsed.TotalMilliseconds))
            if (-not $p.WaitForExit($remaining)) {
                throw "Concurrent process exceeded 30-second global deadline (PID=$($p.Id))"
            }
            $stdout = $entry.StdoutTask.GetAwaiter().GetResult()
            $stderr = $entry.StderrTask.GetAwaiter().GetResult()
            if ($stdout.Length -gt 1048576 -or $stderr.Length -gt 1048576) {
                throw "Concurrent process output exceeded 1 MiB per stream (PID=$($p.Id))"
            }
            $outcomes += [pscustomobject]@{
                ExitCode=$p.ExitCode; Stdout=$stdout; Stderr=$stderr; Pid=$p.Id
            }
        }
    } finally {
        foreach ($entry in $processes) {
            $p = $entry.Process
            try {
                if (-not $p.HasExited) {
                    $p.Kill($true)
                    [void]$p.WaitForExit(5000)
                }
            } catch {
                $script:Failures.Add('concurrent-process-cleanup')
            } finally {
                $p.Dispose()
            }
        }
        # Preserve successful child observations even when another child times out.
        @($outcomes) | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $Artifacts ($Name+'.json'))
    }
    return ,$outcomes
}
try {
    Invoke-Observed 'missing-repository' @('status','--json',$Fixture) 4 'E_NOT_INITIALIZED' | Out-Null
    Invoke-Observed 'initialize' @('init','--json',$Fixture) 0 | Out-Null
    Save-ACL $Meta 'initialized-metadata'
    Assert-PrivateDACL 'metadata-private-on-create' $Meta
    Save-ACL (Join-Path $Meta 'format') 'initialized-marker'
    Assert-PrivateDACL 'marker-private-on-create' (Join-Path $Meta 'format')
    Invoke-Observed 'inspect' @('status','--json',$Fixture) 0 | Out-Null
    $put = Invoke-Observed 'blob-put' @('blob','put','--json',$Fixture,'src/main.rs') 0
    $blob = [string](($put.Text | ConvertFrom-Json).id)
    if ($blob -notmatch '^b1_[0-9a-f]{64}$') { throw 'Invalid object ID' }
    $digest = $blob.Substring(3)
    $blobPath = Join-Path $Meta ('objects\b1\' + $digest.Substring(0,2) + '\' + $digest)
    Save-ACL $blobPath 'initialized-blob'
    Assert-PrivateDACL 'blob-private-on-create' $blobPath
    Assert-PrivateDACL 'cas-kind-private-on-create' (Join-Path $Meta 'objects\\b1')
    Invoke-Observed 'blob-verify' @('blob','verify','--json',$Fixture,$blob) 0 | Out-Null
    $manifest = 'src/main.rs' + [char]9 + $blob + [char]9 + '0' + [char]10
    [IO.File]::WriteAllBytes((Join-Path $Fixture 'manifest.tsv'),[Text.Encoding]::UTF8.GetBytes($manifest))
    $snapshotResult = Invoke-Observed 'snapshot-put' @('snapshot','put','--json',$Fixture,'manifest.tsv') 0
    $snapshot = [string](($snapshotResult.Text | ConvertFrom-Json).id)
    Invoke-Observed 'snapshot-show' @('snapshot','show','--json',$Fixture,$snapshot) 0 | Out-Null
    # The canonical path contract must hold on case-insensitive NTFS.
    $colliding = 'src/main.rs' + [char]9 + $blob + [char]9 + '0' + [char]10 +
                 'src/Main.rs' + [char]9 + $blob + [char]9 + '0' + [char]10
    [IO.File]::WriteAllBytes((Join-Path $Fixture 'case-collision.tsv'), [Text.Encoding]::UTF8.GetBytes($colliding))
    Invoke-Observed 'casefold-collision-denied' @('snapshot','put','--json',$Fixture,'case-collision.tsv') 8 'E_SNAPSHOT_INVALID' | Out-Null
    $reserved = 'src/CON.txt' + [char]9 + $blob + [char]9 + '0' + [char]10
    [IO.File]::WriteAllBytes((Join-Path $Fixture 'reserved-name.tsv'), [Text.Encoding]::UTF8.GetBytes($reserved))
    Invoke-Observed 'reserved-device-name-denied' @('snapshot','put','--json',$Fixture,'reserved-name.tsv') 3 'E_UNSAFE_PATH' | Out-Null
    $Destination = Join-Path $Fixture 'checkout'
    Invoke-Observed 'materialize' @('snapshot','materialize','--json',$Fixture,$snapshot,$Destination) 0 | Out-Null
    $a = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash
    $b = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Destination 'src\main.rs')).Hash
    if ($a -ne $b) { $script:Failures.Add('snapshot-content-mismatch') }
    Invoke-Observed 'checkout-no-overwrite' @('snapshot','materialize','--json',$Fixture,$snapshot,$Destination) 5 'E_ALREADY_EXISTS' | Out-Null
    Invoke-Observed 'parent-traversal' @('blob','put','--json',$Fixture,'../escape') 3 'E_UNSAFE_PATH' | Out-Null
    try {
        $junction = Join-Path $Artifacts 'repository-junction'
        New-Item -ItemType Junction -Path $junction -Target $Fixture -ErrorAction Stop | Out-Null
        Invoke-Observed 'junction-denial' @('status','--json',$junction) 3 'E_UNSAFE_PATH' | Out-Null
    } catch {
        $script:Failures.Add('junction-not-verified')
        Write-Host "NOT_RUN junction validation: $_"
    }
    # Negative security cases: added rights must be rejected without auto-repair.
    Test-DACL 'metadata-everyone-modify' $Meta @('status','--json',$Fixture) 6 'E_INVALID_STORE'
    Test-DACL 'marker-everyone-modify' (Join-Path $Meta 'format') @('status','--json',$Fixture) 6 'E_INVALID_STORE'
    Test-DACL 'cas-root-everyone-modify' (Join-Path $Meta 'objects') @('blob','verify','--json',$Fixture,$blob) 3 'E_UNSAFE_PATH'
    Test-DACL 'cas-shard-everyone-modify' (Split-Path -Parent $blobPath) @('blob','verify','--json',$Fixture,$blob) 3 'E_UNSAFE_PATH'
    Test-DACL 'blob-everyone-modify' $blobPath @('blob','verify','--json',$Fixture,$blob) 3 'E_UNSAFE_PATH'
    $race = Join-Path $Fixture 'race-checkout'
    $outcomes = Invoke-Racing 'checkout-20-contenders' @('snapshot','materialize','--json',$Fixture,$snapshot,$race) $Contenders
    $won = @($outcomes | Where-Object ExitCode -eq 0).Count
    $rejected = @($outcomes | Where-Object {
        $_.ExitCode -eq 5 -and ($_.Stdout | ConvertFrom-Json).code -eq 'E_ALREADY_EXISTS'
    }).Count
    if ($won -ne 1 -or $rejected -ne ($Contenders-1)) { $script:Failures.Add('checkout-concurrency-invariant') }
} catch {
    $script:Failures.Add('unexpected-exception')
    Write-Host "FAIL unexpected qualification error: $_"
} finally {
    $head = 'UNKNOWN'
    try { $head = (& git rev-parse HEAD 2>$null).Trim() } catch {}
    $summary = [ordered]@{
        Protocol='openscion.qa.windows-native.v1'
        System=[Environment]::OSVersion.VersionString
        DriveFormat=$Drive.DriveFormat; GitHead=$head
        BinarySHA256=(Get-FileHash -Algorithm SHA256 -LiteralPath $Bin).Hash
        Cases=$script:Results; Failures=$script:Failures
        Important='No Windows process-kill or power-loss claims; independent security review still required'
    }
    $summary | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $Artifacts 'summary.json')
    Write-Host ("Evidence: "+$Artifacts+"; failures="+$script:Failures.Count)
}
if ($script:Failures.Count -gt 0) { exit 1 }
exit 0
