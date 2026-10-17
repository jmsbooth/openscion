#Requires -Version 7.4
<#
Native Windows NTFS, ACL, reparse-point and concurrency qualification.
Not GitHub CI. Disposable fixture only. Tests are expected to FAIL until
Windows DACL enforcement is implemented. Native Windows execution and an
independent security reviewer are required before merge approval.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$ArtifactDir = (Join-Path $env:TEMP ("openscion-native-qa-" + [guid]::NewGuid().ToString("N"))),
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
    }
}
function Invoke-Racing {
    param([string]$Name,[string[]]$Arguments,[int]$Count)
    $processes = @()
    for ($i=0; $i -lt $Count; $i++) {
        $info = [Diagnostics.ProcessStartInfo]::new($Bin)
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        foreach($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
        $processes += [Diagnostics.Process]::Start($info)
    }
    $outcomes = @()
    foreach ($p in $processes) {
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        if (-not $p.WaitForExit(30000)) { $p.Kill($true); throw 'Concurrent process timed out' }
        $outcomes += [pscustomobject]@{ ExitCode=$p.ExitCode; Stdout=$stdout; Stderr=$stderr }
        $p.Dispose()
    }
    $outcomes | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $Artifacts ($Name+'.json'))
    return ,$outcomes
}
try {
    Invoke-Observed 'missing-repository' @('status','--json',$Fixture) 4 'E_NOT_INITIALIZED' | Out-Null
    Invoke-Observed 'initialize' @('init','--json',$Fixture) 0 | Out-Null
    Save-ACL $Meta 'initialized-metadata'
    Save-ACL (Join-Path $Meta 'format') 'initialized-marker'
    Invoke-Observed 'inspect' @('status','--json',$Fixture) 0 | Out-Null
    $put = Invoke-Observed 'blob-put' @('blob','put','--json',$Fixture,'src/main.rs') 0
    $blob = [string](($put.Text | ConvertFrom-Json).id)
    if ($blob -notmatch '^b1_[0-9a-f]{64}$') { throw 'Invalid object ID' }
    $digest = $blob.Substring(3)
    $blobPath = Join-Path $Meta ('objects\b1\' + $digest.Substring(0,2) + '\' + $digest)
    Save-ACL $blobPath 'initialized-blob'
    Invoke-Observed 'blob-verify' @('blob','verify','--json',$Fixture,$blob) 0 | Out-Null
    $manifest = 'src/main.rs' + [char]9 + $blob + [char]9 + '0' + [char]10
    [IO.File]::WriteAllBytes((Join-Path $Fixture 'manifest.tsv'),[Text.Encoding]::UTF8.GetBytes($manifest))
    $snapshotResult = Invoke-Observed 'snapshot-put' @('snapshot','put','--json',$Fixture,'manifest.tsv') 0
    $snapshot = [string](($snapshotResult.Text | ConvertFrom-Json).id)
    Invoke-Observed 'snapshot-show' @('snapshot','show','--json',$Fixture,$snapshot) 0 | Out-Null
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
    # RED security cases: source review found Unix-only permission checks.
    Test-DACL 'metadata-everyone-modify' $Meta @('status','--json',$Fixture) 6 'E_INVALID_STORE'
    Test-DACL 'marker-everyone-modify' (Join-Path $Meta 'format') @('status','--json',$Fixture) 6 'E_INVALID_STORE'
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
