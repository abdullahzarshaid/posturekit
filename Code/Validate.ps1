#requires -Version 5.1
<# Parses package PowerShell files WITHOUT executing their contents. Also parses JSON.
This is a syntax gate, not proof of cmdlet availability, permissions or Windows behaviour. #>
[CmdletBinding()]
param([string]$Directory,[string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
# $PSScriptRoot is EMPTY inside a param() default under Windows PowerShell 5.1 when the
# script is invoked with powershell.exe -File. Resolve it in the body instead, so the
# non-interactive execution path used by ConfigMgr/Intune/GPO/scheduled tasks works.
if (-not $Directory) { $Directory = $PSScriptRoot }
if (-not $Directory) { $Directory = Split-Path -Parent $PSCommandPath }
if (-not $Directory) { throw 'Unable to determine the package directory. Pass -Directory explicitly.' }
if ($OutputPath -and (Test-Path -LiteralPath $OutputPath)) { throw 'Choose a new validation output file.' }
$rows=New-Object 'System.Collections.Generic.List[object]'
$failed=$false
$scanDirs=@((Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path)
$parent=Split-Path -Parent $scanDirs[0]
$extensions=Join-Path $parent 'Extensions'
if (Test-Path -LiteralPath $extensions -PathType Container) { $scanDirs += (Resolve-Path -LiteralPath $extensions).Path }
$psFiles=@($scanDirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter '*.ps1' -File } | Sort-Object FullName)
foreach ($file in $psFiles) {
    $tokens=$null; $parseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    $details=@($parseErrors | ForEach-Object { 'Line {0}: {1}' -f $_.Extent.StartLineNumber,$_.Message })
    $ok=($details.Count -eq 0)
    if (-not $ok) { $failed=$true }
    [void]$rows.Add([pscustomobject]@{file=$file.FullName;kind='PowerShell syntax';passed=$ok;details=$details})
}
foreach ($file in (Get-ChildItem -LiteralPath $Directory -Filter '*.json' -File | Sort-Object Name)) {
    $ok=$true; $details=@()
    try { $null=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { $ok=$false;$failed=$true;$details=@($_.Exception.Message) }
    [void]$rows.Add([pscustomobject]@{file=$file.Name;kind='JSON syntax';passed=$ok;details=$details})
}
$report=[ordered]@{evidence_kind='SyntaxValidation';timestamp_utc=[DateTime]::UtcNow.ToString('o');
    engine=$PSVersionTable.PSVersion.ToString();edition=$PSVersionTable.PSEdition;os=$env:OS;
    passed=(-not $failed);checks=@($rows.ToArray());
    notice='No target collection executed. JSON syntax checking does not validate scope authorization or reject all duplicate-key cases.'}
if ($OutputPath) { $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
$rows | Format-Table file,kind,passed -AutoSize
if ($failed) { throw 'Syntax validation failed. Inspect the recorded details before any execution.' }
Write-Host 'Syntax gate passed on this engine. Windows runtime and scope validation are separate gates.'
