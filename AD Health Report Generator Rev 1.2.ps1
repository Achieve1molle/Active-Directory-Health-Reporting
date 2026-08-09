<#
.SYNOPSIS
Creates offline HTML reports from AD Health Raw Collector ZIP packages.
.REQUIRES
PowerShell 7 or later.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [string]$OutputDirectory = (Join-Path (Get-Location) ("AD-Health-Report-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or later is required.' }

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Read-JsonDocument {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
}

function ConvertTo-DisplayValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join ', ') }
    return [string]$Value
}

function New-HtmlTable {
    param(
        [AllowNull()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )
    $items = @($Rows | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { return '<div class="notice">No data was collected.</div>' }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('<table><thead><tr>')
    foreach ($columnName in $Columns) { [void]$builder.Append('<th>').Append((ConvertTo-HtmlEncoded $columnName)).Append('</th>') }
    [void]$builder.Append('</tr></thead><tbody>')
    foreach ($row in $items) {
        [void]$builder.Append('<tr>')
        foreach ($columnName in $Columns) {
            $property = $row.PSObject.Properties[$columnName]
            $value = if ($null -ne $property) { ConvertTo-DisplayValue $property.Value } else { '' }
            [void]$builder.Append('<td>').Append((ConvertTo-HtmlEncoded $value)).Append('</td>')
        }
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table>')
    return $builder.ToString()
}

function New-HtmlSection {
    param([string]$Title, [string]$Body)
    return "<section><h2>$(ConvertTo-HtmlEncoded $Title)</h2>$Body</section>"
}

function Get-RawText {
    param([string]$PackagePath,[string]$FileName)
    $path=Join-Path $PackagePath $FileName
    if(Test-Path -LiteralPath $path){return [string](Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue)}
    return ''
}
function New-Finding {
    param([string]$Scope,[string]$Category,[ValidateSet('Green','Yellow','Red')][string]$State,[string]$Title,[string]$Detail,[string]$Source)
    [pscustomobject]@{Scope=$Scope;Category=$Category;State=$State;Title=$Title;Detail=$Detail;Source=$Source}
}
function Get-WorstState {
    param([object[]]$Findings)
    if(@($Findings|Where-Object State -eq 'Red').Count -gt 0){return 'Red'}
    if(@($Findings|Where-Object State -eq 'Yellow').Count -gt 0){return 'Yellow'}
    return 'Green'
}
function Get-GradeFromState {
    param([string]$State)
    switch($State){'Green'{'A'};'Yellow'{'C'};'Red'{'F'};default{'Unknown'}}
}
function New-HealthBadge {
    param([string]$State,[string]$Text)
    return "<span class='health $($State.ToLowerInvariant())'>$(ConvertTo-HtmlEncoded $Text)</span>"
}
function Get-ChangeRecommendations {
    param(
        [string]$ForestState,
        [string]$ForestGrade,
        [bool]$AllDcReachable,
        [object[]]$AllFindings,
        [object[]]$DomainControllers,
        [object]$UpgradeAnalysis
    )
    $redCount=@($AllFindings|Where-Object State -eq 'Red').Count
    $yellowCount=@($AllFindings|Where-Object State -eq 'Yellow').Count
    $replicationRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'Replication' }).Count
    $dnsRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'DNS' }).Count
    $dcdiagRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'DCDiag' }).Count
    $sysvolRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'SYSVOL' }).Count
    $eventRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'Event Log' }).Count
    $healthyForChange=($ForestState -eq 'Green' -and $AllDcReachable -and $redCount -eq 0)
    $stableEnoughForLowRisk=($ForestState -ne 'Red' -and $AllDcReachable -and $replicationRed -eq 0 -and $dnsRed -eq 0 -and $sysvolRed -eq 0)
    $baseBlockers=@()
    if(!$AllDcReachable){$baseBlockers+='One or more domain controllers are not confirmed reachable'}
    if($replicationRed){$baseBlockers+="$replicationRed red replication finding(s)"}
    if($dnsRed){$baseBlockers+="$dnsRed red DNS finding(s)"}
    if($dcdiagRed){$baseBlockers+="$dcdiagRed red DCDiag finding(s)"}
    if($sysvolRed){$baseBlockers+="$sysvolRed red SYSVOL/DFSR finding(s)"}
    if($eventRed){$baseBlockers+="$eventRed red event-log finding(s)"}
    if(!$baseBlockers.Count -and $yellowCount){$baseBlockers+="$yellowCount yellow review finding(s)"}
    if(!$baseBlockers.Count){$baseBlockers+='No health blockers detected'}
    $commonReason=$baseBlockers -join '; '
    $domainAtHighest=([string]$UpgradeAnalysis.CurrentDomain -match [regex]::Escape([string]$UpgradeAnalysis.HighestEligibleDomain))
    $forestAtHighest=([string]$UpgradeAnalysis.CurrentForest -match [regex]::Escape([string]$UpgradeAnalysis.HighestEligibleForest))
    @(
        [pscustomobject]@{ProposedChange='Add a domain controller';Recommended=$stableEnoughForLowRisk;RequiredHealth='Green or Yellow with no red replication, DNS, or SYSVOL findings';Reason=if($stableEnoughForLowRisk){'Health baseline is adequate for a controlled DC addition. Complete normal pre-change validation and backups.'}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Migrate FSMO roles';Recommended=$healthyForChange;RequiredHealth='Green only; all DCs reachable; no red findings';Reason=if($healthyForChange){'Forest health is Green and all DCs are confirmed reachable.'}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Update forest functional level';Recommended=($healthyForChange -and !$forestAtHighest -and $UpgradeAnalysis.NoBlockers);RequiredHealth='Green only; no OS blockers; domain level already eligible';Reason=if($forestAtHighest){"No change required. Forest already uses the highest eligible level: $($UpgradeAnalysis.CurrentForest)."}elseif(!$UpgradeAnalysis.NoBlockers){(@($UpgradeAnalysis.Blockers.Title)-join '; ')}elseif($healthyForChange){"Eligible to raise toward $($UpgradeAnalysis.HighestEligibleForest) after formal change validation."}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Update domain functional level';Recommended=($healthyForChange -and !$domainAtHighest -and $UpgradeAnalysis.NoBlockers);RequiredHealth='Green only; all DCs support the target level';Reason=if($domainAtHighest){"No change required. Domain already uses the highest eligible level: $($UpgradeAnalysis.CurrentDomain)."}elseif(!$UpgradeAnalysis.NoBlockers){(@($UpgradeAnalysis.Blockers.Title)-join '; ')}elseif($healthyForChange){"Eligible to raise toward $($UpgradeAnalysis.HighestEligibleDomain) after formal change validation."}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Demote a domain controller';Recommended=$healthyForChange;RequiredHealth='Green only; all DCs reachable; replication, DNS, SYSVOL, and DCDiag healthy';Reason=if($healthyForChange){'Health baseline is Green. Confirm remaining DNS, GC, FSMO, and capacity coverage before demotion.'}else{$commonReason}}
    )
}
function Get-FunctionalLevelAnalysis {
    param([object[]]$DomainControllers,[string]$CurrentDomainMode,[string]$CurrentForestMode)
    $rows=@();$blockers=@();$all2025=$true;$all2016OrLater=$true
    foreach($dc in @($DomainControllers)){
        $os=[string]$dc.OperatingSystem;$eligible2025=$os -match '2025';$eligible2016=$os -match '2016|2019|2022|2025'
        if(!$eligible2025){$all2025=$false;$blockers+=New-Finding 'Forest/Domain' 'Functional Level' 'Yellow' "$($dc.HostName) blocks Windows Server 2025 functional level" "DC operating system is '$os'. Windows Server 2025 functional level requires every DC to run Windows Server 2025." 'domain-controllers.json'}
        if(!$eligible2016){$all2016OrLater=$false}
        $rows+=[pscustomobject]@{HostName=$dc.HostName;OperatingSystem=$os;EligibleFor2016=$eligible2016;EligibleFor2025=$eligible2025;Reason=if($eligible2025){'No blocker for Windows Server 2025 functional level'}elseif($eligible2016){'Supports Windows Server 2016 functional level, but not Windows Server 2025 functional level'}else{'Operating system is older than Windows Server 2016'}}
    }
    $highest=if($all2025){'Windows2025'}elseif($all2016OrLater){'Windows2016'}else{'Review legacy DC versions'}
    [pscustomobject]@{HighestEligibleDomain=$highest;HighestEligibleForest=$highest;CurrentDomain=$CurrentDomainMode;CurrentForest=$CurrentForestMode;Rows=$rows;Blockers=$blockers;NoBlockers=($blockers.Count -eq 0)}
}
function Get-NativeStandardOutput { param([string]$Text) if([string]::IsNullOrWhiteSpace($Text)){return ''};$m=[regex]::Match($Text,'(?s)===== STANDARD OUTPUT =====\s*(.*?)\s*===== STANDARD ERROR =====');if($m.Success){return $m.Groups[1].Value.Trim()};return $Text }
function Get-ConnectivityFindings {
 param([object[]]$Rows,[object[]]$ReturnRows,[string]$Scope)
 $f=@();$critical=@(53,88,135,389,445,464,3268);$blocked=@($Rows|Where-Object{$_.Port -in $critical -and $_.Open -ne $true})
 foreach($g in @($blocked|Group-Object Destination)){$ports=@($g.Group.Port|Sort-Object -Unique)-join ', ';$f+=New-Finding $g.Name 'Connectivity' 'Red' 'Required AD ports unavailable from collector' "Blocked or unreachable TCP ports: $ports. Validate firewall, routing, DNS, and service availability." 'forest-connectivity.json'}
 foreach($r in @($ReturnRows)){if($r.RemoteExecution -eq 'Unavailable'){$f+=New-Finding $r.Source 'Connectivity' 'Yellow' 'Reverse-path test unavailable' "Remote PowerShell could not test the return path to the collector: $($r.Error)" 'forest-return-path.json'}elseif($r.RemoteExecution -eq 'Success'){$bad=@($r.Results|Where-Object{$_.Port -in $critical -and $_.Open -ne $true});if($bad.Count){$f+=New-Finding $r.Source 'Connectivity' 'Red' 'Required AD ports unavailable toward collector' ("Blocked or unreachable TCP ports: "+(@($bad.Port|Sort-Object -Unique)-join ', ')) 'forest-return-path.json'}}}
 if(!$f.Count){$f+=New-Finding $Scope 'Connectivity' 'Green' 'AD connectivity checks passed' 'Required tested AD TCP ports were reachable for the available test perspectives.' 'forest-connectivity.json'};return $f
}
function Test-DcdiagText { param([string]$Text,[string]$Source,[string]$Scope) if([string]::IsNullOrWhiteSpace($Text)){return ,(New-Finding $Scope 'DCDiag' 'Yellow' 'DCDiag evidence missing' 'Expected evidence was unavailable.' $Source)};$o=Get-NativeStandardOutput $Text;$failed=@($o-split"`r?`n"|ForEach-Object{$_.Trim()}|Where-Object{$_-match'(?i)^\.{3,}\s+.+?\s+failed test\s+\S+'}|Sort-Object -Unique);if(!$failed.Count){return ,(New-Finding $Scope 'DCDiag' 'Green' 'DCDiag passed' 'No explicit failed-test result was found.' $Source)};$f=@();foreach($line in $failed){$test=if($line-match'(?i)failed test\s+(\S+)'){$Matches[1]}else{'Unknown'};$state=if($test-match'^(?i:DFSREvent|KccEvent|SystemLog|FrsEvent)$'){'Yellow'}else{'Red'};$f+=New-Finding $Scope 'DCDiag' $state "DCDiag test failed: $test" $line $Source};return $f }
function Test-RepadminText {
 param([string]$ShowRepl,[string]$Summary,[string]$Scope)
 $show=Get-NativeStandardOutput $ShowRepl;$sum=Get-NativeStandardOutput $Summary;if([string]::IsNullOrWhiteSpace($show)-and[string]::IsNullOrWhiteSpace($sum)){return ,(New-Finding $Scope 'Replication' 'Yellow' 'Replication evidence missing' 'Repadmin evidence unavailable.' 'repadmin')}
 $cols=@('RowType','Destination DSA Site','Destination DSA','Naming Context','Source DSA Site','Source DSA','Transport Type','Number of Failures','Last Failure Time','Last Success Time','Last Failure Status');$info=@($show-split"`r?`n"|Where-Object{$_-match'^showrepl_INFO,'});$rows=@();if($info.Count){try{$rows=@(($info-join"`r`n")|ConvertFrom-Csv -Header $cols)}catch{}}
 $fail=@($rows|Where-Object{[int]$_.'Number of Failures'-gt0 -or [int]$_.'Last Failure Status'-ne0});$queryErrors=@($show-split"`r?`n"|Where-Object{$_-match'^showrepl_ERROR,'}|Sort-Object -Unique)
 $f=@();foreach($r in $fail){$f+=New-Finding $r.'Destination DSA' 'Replication' 'Red' 'Replication relationship failure' "Source=$($r.'Source DSA'); NC=$($r.'Naming Context'); Failures=$($r.'Number of Failures'); Status=$($r.'Last Failure Status')" 'repadmin-showrepl-all.csv.txt'}
 if($queryErrors.Count){$names=@($queryErrors|ForEach-Object{($_-split',')[2]}|Sort-Object -Unique);$f+=New-Finding $Scope 'Replication' 'Yellow' 'Domain-wide replication query coverage incomplete' ("Repadmin could not retrieve status from {0} DC(s): {1}. Valid relationship rows are graded separately."-f $names.Count,($names-join', ')) 'repadmin-showrepl-all.csv.txt'}
 if(!$fail.Count -and $rows.Count){$f+=New-Finding $Scope 'Replication' 'Green' 'Retrieved replication relationships healthy' ("{0} relationship(s) evaluated with zero failures and status 0."-f $rows.Count) 'repadmin-showrepl-all.csv.txt'}elseif(!$f.Count){$f+=New-Finding $Scope 'Replication' 'Yellow' 'Replication output not fully parsed' 'No confirmed failure row was found, but complete structured results were unavailable.' 'repadmin'};return $f
}
function Test-DnsText {
    param([string]$Text,[string]$Scope,[string]$Source)
    if([string]::IsNullOrWhiteSpace($Text)){return ,(New-Finding $Scope 'DNS' 'Yellow' 'DNS diagnostic evidence missing' 'The DNS-specific DCDiag output was not available.' $Source)}
    $bad=@($Text -split "`r?`n"|Where-Object{$_ -match '(?i)\bfailed test\b|DNS test.*fail|error:' -and $_ -notmatch '(?i)0 errors|no errors'})
    if($bad.Count){return @($bad|Select-Object -First 50|ForEach-Object{New-Finding $Scope 'DNS' 'Red' 'DNS health failure' $_.Trim() $Source})}
    return ,(New-Finding $Scope 'DNS' 'Green' 'DNS diagnostics passed' 'No DNS failure signature was found in the captured DNS DCDiag output.' $Source)
}
function Get-SysvolAssessment {
    param($Local,[string]$PackagePath,[string]$Scope)
    $shares=@($Local.Shares);$sysvol=$shares|Where-Object Name -eq 'SYSVOL'|Select-Object -First 1;$netlogon=$shares|Where-Object Name -eq 'NETLOGON'|Select-Object -First 1
    $migration=Get-RawText $PackagePath 'dfsrmig-global-state.txt';$migrationState=Get-RawText $PackagePath 'dfsrmig-migration-state.txt'
    $dfsr=($migration -match '(?i)eliminated|state\s*3') -or ($migrationState -match '(?i)consistent state.*eliminated|all domain controllers.*eliminated')
    $frsLegacy=(!$dfsr)
    $findings=@()
    if(!$sysvol){$findings+=New-Finding $Scope 'SYSVOL' 'Red' 'SYSVOL share missing' 'SYSVOL was not present in the local share inventory.' 'local-inventory.json'}
    if(!$netlogon){$findings+=New-Finding $Scope 'SYSVOL' 'Red' 'NETLOGON share missing' 'NETLOGON was not present in the local share inventory.' 'local-inventory.json'}
    if($frsLegacy){$findings+=New-Finding $Scope 'SYSVOL' 'Red' 'Legacy FRS or indeterminate SYSVOL replication' 'DFSRMIG evidence did not confirm the Eliminated state. Review dfsrmig raw files.' 'dfsrmig-global-state.txt'}else{$findings+=New-Finding $Scope 'SYSVOL' 'Green' 'SYSVOL uses DFS Replication' 'DFSRMIG evidence indicates the Eliminated state.' 'dfsrmig-global-state.txt'}
    [pscustomobject]@{SysvolPublished=[bool]$sysvol;NetlogonPublished=[bool]$netlogon;SysvolPath=if($sysvol){$sysvol.Path}else{''};NetlogonPath=if($netlogon){$netlogon.Path}else{''};DFSR=$dfsr;LegacyFRS=$frsLegacy;MigrationText=($migration.Trim());Findings=$findings}
}
function Get-EventFindings {
    param([object[]]$Events,[string]$Scope)
    $critical=@($Events|Where-Object{$_.LevelDisplayName -in @('Critical','Error')});$groups=@($critical|Group-Object LogName,Id,ProviderName|Sort-Object Count -Descending)
    $findings=@();foreach($g in $groups|Select-Object -First 100){$sample=$g.Group|Select-Object -First 1;$state=if($sample.LevelDisplayName -eq 'Critical'){'Red'}else{'Yellow'};$findings+=New-Finding $Scope 'Event Log' $state ("Recurring event ID {0} ({1} occurrence(s))" -f $sample.Id,$g.Count) ("Log: {0}; Provider: {1}; Sample: {2}" -f $sample.LogName,$sample.ProviderName,([string]$sample.Message -replace '\s+',' ')) 'events.json'}
    if(!$groups.Count){$findings+=New-Finding $Scope 'Event Log' 'Green' 'No critical or error events' 'No Critical or Error events were captured in the configured lookback period.' 'events.json'}
    return $findings
}
$Css = @'
:root{--navy:#1F3864;--blue:#2E75B6;--light:#BDD7EE;--green:#548235;--red:#C00000;--amber:#F4B942;--text:#1A1A2E;--muted:#595959}
*{box-sizing:border-box}body{margin:0;font:13px 'Segoe UI',Arial,sans-serif;background:#EEF2F7;color:var(--text)}header{background:linear-gradient(135deg,var(--navy),#0D1B35);color:#fff;padding:26px 40px;border-bottom:4px solid var(--blue)}header h1{margin:0;font-size:24px}.sub{color:var(--light);margin-top:5px}.meta{display:flex;gap:28px;margin-top:15px;padding-top:12px;border-top:1px solid #ffffff33}.meta b{display:block;font-size:9px;color:#8BAFD4;text-transform:uppercase}.page{max-width:1500px;margin:auto;padding:24px 32px}section{margin-bottom:26px}h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--navy);border-left:4px solid var(--blue);padding:8px 12px;background:#fff}.cards{display:grid;grid-template-columns:repeat(4,minmax(190px,1fr));gap:10px}.card{background:#fff;padding:14px;text-align:center;border-top:3px solid var(--blue);box-shadow:0 1px 4px #0002;min-height:124px;display:flex;flex-direction:column;align-items:center;justify-content:flex-start}.value{font-size:24px;font-weight:800;color:var(--navy);white-space:nowrap;overflow:visible;word-break:normal;display:flex;align-items:center;justify-content:center;flex:1;width:100%}.value.compact{font-size:20px}.label{margin-top:auto;min-height:24px;display:flex;align-items:flex-end;justify-content:center;width:100%;line-height:1.2}.label{font-size:9px;text-transform:uppercase;color:var(--muted);margin-top:auto;min-height:24px;display:flex;align-items:flex-end;justify-content:center;width:100%;line-height:1.2}table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px #0002;font-size:11px}th{background:var(--navy);color:#fff;padding:9px;text-align:left;text-transform:uppercase;font-size:9px}td{padding:8px 9px;border-bottom:1px solid #EEF2F7;vertical-align:top;overflow-wrap:anywhere}tr:nth-child(even) td{background:#F8FBFF}.notice{background:#FFF8E1;border-left:4px solid var(--amber);padding:12px 16px}.health{display:inline-block;padding:5px 11px;border-radius:999px;font-weight:800;text-transform:uppercase}.health.green{background:#E2EFDA;color:#375623}.health.yellow{background:#FFF2CC;color:#7B3F00}.health.red{background:#F4CCCC;color:#C00000}.card.green{border-top-color:#548235}.card.yellow{border-top-color:#F4B942}.card.red{border-top-color:#C00000}.finding-red td{background:#FDE9E7!important}.finding-yellow td{background:#FFF8E1!important}.finding-green td{background:#ECF5E8!important}.grade{font-size:42px;font-weight:900}.links a{display:inline-block;margin:3px 14px 3px 0}footer{background:var(--navy);color:#ffffff88;text-align:center;padding:14px}@media(max-width:1350px){.cards{grid-template-columns:repeat(3,minmax(210px,1fr))}}@media(max-width:900px){.cards{grid-template-columns:repeat(2,minmax(210px,1fr))}}@media(max-width:560px){.cards{grid-template-columns:1fr}.value{white-space:normal}}
'@

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$extractRoot = Join-Path $env:TEMP ("ADHealthReport-{0}" -f [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

try {
    if (Test-Path -LiteralPath $InputPath -PathType Leaf) {
        $zipFiles = @(Get-Item -LiteralPath $InputPath)
    } elseif (Test-Path -LiteralPath $InputPath -PathType Container) {
        $zipFiles = @(Get-ChildItem -LiteralPath $InputPath -Filter '*.zip' -File)
    } else {
        throw "Input path was not found: $InputPath"
    }
    if ($zipFiles.Count -eq 0) { throw 'No collector ZIP packages were found.' }

    $packages = @()
    foreach ($zipFile in $zipFiles) {
        Write-Host "Reading package: $($zipFile.FullName)"
        $destination = Join-Path $extractRoot $zipFile.BaseName
        Expand-Archive -LiteralPath $zipFile.FullName -DestinationPath $destination -Force
        $manifest = Read-JsonDocument (Join-Path $destination 'manifest.json')
        if ($null -eq $manifest) { Write-Warning "Skipping $($zipFile.Name): manifest.json is missing."; continue }
        $packages += [pscustomobject]@{
            Zip      = $zipFile
            Path     = $destination
            Manifest = $manifest
            Local    = Read-JsonDocument (Join-Path $destination 'local-inventory.json')
            Domain   = Read-JsonDocument (Join-Path $destination 'domain.json')
            Forest   = Read-JsonDocument (Join-Path $destination 'forest.json')
            DCs      = @(Read-JsonDocument (Join-Path $destination 'domain-controllers.json'))
            Events   = @(Read-JsonDocument (Join-Path $destination 'events.json'))
        }
    }
    if ($packages.Count -eq 0) { throw 'No valid raw packages were found.' }

    $firstPackage = $packages[0]
    $domainData = $firstPackage.Domain
    $forestData = $firstPackage.Forest
    $allDomainControllers = @($firstPackage.DCs)
    $dcOutputDirectory = Join-Path $OutputDirectory 'DomainControllers'
    $rawOutputDirectory = Join-Path $OutputDirectory 'Raw'
    New-Item -ItemType Directory -Path $dcOutputDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $rawOutputDirectory -Force | Out-Null

    $allFindings=@();$dcAssessments=@()
    foreach($analysisPackage in $packages){
        $scope=[string]$analysisPackage.Manifest.ComputerFqdn;if(!$scope){$scope=[string]$analysisPackage.Manifest.ComputerName}
        $dcdiagLocal=Get-RawText $analysisPackage.Path 'dcdiag-local-verbose.txt'
        $dcdiagEnterprise=Get-RawText $analysisPackage.Path 'dcdiag-enterprise-comprehensive-verbose.txt'
        $showRepl=Get-RawText $analysisPackage.Path 'repadmin-showrepl-all.csv.txt'
        $replSummary=Get-RawText $analysisPackage.Path 'repadmin-replsummary.txt'
        $dnsFiles=@(Get-ChildItem -LiteralPath $analysisPackage.Path -Filter 'dcdiag-dns-*.txt' -File)
        $sysvol=Get-SysvolAssessment $analysisPackage.Local $analysisPackage.Path $scope
        $dcFindings=@();$dcFindings+=Test-DcdiagText $dcdiagLocal 'dcdiag-local-verbose.txt' $scope;$dcFindings+=Test-DcdiagText $dcdiagEnterprise 'dcdiag-enterprise-comprehensive-verbose.txt' $scope;$dcFindings+=Test-RepadminText $showRepl $replSummary $scope;foreach($dnsFile in $dnsFiles){$dnsText=Get-Content -LiteralPath $dnsFile.FullName -Raw;$dcFindings+=Test-DnsText $dnsText ($dnsFile.BaseName-replace'^dcdiag-dns-','') $dnsFile.Name};if(!$dnsFiles.Count){$dcFindings+=Test-DnsText '' $scope 'dcdiag-dns'};$dcFindings+=Get-ConnectivityFindings $analysisPackage.Connectivity $analysisPackage.ReturnPath $scope;$dcFindings+=@($sysvol.Findings);$dcFindings+=Get-EventFindings $analysisPackage.Events $scope
        $state=Get-WorstState $dcFindings;$dcAssessments+=[pscustomobject]@{ComputerName=$analysisPackage.Manifest.ComputerName;Fqdn=$scope;State=$state;Grade=(Get-GradeFromState $state);Sysvol=$sysvol;Findings=$dcFindings};$allFindings+=@($dcFindings)
    }
    $upgrade=Get-FunctionalLevelAnalysis $allDomainControllers ([string]$domainData.DomainMode) ([string]$forestData.ForestMode);$allFindings+=@($upgrade.Blockers)
    $forestState=Get-WorstState $allFindings;$forestGrade=Get-GradeFromState $forestState

    $availabilityRows=@()
    foreach($inventoryDc in $allDomainControllers){
        $dcHost=[string]$inventoryDc.HostName
        $matchingPackage=@($packages|Where-Object{$_.Manifest.ComputerFqdn -ieq $dcHost -or $_.Manifest.ComputerName -ieq ($dcHost -split '\.')[0]}|Select-Object -First 1)
        $reachProperty=$inventoryDc.PSObject.Properties['Reachable']
        $onlineProperty=$inventoryDc.PSObject.Properties['Online']
        if($reachProperty){$reachable=[bool]$reachProperty.Value;$basis='Collector connectivity test'}
        elseif($onlineProperty){$reachable=[bool]$onlineProperty.Value;$basis='Collector online test'}
        elseif($matchingPackage.Count -gt 0){$reachable=$true;$basis='Local collector package was successfully produced on this DC'}
        else{$reachable=$false;$basis='No local collector package or explicit reachability result was supplied'}
        $availabilityRows+=[pscustomobject]@{HostName=$dcHost;IPv4Address=$inventoryDc.IPv4Address;Enabled=$inventoryDc.Enabled;Reachable=$reachable;AssessmentBasis=$basis;CollectorPackage=if($matchingPackage.Count){$matchingPackage[0].Zip.Name}else{'Missing'}}
    }
    $unreachableRows=@($availabilityRows|Where-Object{$_.Reachable -ne $true -or $_.Enabled -eq $false})
    $allDcReachable=($availabilityRows.Count -gt 0 -and $unreachableRows.Count -eq 0)
    $dnsPackageRows=@($packages|Where-Object{
        $featureNames=@($_.Local.Features|ForEach-Object{[string]$_.Name})
        $serviceNames=@($_.Local.Services|ForEach-Object{[string]$_.Name})
        ($featureNames -match '(?i)^DNS$|DNS-Server|DNS-Server-Full-Role') -or ($serviceNames -contains 'DNS')
    })
    $dnsServerNames=@($dnsPackageRows|ForEach-Object{[string]$_.Manifest.ComputerFqdn}|Where-Object{$_}|Sort-Object -Unique)
    $dnsServerCount=$dnsServerNames.Count
    $changeRecommendations=Get-ChangeRecommendations -ForestState $forestState -ForestGrade $forestGrade -AllDcReachable $allDcReachable -AllFindings $allFindings -DomainControllers $allDomainControllers -UpgradeAnalysis $upgrade

    foreach ($package in $packages) {
        $computerName = [string]$package.Manifest.ComputerName
        $packageRawDirectory = Join-Path $rawOutputDirectory $computerName
        New-Item -ItemType Directory -Path $packageRawDirectory -Force | Out-Null
        Copy-Item -Path (Join-Path $package.Path '*') -Destination $packageRawDirectory -Recurse -Force

        $local = $package.Local
        if ($null -eq $local) { Write-Warning "No local-inventory.json in $($package.Zip.Name)."; continue }
        $allEvents = @($package.Events)
        $criticalEvents = @($allEvents | Where-Object { $_.LevelDisplayName -in @('Critical','Error') })
        $body = "<div class='cards'>" +
            "<div class='card'><div class='value'>$(ConvertTo-HtmlEncoded $local.OS)</div><div class='label'>Operating System</div></div>" +
            "<div class='card'><div class='value'>$(ConvertTo-HtmlEncoded $local.Site)</div><div class='label'>Site</div></div>" +
            "<div class='card'><div class='value'>$(@($local.Features).Count)</div><div class='label'>Roles and Features</div></div>" +
            "<div class='card'><div class='value'>$(@($local.Services).Count)</div><div class='label'>Services</div></div>" +
            "<div class='card'><div class='value'>$(@($local.Software).Count)</div><div class='label'>Applications</div></div>" +
            "<div class='card'><div class='value'>$($criticalEvents.Count)</div><div class='label'>Critical and Error Events</div></div></div>"
        $body += New-HtmlSection 'SYSVOL and NETLOGON Shares' (New-HtmlTable @($local.Shares) @('Name','Path','Status'))
        $body += New-HtmlSection 'Network and DNS Configuration' (New-HtmlTable @($local.Network) @('Description','MACAddress','IPAddress','IPSubnet','DefaultGateway','DNSServers','DNSDomain','DHCPEnabled'))
        $body += New-HtmlSection 'Installed Roles and Features' (New-HtmlTable @($local.Features) @('Name','DisplayName','InstallState'))
        $body += New-HtmlSection 'Services' (New-HtmlTable @($local.Services) @('Name','DisplayName','State','StartMode','StartName'))
        $body += New-HtmlSection 'Installed Applications' (New-HtmlTable @($local.Software) @('DisplayName','DisplayVersion','Publisher','InstallDate'))
        $body += New-HtmlSection 'Critical and Error Events' (New-HtmlTable $criticalEvents @('LogName','TimeCreated','Id','LevelDisplayName','ProviderName','Message'))
        $encodedComputer = [uri]::EscapeDataString($computerName)
        $links = "<div class='links'><a href='../Raw/$encodedComputer/dcdiag-local-verbose.txt'>Local dcdiag</a><a href='../Raw/$encodedComputer/dcdiag-enterprise-comprehensive-verbose.txt'>Enterprise dcdiag</a><a href='../Raw/$encodedComputer/repadmin-showrepl-all.csv.txt'>Repadmin CSV</a><a href='../Raw/$encodedComputer/collector.log'>Collector log</a></div>"
        $body += New-HtmlSection 'Raw Evidence' $links
        $dcHtml = "<!doctype html><html><head><meta charset='utf-8'><title>$(ConvertTo-HtmlEncoded $local.Fqdn)</title><style>$Css</style></head><body><header><h1>Domain Controller Health and Inventory</h1><div class='sub'>$(ConvertTo-HtmlEncoded $local.Fqdn)</div><div class='meta'><div><b>Collected</b>$(ConvertTo-HtmlEncoded $local.Collected)</div><div><b>Source ZIP</b>$(ConvertTo-HtmlEncoded $package.Zip.Name)</div></div></header><main class='page'>$body</main><footer>Active Directory Health Raw Collector and Report Generator Rev 1.2</footer></body></html>"
        $safeName = $computerName -replace '[^A-Za-z0-9._-]','_'
        Set-Content -LiteralPath (Join-Path $dcOutputDirectory ($safeName + '.html')) -Value $dcHtml -Encoding UTF8
    }

    $fsmoRows=@([pscustomobject]@{Role='Schema Master';Holder=$forestData.SchemaMaster},[pscustomobject]@{Role='Domain Naming Master';Holder=$forestData.DomainNamingMaster},[pscustomobject]@{Role='PDC Emulator';Holder=$domainData.PDCEmulator},[pscustomobject]@{Role='RID Master';Holder=$domainData.RIDMaster},[pscustomobject]@{Role='Infrastructure Master';Holder=$domainData.InfrastructureMaster})
    $gcRows=@($allDomainControllers|Where-Object{$_.IsGlobalCatalog -eq $true})
    $reachState=if($allDcReachable){'Green'}else{'Red'}
    $cards="<div class='cards'><div class='card $($forestState.ToLower())'><div class='value grade'>$forestGrade</div><div class='label'>Forest Health Grade</div></div><div class='card $($forestState.ToLower())'><div class='value'>$(New-HealthBadge $forestState $forestState)</div><div class='label'>Overall Health</div></div><div class='card'><div class='value'>$($allDomainControllers.Count)</div><div class='label'>Domain Controllers</div></div><div class='card'><div class='value'>$($gcRows.Count)</div><div class='label'>Global Catalogs</div></div><div class='card'><div class='value compact'>$(ConvertTo-HtmlEncoded $forestData.ForestMode)</div><div class='label'>Forest Functional Level</div></div><div class='card'><div class='value compact'>$(ConvertTo-HtmlEncoded $domainData.DomainMode)</div><div class='label'>Domain Functional Level</div></div><div class='card'><div class='value'>$dnsServerCount</div><div class='label'>DNS Servers Present</div></div><div class='card $($reachState.ToLower())'><div class='value'>$(New-HealthBadge $reachState ([string]$allDcReachable))</div><div class='label'>All Domain Controllers Reachable</div></div></div>"
    $body=$cards
    $summaryRows=@($dcAssessments|ForEach-Object{[pscustomobject]@{DomainController=$_.Fqdn;Health=$_.State;Grade=$_.Grade;SYSVOLPublished=$_.Sysvol.SysvolPublished;NETLOGONPublished=$_.Sysvol.NetlogonPublished;DFSR=$_.Sysvol.DFSR;LegacyFRS=$_.Sysvol.LegacyFRS;SYSVOLPath=$_.Sysvol.SysvolPath}})
    $body+=New-HtmlSection 'Forest and Domain Health Assessment' (New-HtmlTable $summaryRows @('DomainController','Health','Grade','SYSVOLPublished','NETLOGONPublished','DFSR','LegacyFRS','SYSVOLPath'))
    $body+=New-HtmlSection 'Change Recommendations Based on Current Health' (New-HtmlTable $changeRecommendations @('ProposedChange','Recommended','RequiredHealth','Reason'))
    $body+=New-HtmlSection 'Domain Controller Availability and Reachability' (New-HtmlTable $availabilityRows @('HostName','IPv4Address','Enabled','Reachable','AssessmentBasis','CollectorPackage'))
    $body+=New-HtmlSection 'Domain Controllers Not Online or Reachable' (New-HtmlTable $unreachableRows @('HostName','IPv4Address','Enabled','Reachable','AssessmentBasis','CollectorPackage'))
    $dnsRows=@($dnsPackageRows|ForEach-Object{[pscustomobject]@{HostName=$_.Manifest.ComputerFqdn;ComputerName=$_.Manifest.ComputerName;DnsServicePresent=(@($_.Local.Services|Where-Object Name -eq 'DNS').Count -gt 0);DnsRoleOrFeaturePresent=(@($_.Local.Features|Where-Object{[string]$_.Name -match '(?i)^DNS$|DNS-Server|DNS-Server-Full-Role'}).Count -gt 0)}})
    $body+=New-HtmlSection 'DNS Servers Present' (New-HtmlTable $dnsRows @('HostName','ComputerName','DnsServicePresent','DnsRoleOrFeaturePresent'))
    $upgradeSummary=@([pscustomobject]@{Scope='Domain';Current=$upgrade.CurrentDomain;HighestEligible=$upgrade.HighestEligibleDomain;Blockers=if($upgrade.NoBlockers){'No blockers'}else{(@($upgrade.Blockers.Title)-join '; ')}},[pscustomobject]@{Scope='Forest';Current=$upgrade.CurrentForest;HighestEligible=$upgrade.HighestEligibleForest;Blockers=if($upgrade.NoBlockers){'No blockers'}else{(@($upgrade.Blockers.Title)-join '; ')}})
    $body+=New-HtmlSection 'Forest and Domain Functional-Level Upgrade Path' (New-HtmlTable $upgradeSummary @('Scope','Current','HighestEligible','Blockers'))
    $body+=New-HtmlSection 'Domain Controller Eligibility for Functional-Level Upgrade' (New-HtmlTable $upgrade.Rows @('HostName','OperatingSystem','EligibleFor2016','EligibleFor2025','Reason'))
    $body+=New-HtmlSection 'Domain Controllers' (New-HtmlTable $allDomainControllers @('HostName','IPv4Address','Site','OperatingSystem','OperatingSystemVersion','IsGlobalCatalog','IsReadOnly','Enabled'))
    $body+=New-HtmlSection 'FSMO Role Holders' (New-HtmlTable $fsmoRows @('Role','Holder'))
    $body+=New-HtmlSection 'Global Catalog Servers' (New-HtmlTable $gcRows @('HostName','IPv4Address','Site'))
    $categoryRows=@();foreach($category in 'Replication','Connectivity','DNS','DCDiag','SYSVOL','Event Log'){$categoryFindings=@($allFindings|Where-Object Category -eq $category);$categoryRows+=[pscustomobject]@{Category=$category;Health=(Get-WorstState $categoryFindings);Green=@($categoryFindings|Where-Object State -eq 'Green').Count;Yellow=@($categoryFindings|Where-Object State -eq 'Yellow').Count;Red=@($categoryFindings|Where-Object State -eq 'Red').Count}}
    $body+=New-HtmlSection 'Health by Diagnostic Category' (New-HtmlTable $categoryRows @('Category','Health','Green','Yellow','Red'))
    $redFindings=@($allFindings|Where-Object State -eq 'Red');$yellowFindings=@($allFindings|Where-Object State -eq 'Yellow')
    $body+=New-HtmlSection 'Red Findings Requiring Action' (New-HtmlTable $redFindings @('Scope','Category','State','Title','Detail','Source'))
    $body+=New-HtmlSection 'Yellow Findings Requiring Review' (New-HtmlTable $yellowFindings @('Scope','Category','State','Title','Detail','Source'))
    $packageRows=@($packages|ForEach-Object{[pscustomobject]@{ComputerName=$_.Manifest.ComputerName;ComputerFqdn=$_.Manifest.ComputerFqdn;CollectedUtc=$_.Manifest.CollectedUtc;OperatingSystem=$_.Manifest.OperatingSystem;Zip=$_.Zip.Name}})
    $connectivityRows=@($packages|ForEach-Object{$_.Connectivity});$returnRows=@($packages|ForEach-Object{$_.ReturnPath}|ForEach-Object{[pscustomobject]@{Source=$_.Source;Destination=$_.Destination;RemoteExecution=$_.RemoteExecution;Error=$_.Error}});$body+=New-HtmlSection 'Forest-Wide Connectivity Tests' (New-HtmlTable $connectivityRows @('Source','Destination','DestinationSite','ResolvedAddresses','IcmpReachable','Port','Open','LatencyMs','Error'));$body+=New-HtmlSection 'Reverse-Path Test Coverage' (New-HtmlTable $returnRows @('Source','Destination','RemoteExecution','Error'))
    $body+=New-HtmlSection 'Collected Packages' (New-HtmlTable $packageRows @('ComputerName','ComputerFqdn','CollectedUtc','OperatingSystem','Zip'))
    $missing=@($allDomainControllers|Where-Object{$dcHostName=$_.HostName;@($packages|Where-Object{$_.Manifest.ComputerFqdn -ieq $dcHostName}).Count -eq 0});if($missing.Count){$body+=New-HtmlSection 'Collection Coverage Warning' ("<div class='notice'>No local collector package was provided for: $(ConvertTo-HtmlEncoded (($missing.HostName)-join ', ')). This is informational and does not reduce the grade. Domain-wide evidence from the selected collector DC is used; remote local-event detail may be limited.</div>")}
    $reportHtml="<!doctype html><html><head><meta charset='utf-8'><title>AD Health - $(ConvertTo-HtmlEncoded $domainData.Name)</title><style>$Css</style></head><body><header><h1>Active Directory Forest and Domain Health Assessment</h1><div class='sub'>$(ConvertTo-HtmlEncoded $domainData.Name)</div><div class='meta'><div><b>Generated</b>$(Get-Date)</div><div><b>Packages</b>$($packages.Count)</div><div><b>Health</b>$forestState / Grade $forestGrade</div></div></header><main class='page'>$body</main><footer>Active Directory Health Raw Collector and Report Generator Rev 1.2</footer></body></html>"
    $reportPath=Join-Path $OutputDirectory 'Active-Directory-Consolidated-Report.html';Set-Content -LiteralPath $reportPath -Value $reportHtml -Encoding UTF8;Write-Host "Report created: $reportPath" -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
}
