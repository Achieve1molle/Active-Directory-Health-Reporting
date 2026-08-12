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

    [string]$OutputDirectory = (Join-Path (Get-Location) ("AD-Health-Report-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [string]$WaiverPath
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
            $columnClass='col-' + ($columnName.ToLowerInvariant() -replace '[^a-z0-9]+','-').Trim('-')
            $encodedValue=ConvertTo-HtmlEncoded $value
            [void]$builder.Append("<td class='$columnClass' title='$encodedValue'>").Append($encodedValue).Append('</td>')
        }
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table>')
    return $builder.ToString()
}

function New-HtmlSection {
    param([string]$Title, [string]$Body)
    return "<section><h2>$(ConvertTo-HtmlEncoded $Title)</h2><div class='table-scroll'>$Body</div></section>"
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
    $connectivityRed=@($AllFindings|Where-Object{ $_.State -eq 'Red' -and $_.Category -eq 'Connectivity' }).Count
    $healthyForChange=($ForestState -eq 'Green' -and $AllDcReachable -and $redCount -eq 0)
    $stableEnoughForLowRisk=($ForestState -ne 'Red' -and $AllDcReachable -and $replicationRed -eq 0 -and $dnsRed -eq 0 -and $sysvolRed -eq 0)
    $baseBlockers=@()
    if(!$AllDcReachable){$baseBlockers+='One or more domain controllers are not confirmed reachable'}
    if($replicationRed){$baseBlockers+="$replicationRed red replication finding(s)"}
    if($dnsRed){$baseBlockers+="$dnsRed red DNS finding(s)"}
    if($dcdiagRed){$baseBlockers+="$dcdiagRed red DCDiag finding(s)"}
    if($sysvolRed){$baseBlockers+="$sysvolRed red SYSVOL/DFSR finding(s)"}
    if($eventRed){$baseBlockers+="$eventRed red AD-impacting event-log finding(s)"}
    if($connectivityRed){$baseBlockers+="$connectivityRed required-port connectivity failure(s)"}
    if(!$baseBlockers.Count -and $yellowCount){$baseBlockers+="$yellowCount yellow review finding(s)"}
    if(!$baseBlockers.Count){$baseBlockers+='No health blockers detected'}
    $commonReason=$baseBlockers -join '; '
    $domainAtHighest=([string]$UpgradeAnalysis.CurrentDomain -match [regex]::Escape([string]'Windows2016'))
    $forestAtHighest=([string]$UpgradeAnalysis.CurrentForest -match [regex]::Escape([string]'Windows2016'))
    @(
        [pscustomobject]@{ProposedChange='Add a domain controller';Recommended=$stableEnoughForLowRisk;RequiredHealth='Green or Yellow with no red replication, DNS, or SYSVOL findings';Reason=if($stableEnoughForLowRisk){'Health baseline is adequate for a controlled DC addition. Complete normal pre-change validation and backups.'}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Migrate FSMO roles';Recommended=$healthyForChange;RequiredHealth='Green only; all DCs reachable; no red findings';Reason=if($healthyForChange){'Forest health is Green and all DCs are confirmed reachable.'}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Update forest functional level';Recommended=($healthyForChange -and !$forestAtHighest -and $UpgradeAnalysis.Eligible2016);RequiredHealth='Green only; no OS blockers; domain level already eligible';Reason=if($forestAtHighest){"No change required. Forest already uses the highest eligible level: $($UpgradeAnalysis.CurrentForest)."}elseif(!$UpgradeAnalysis.Eligible2016){(@($UpgradeAnalysis.Blockers2016.Title)-join '; ')}elseif($healthyForChange){"Eligible to raise toward $('Windows2016') after formal change validation."}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Update domain functional level';Recommended=($healthyForChange -and !$domainAtHighest -and $UpgradeAnalysis.Eligible2016);RequiredHealth='Green only; all DCs support the target level';Reason=if($domainAtHighest){"No change required. Domain already uses the highest eligible level: $($UpgradeAnalysis.CurrentDomain)."}elseif(!$UpgradeAnalysis.Eligible2016){(@($UpgradeAnalysis.Blockers2016.Title)-join '; ')}elseif($healthyForChange){"Eligible to raise toward $('Windows2016') after formal change validation."}else{$commonReason}}
        [pscustomobject]@{ProposedChange='Demote a domain controller';Recommended=$healthyForChange;RequiredHealth='Green only; all DCs reachable; replication, DNS, SYSVOL, and DCDiag healthy';Reason=if($healthyForChange){'Health baseline is Green. Confirm remaining DNS, GC, FSMO, and capacity coverage before demotion.'}else{$commonReason}}
    )
}
function Get-FunctionalLevelAnalysis { param([object[]]$DomainControllers,[string]$CurrentDomainMode,[string]$CurrentForestMode)
 $rows=@();$block2016=@();$block2025=@();foreach($dc in @($DomainControllers)){$os=[string]$dc.OperatingSystem;$e2016=$os-match'2016|2019|2022|2025';$e2025=$os-match'2025';if(!$e2016){$block2016+=New-Finding 'Forest/Domain' 'Functional Level' 'Red' "$($dc.HostName) blocks Windows Server 2016 functional level" "DC operating system is '$os'." 'domain-controllers.json'};if(!$e2025){$block2025+=[pscustomobject]@{HostName=$dc.HostName;OperatingSystem=$os;Reason='Windows Server 2025 functional level requires Windows Server 2025 DCs'}};$rows+=[pscustomobject]@{HostName=$dc.HostName;OperatingSystem=$os;EligibleFor2016=$e2016;EligibleFor2025=$e2025}}
 [pscustomobject]@{CurrentDomain=$CurrentDomainMode;CurrentForest=$CurrentForestMode;Rows=$rows;Blockers2016=$block2016;Blockers2025=$block2025;Eligible2016=($block2016.Count-eq0);Eligible2025=($block2025.Count-eq0)} }
function Test-DcdiagText {
    param([string]$Text,[string]$Source,[string]$Scope)
    if([string]::IsNullOrWhiteSpace($Text)){return ,(New-Finding $Scope 'DCDiag' 'Yellow' 'DCDiag evidence missing' 'The expected raw DCDiag file was not available.' $Source)}
    $lines=@($Text -split "`r?`n" | ForEach-Object {$_.Trim()} | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    $failed=@($lines | Where-Object {$_ -match '(?i)failed test\s+\w+|fatal error|could not be tested' -and $_ -notmatch '(?i)previous call succeeded'} | Sort-Object -Unique)
    if($failed.Count){return @($failed | Select-Object -First 50 | ForEach-Object {New-Finding $Scope 'DCDiag' 'Red' 'DCDiag test failed' $_ $Source})}
    return ,(New-Finding $Scope 'DCDiag' 'Green' 'DCDiag completed without an explicit failed-test result' 'Historical warning and error events embedded in DCDiag output are assessed separately under Event Log.' $Source)
}
function Test-RepadminText {
    param([string]$ShowRepl,[string]$Summary,[string]$Scope)
    $combined="$ShowRepl`n$Summary"
    if([string]::IsNullOrWhiteSpace($combined)){return ,(New-Finding $Scope 'Replication' 'Yellow' 'Replication evidence missing' 'Repadmin output was not available.' 'repadmin')}
    $lines=@($combined -split "`r?`n" | ForEach-Object {$_.Trim()} | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    $bad=@($lines | Where-Object {
        $_ -notmatch '(?i)^showrepl_COLUMNS|Destination DSA Site,Destination DSA|Source DSA.*largest delta|^Command:|^Completed:|^ExitCode:|====' -and
        (($_ -match '(?i)\b([1-9]\d*)\s*/\s*\d+\s+\d+%' ) -or ($_ -match '(?i)last failure status.*[1-9]\d*') -or ($_ -match '(?i)result\s+[-:]\s*[1-9]\d*') -or ($_ -match '(?i)replication.*failed'))
    } | Sort-Object -Unique)
    if($bad.Count){return @($bad | Select-Object -First 50 | ForEach-Object {New-Finding $Scope 'Replication' 'Red' 'Replication failure detected' $_ 'repadmin'})}
    return ,(New-Finding $Scope 'Replication' 'Green' 'No Repadmin replication failures detected' 'Headers and zero-failure summary rows were excluded from failure scoring.' 'repadmin')
}
function Test-DnsText {
    param([string]$Text,[string]$Scope,[string]$Source)
    if([string]::IsNullOrWhiteSpace($Text)){return ,(New-Finding $Scope 'DNS' 'Yellow' 'DNS diagnostic evidence missing' 'The DNS-specific DCDiag output was not available.' $Source)}
    $lines=@($Text -split "`r?`n" | ForEach-Object {$_.Trim()} | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    $red=@($lines | Where-Object {$_ -match '(?i)failed test DNS|all forwarders in the forwarder list are invalid|all DNS servers are invalid|record registrations (cannot be found|not found)' } | Sort-Object -Unique)
    $yellow=@($lines | Where-Object {$_ -match '(?i)^Warning: Delegation .* is broken|dynamic IP address' } | Sort-Object -Unique)
    $findings=@()
    foreach($line in $red){$findings+=New-Finding $Scope 'DNS' 'Red' 'DNS diagnostic failure' $line $Source}
    foreach($line in $yellow){$findings+=New-Finding $Scope 'DNS' 'Yellow' 'DNS diagnostic warning' $line $Source}
    if(!$findings.Count){$findings+=New-Finding $Scope 'DNS' 'Green' 'DNS diagnostics passed' 'No actionable DNS failure signature was found.' $Source}
    return $findings
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
    $critical=@($Events|Where-Object{$_.LevelDisplayName -in @('Critical','Error')})
    $groups=@($critical|Group-Object LogName,Id,ProviderName|Sort-Object Count -Descending)
    $adBlockingIds=@(404,407,408,4004,4015,4016,5002,2087,2095,2104,2103,2213,1411)
    $findings=@()
    foreach($g in $groups|Select-Object -First 100){
        $sample=$g.Group|Select-Object -First 1
        $provider=[string]$sample.ProviderName;$id=[int]$sample.Id
        $isAdCritical=($id -in $adBlockingIds) -and ($provider -match '(?i)DNS|ActiveDirectory|DFSR|Directory')
        $state=if($isAdCritical){'Red'}else{'Yellow'}
        $title=if($isAdCritical){"AD-impacting event ID $id ($($g.Count) occurrence(s))"}else{"Operational event ID $id ($($g.Count) occurrence(s))"}
        $findings+=New-Finding $Scope 'Event Log' $state $title ("Log: {0}; Provider: {1}; Sample: {2}" -f $sample.LogName,$provider,([string]$sample.Message -replace '\s+',' ')) 'events.json'
    }
    if(!$groups.Count){$findings+=New-Finding $Scope 'Event Log' 'Green' 'No critical or error events' 'No Critical or Error events were captured in the configured lookback period.' 'events.json'}
    return $findings
}
function Get-DnsIssueRows { param($Packages)
 $rows=@();$seen=@{}
 foreach($p in @($Packages)){foreach($f in @(Get-ChildItem $p.Path -Filter 'dcdiag-dns-*.txt' -File -ErrorAction SilentlyContinue)){
  $text=Get-RawText $p.Path $f.Name;$scope=$f.BaseName-replace'^dcdiag-dns-',''
  foreach($line in @($text-split"`r?`n"|ForEach-Object{$_.Trim()}|Where-Object{$_-match'(?i)failed test DNS|all forwarders in the forwarder list are invalid|all DNS servers are invalid|record registrations (cannot be found|not found)|^Warning: Delegation .* is broken|dynamic IP address'}|Sort-Object -Unique)){
   $normalized=($line.ToLowerInvariant() -replace'\s+',' ').Trim();$key="$scope|$normalized"
   if(!$seen.ContainsKey($key)){$seen[$key]=$true;$rows+=[pscustomobject]@{DomainController=$scope;Severity=if($line-match'(?i)^Warning:|dynamic IP'){'Warning'}else{'Error'};Issue=$line;Source=$f.Name}}
  }
 }}
 return $rows
}
function Get-TimeRows { param($Packages)
 $rows=@()
 foreach($p in @($Packages)){
  $statusVerbose=[string](Get-RawText $p.Path 'w32tm-status-verbose.txt')
  $statusBasic=[string](Get-RawText $p.Path 'w32tm-status.txt')
  $configuration=[string](Get-RawText $p.Path 'w32tm-configuration.txt')
  $sourceFile=[string](Get-RawText $p.Path 'w32tm-source.txt')
  $monitor=[string](Get-RawText $p.Path 'w32tm-forest-monitor.txt')
  $status=if(-not [string]::IsNullOrWhiteSpace($statusVerbose)){$statusVerbose}else{$statusBasic}
  $sourceLine=@($sourceFile -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch 'Command:|Completed:|ExitCode:|====' } | Select-Object -First 1)
  if($sourceLine.Count -gt 0){$src=([string]$sourceLine[0]).Trim()}
  elseif($status -match '(?im)^Source:\s*(.+)$'){$src=([string]$Matches[1]).Trim()}
  else{$src='Evidence not collected'}
  $last=if($status -match '(?im)^Last Successful Sync Time:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $stratum=if($status -match '(?im)^Stratum:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $reference=if($status -match '(?im)^ReferenceId:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $rootDelay=if($status -match '(?im)^Root Delay:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $dispersion=if($status -match '(?im)^Root Dispersion:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $configuredPeers=if($configuration -match '(?im)^NtpServer:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $timeType=if($configuration -match '(?im)^Type:\s*(.+)$'){([string]$Matches[1]).Trim()}else{'Not available'}
  $fqdn=if($null -ne $p.Manifest -and -not [string]::IsNullOrWhiteSpace([string]$p.Manifest.ComputerFqdn)){[string]$p.Manifest.ComputerFqdn}else{'Unknown collector'}
  $rows+=[pscustomobject]@{DomainController=$fqdn;TimeSource=$src;ConfiguredPeers=$configuredPeers;Type=$timeType;LastSuccessfulSync=$last;Stratum=$stratum;ReferenceId=$reference;RootDelay=$rootDelay;RootDispersion=$dispersion;ForestMonitor=if(-not [string]::IsNullOrWhiteSpace($monitor)){'Available'}else{'Missing'}}
 }
 return $rows
}
function Get-FindingId {
 param([object]$Finding)
 $identity=('{0}|{1}|{2}|{3}|{4}|{5}' -f $Finding.Scope,$Finding.Category,$Finding.State,$Finding.Title,$Finding.Detail,$Finding.Source).ToLowerInvariant()
 $hash=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))
 return ([BitConverter]::ToString($hash)-replace'-','').Substring(0,16)
}
function Test-ApprovedValue { param($Value) return ([string]$Value -match '^(?i:true|yes|y|1|approved)$') }
function Get-WaiverDecision {
 param([object]$Finding,[hashtable]$Index,[datetime]$AsOf)
 $id=Get-FindingId $Finding
 if($Finding.State -eq 'Green'){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Not eligible: positive Green finding';Record=$null}}
 if(!$Index.ContainsKey($id)){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Not approved';Record=$null}}
 $w=$Index[$id]
 if(-not(Test-ApprovedValue $w.Approved)){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Not approved';Record=$w}}
 if([string]::IsNullOrWhiteSpace([string]$w.Approver)-or[string]::IsNullOrWhiteSpace([string]$w.ApprovedDate)-or[string]::IsNullOrWhiteSpace([string]$w.Reason)){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Invalid: approver, approved date, and reason are required';Record=$w}}
 $d=[datetime]::MinValue;if(-not[datetime]::TryParse([string]$w.ApprovedDate,[ref]$d)){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Invalid approved date';Record=$w}}
 if(-not[string]::IsNullOrWhiteSpace([string]$w.ExpirationDate)){$e=[datetime]::MinValue;if(-not[datetime]::TryParse([string]$w.ExpirationDate,[ref]$e)){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Invalid expiration date';Record=$w}};if($e.Date-lt$AsOf.Date){return [pscustomobject]@{FindingId=$id;Applied=$false;Status='Expired';Record=$w}}}
 return [pscustomobject]@{FindingId=$id;Applied=$true;Status='Approved waiver applied';Record=$w}
}
$Css = @'
:root{--navy:#1F3864;--blue:#2E75B6;--light:#BDD7EE;--green:#548235;--red:#C00000;--amber:#F4B942;--text:#1A1A2E;--muted:#595959}
*{box-sizing:border-box}body{margin:0;font:13px 'Segoe UI',Arial,sans-serif;background:#EEF2F7;color:var(--text)}header{background:linear-gradient(135deg,var(--navy),#0D1B35);color:#fff;padding:26px 40px;border-bottom:4px solid var(--blue)}header h1{margin:0;font-size:24px}.sub{color:var(--light);margin-top:5px}.meta{display:flex;gap:28px;margin-top:15px;padding-top:12px;border-top:1px solid #ffffff33}.meta b{display:block;font-size:9px;color:#8BAFD4;text-transform:uppercase}.page{max-width:1500px;margin:auto;padding:24px 32px}section{margin-bottom:26px}h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--navy);border-left:4px solid var(--blue);padding:8px 12px;background:#fff}.cards{display:grid;grid-template-columns:repeat(4,minmax(190px,1fr));gap:10px}.card{background:#fff;padding:14px;text-align:center;border-top:3px solid var(--blue);box-shadow:0 1px 4px #0002;min-height:124px;display:flex;flex-direction:column;align-items:center;justify-content:flex-start}.value{font-size:24px;font-weight:800;color:var(--navy);white-space:normal;overflow-wrap:anywhere;line-height:1.2;display:flex;align-items:center;justify-content:center;flex:1;width:100%}.value.compact{font-size:20px}.value.long{font-size:18px;line-height:1.25}.open{color:#375623;font-weight:700}.closed{color:#C00000;font-weight:700}.label{margin-top:auto;min-height:24px;display:flex;align-items:flex-end;justify-content:center;width:100%;line-height:1.2}.label{font-size:9px;text-transform:uppercase;color:var(--muted);margin-top:auto;min-height:24px;display:flex;align-items:flex-end;justify-content:center;width:100%;line-height:1.2}table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px #0002;font-size:11px;table-layout:auto}th{background:var(--navy);color:#fff;padding:9px;text-align:left;text-transform:uppercase;font-size:9px;white-space:normal;min-width:82px}td{padding:8px 9px;border-bottom:1px solid #EEF2F7;vertical-align:top;overflow-wrap:normal;word-break:normal;white-space:normal}.col-category,.col-state,.col-health,.col-effectivehealth,.col-grade,.col-port,.col-protocol,.col-requirement,.col-affectsgrade,.col-recommended,.col-severity,.col-green,.col-originalyellow,.col-waivedyellow,.col-remainingyellow,.col-originalred,.col-waivedred,.col-remainingred{white-space:nowrap;min-width:105px;width:1%}.col-source{min-width:190px;max-width:260px}.col-evidence,.col-detail,.col-reason,.col-error,.col-blockers{min-width:280px;max-width:620px}.col-domaincontroller,.col-hostname,.col-destination,.col-source{overflow-wrap:anywhere}.table-scroll{overflow-x:auto}tr:nth-child(even) td{background:#F8FBFF}.notice{background:#FFF8E1;border-left:4px solid var(--amber);padding:12px 16px}.health{display:inline-block;padding:5px 11px;border-radius:999px;font-weight:800;text-transform:uppercase}.health.green{background:#E2EFDA;color:#375623}.health.yellow{background:#FFF2CC;color:#7B3F00}.health.red{background:#F4CCCC;color:#C00000}.card.green{border-top-color:#548235}.card.yellow{border-top-color:#F4B942}.card.red{border-top-color:#C00000}.finding-red td{background:#FDE9E7!important}.finding-yellow td{background:#FFF8E1!important}.finding-green td{background:#ECF5E8!important}.grade{font-size:42px;font-weight:900}.links a{display:inline-block;margin:3px 14px 3px 0}footer{background:var(--navy);color:#ffffff88;text-align:center;padding:14px}@media(max-width:1350px){.cards{grid-template-columns:repeat(3,minmax(210px,1fr))}}@media(max-width:900px){.cards{grid-template-columns:repeat(2,minmax(210px,1fr))}}@media(max-width:560px){.cards{grid-template-columns:1fr}.value{white-space:normal}}
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
            Connectivity = @(Read-JsonDocument (Join-Path $destination 'forest-connectivity.json'))
            ReturnPath = @(Read-JsonDocument (Join-Path $destination 'forest-return-path.json'))
            DnsZones = @(Read-JsonDocument (Join-Path $destination 'dns-zones.json'))
        }
    }
    if ($packages.Count -eq 0) { throw 'No valid raw packages were found.' }

    $firstPackage = $packages[0]
    $domainData = $firstPackage.Domain
    $forestData = $firstPackage.Forest
    $allDomainControllers = @($firstPackage.DCs)
    $dcOutputDirectory = Join-Path $OutputDirectory 'LocalInventory'
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
        $dnsFile=Get-ChildItem -LiteralPath $analysisPackage.Path -Filter 'dcdiag-dns-*.txt' -File|Select-Object -First 1
        $dnsText=if($dnsFile){Get-Content -LiteralPath $dnsFile.FullName -Raw}else{''}
        $sysvol=Get-SysvolAssessment $analysisPackage.Local $analysisPackage.Path $scope
        $dcFindings=@();$dcFindings+=Test-DcdiagText $dcdiagLocal 'dcdiag-local-verbose.txt' $scope;$dcFindings+=Test-DcdiagText $dcdiagEnterprise 'dcdiag-enterprise-comprehensive-verbose.txt' $scope;$dcFindings+=Test-RepadminText $showRepl $replSummary $scope;$dcFindings+=Test-DnsText $dnsText $scope $(if($dnsFile){$dnsFile.Name}else{'dcdiag-dns'});$dcFindings+=@($sysvol.Findings);$dcFindings+=Get-EventFindings $analysisPackage.Events $scope
        $state=Get-WorstState $dcFindings;$dcAssessments+=[pscustomobject]@{ComputerName=$analysisPackage.Manifest.ComputerName;Fqdn=$scope;State=$state;Grade=(Get-GradeFromState $state);Sysvol=$sysvol;Findings=$dcFindings};$allFindings+=@($dcFindings)
    }
    $upgrade=Get-FunctionalLevelAnalysis $allDomainControllers ([string]$domainData.DomainMode) ([string]$forestData.ForestMode);$allFindings+=@($upgrade.Blockers2016)
    # Port classification is scoped to DC-to-DC health. Only baseline AD ports affect grade.
    # TCP 464, LDAPS, GC, and ADWS are reported as recommended/conditional observations.
    $requiredDcPorts=@(53,88,135,389,445)
    $recommendedDcPorts=@(464)
    $conditionalDcPorts=@(636,3268,3269,9389)
    foreach($evidencePackage in @($packages)){
        foreach($networkTest in @($evidencePackage.Connectivity)){
            if($null -eq $networkTest -or [string]::IsNullOrWhiteSpace([string]$networkTest.Destination)){continue}
            $isOpen=([string]$networkTest.Open -match '^(?i:true)$') -or ($networkTest.Open -eq $true)
            if(!$isOpen){
                $port=[int]$networkTest.Port
                if($port -in $requiredDcPorts){$allFindings+=New-Finding ([string]$networkTest.Destination) 'Connectivity' 'Red' ("Required TCP port {0} unavailable" -f $port) ("{0} to {1} timed out or was closed. {2}" -f $networkTest.Source,$networkTest.Destination,$networkTest.Error) 'forest-connectivity.json'}
                elseif($port -in $recommendedDcPorts){$allFindings+=New-Finding ([string]$networkTest.Destination) 'Connectivity' 'Yellow' ("Recommended TCP port {0} unavailable" -f $port) ("Kerberos password-change traffic uses TCP/UDP 464. This result is noteworthy but does not lower the grade as a core DC-replication failure. {0}" -f $networkTest.Error) 'forest-connectivity.json'}
                else{$allFindings+=New-Finding ([string]$networkTest.Destination) 'Connectivity' 'Yellow' ("Conditional TCP port {0} unavailable" -f $port) ("This service port is scenario-dependent and does not affect the grade unless the service is required by the customer design. {0}" -f $networkTest.Error) 'forest-connectivity.json'}
            }
        }
        foreach($reverseTest in @($evidencePackage.ReturnPath)){
            if($null -ne $reverseTest -and $reverseTest.RemoteExecution -ne 'Success' -and -not [string]::IsNullOrWhiteSpace([string]$reverseTest.Source)){$allFindings+=New-Finding ([string]$reverseTest.Source) 'Connectivity' 'Yellow' 'Return-path test not executed' ([string]$reverseTest.Error) 'forest-return-path.json'}
        }
    }
    # Deduplicate repeated symptoms collected from local, enterprise, and per-DC diagnostics.
    $allFindings=@($allFindings | Group-Object Category,State,Title,Detail | ForEach-Object {$_.Group | Select-Object -First 1})
    $rawFindings=@($allFindings);$waiverIndex=@{}
    if(-not[string]::IsNullOrWhiteSpace($WaiverPath)){if(-not(Test-Path -LiteralPath $WaiverPath -PathType Leaf)){throw "Waiver file not found: $WaiverPath"};foreach($w in @(Import-Csv -LiteralPath $WaiverPath)){if($w.FindingId){$waiverIndex[[string]$w.FindingId]=$w}}}
    $effectiveFindings=@();$waivedFindings=@();$waiverReviewRows=@();$now=Get-Date
    foreach($finding in $rawFindings){
      # Positive Green controls never affect grade and are intentionally excluded from waiver review.
      if($finding.State -eq 'Green'){$effectiveFindings+=$finding;continue}
      $decision=Get-WaiverDecision $finding $waiverIndex $now;$w=$decision.Record
      $waiverReviewRows+=[pscustomobject]@{FindingId=$decision.FindingId;Scope=$finding.Scope;Category=$finding.Category;OriginalState=$finding.State;Title=$finding.Title;Detail=$finding.Detail;Source=$finding.Source;Approved=if($w){$w.Approved}else{'False'};Approver=if($w){$w.Approver}else{''};ApprovedDate=if($w){$w.ApprovedDate}else{''};ExpirationDate=if($w){$w.ExpirationDate}else{''};Reason=if($w){$w.Reason}else{''};TicketOrChange=if($w){$w.TicketOrChange}else{''};WaiverStatus=$decision.Status}
      if($decision.Applied){$waivedFindings+=[pscustomobject]@{FindingId=$decision.FindingId;Scope=$finding.Scope;Category=$finding.Category;OriginalState=$finding.State;Title=$finding.Title;Detail=$finding.Detail;Source=$finding.Source;Approver=$w.Approver;ApprovedDate=$w.ApprovedDate;ExpirationDate=$w.ExpirationDate;Reason=$w.Reason;TicketOrChange=$w.TicketOrChange}}
      else{$effectiveFindings+=$finding}
    }
    $waiverReviewPath=Join-Path $OutputDirectory 'AD-Health-Waiver-Review.csv';$waiverReviewRows|Sort-Object @{Expression={if($_.OriginalState-eq'Red'){0}else{1}}},Category,Scope,Title|Export-Csv -LiteralPath $waiverReviewPath -NoTypeInformation -Encoding UTF8
    $rawForestState=Get-WorstState $rawFindings;$rawForestGrade=Get-GradeFromState $rawForestState
    $allFindings=@($effectiveFindings);$forestState=Get-WorstState $allFindings;$forestGrade=Get-GradeFromState $forestState

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
    $dnsPackageRows=@($packages|Where-Object{(@($_.Local.Services|Where-Object Name -eq 'DNS').Count-gt0)-or(@($_.Local.Features|Where-Object{[string]$_.Name-match'(?i)^DNS$|DNS-Server'}).Count-gt0)})
    $dnsTargets=@{};foreach($p in $packages){foreach($f in @(Get-ChildItem $p.Path -Filter 'dcdiag-dns-*.txt' -File -ErrorAction SilentlyContinue)){$n=$f.BaseName-replace'^dcdiag-dns-','';$dnsTargets[$n.ToLowerInvariant()]=$true}}
    $dnsRows=@();foreach($dnsDc in $allDomainControllers){$dnsHostName=[string]$dnsDc.HostName;if([string]::IsNullOrWhiteSpace($dnsHostName)){continue};$key=$dnsHostName.ToLowerInvariant();$short=($dnsHostName-split'\.')[0].ToLowerInvariant();$present=$dnsTargets.ContainsKey($key)-or$dnsTargets.ContainsKey($short);$dnsRows+=[pscustomobject]@{HostName=$dnsHostName;IPv4Address=$dnsDc.IPv4Address;Site=$dnsDc.Site;DnsServerPresent=$present;AssessmentBasis=if($present){'Per-DC DCDiag DNS evidence'}else{'No DNS evidence collected'}}};$dnsServerCount=@($dnsRows|Where-Object { $_.DnsServerPresent -eq $true }).Count
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
            "<div class='card'><div class='value long'>$(ConvertTo-HtmlEncoded $local.OS)</div><div class='label'>Operating System</div></div>" +
            "<div class='card'><div class='value long'>$(ConvertTo-HtmlEncoded $local.Site)</div><div class='label'>Site</div></div>" +
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
        $dcHtml = "<!doctype html><html><head><meta charset='utf-8'><title>$(ConvertTo-HtmlEncoded $local.Fqdn)</title><style>$Css</style></head><body><header><h1>Local Domain Controller Inventory</h1><div class='sub'>$(ConvertTo-HtmlEncoded $local.Fqdn)</div><div class='meta'><div><b>Collected</b>$(ConvertTo-HtmlEncoded $local.Collected)</div><div><b>Source ZIP</b>$(ConvertTo-HtmlEncoded $package.Zip.Name)</div></div></header><main class='page'>$body</main><footer>Active Directory Health Raw Collector and Report Generator Rev 2.3</footer></body></html>"
        $safeName = $computerName -replace '[^A-Za-z0-9._-]','_'
        Set-Content -LiteralPath (Join-Path $dcOutputDirectory ($safeName + '.html')) -Value $dcHtml -Encoding UTF8
    }

    $fsmoRows=@([pscustomobject]@{Role='Schema Master';Holder=$forestData.SchemaMaster},[pscustomobject]@{Role='Domain Naming Master';Holder=$forestData.DomainNamingMaster},[pscustomobject]@{Role='PDC Emulator';Holder=$domainData.PDCEmulator},[pscustomobject]@{Role='RID Master';Holder=$domainData.RIDMaster},[pscustomobject]@{Role='Infrastructure Master';Holder=$domainData.InfrastructureMaster})
    $gcRows=@($allDomainControllers|Where-Object{$_.IsGlobalCatalog -eq $true})
    $reachState=if($allDcReachable){'Green'}else{'Red'}
    $cards="<div class='cards'><div class='card $($forestState.ToLower())'><div class='value grade'>$forestGrade</div><div class='label'>Forest Health Grade</div></div><div class='card $($forestState.ToLower())'><div class='value'>$(New-HealthBadge $forestState $forestState)</div><div class='label'>Overall Health</div></div><div class='card'><div class='value'>$($allDomainControllers.Count)</div><div class='label'>Domain Controllers</div></div><div class='card'><div class='value'>$($gcRows.Count)</div><div class='label'>Global Catalogs</div></div><div class='card'><div class='value compact'>$(ConvertTo-HtmlEncoded $forestData.ForestMode)</div><div class='label'>Forest Functional Level</div></div><div class='card'><div class='value compact'>$(ConvertTo-HtmlEncoded $domainData.DomainMode)</div><div class='label'>Domain Functional Level</div></div><div class='card'><div class='value'>$dnsServerCount</div><div class='label'>DNS Servers Detected in Domain</div></div><div class='card $($reachState.ToLower())'><div class='value'>$(New-HealthBadge $reachState ([string]$allDcReachable))</div><div class='label'>All Domain Controllers Reachable</div></div></div>"
    $body=$cards
    $summaryRows=@($dcAssessments|ForEach-Object{[pscustomobject]@{DomainController=$_.Fqdn;Health=$_.State;Grade=$_.Grade;SYSVOLPublished=$_.Sysvol.SysvolPublished;NETLOGONPublished=$_.Sysvol.NetlogonPublished;DFSR=$_.Sysvol.DFSR;LegacyFRS=$_.Sysvol.LegacyFRS;SYSVOLPath=$_.Sysvol.SysvolPath}})
    $body+=New-HtmlSection 'Forest and Domain Health Assessment' (New-HtmlTable $summaryRows @('DomainController','Health','Grade','SYSVOLPublished','NETLOGONPublished','DFSR','LegacyFRS','SYSVOLPath'))
    $categoryRows=@()
    foreach($category in 'Replication','DNS','DCDiag','SYSVOL','Connectivity','Event Log'){
        $effectiveCategory=@($allFindings|Where-Object Category -eq $category)
        $rawCategory=@($rawFindings|Where-Object Category -eq $category)
        $waivedCategory=@($waivedFindings|Where-Object Category -eq $category)
        $effectiveYellow=@($effectiveCategory|Where-Object State -eq 'Yellow').Count
        $effectiveRed=@($effectiveCategory|Where-Object State -eq 'Red').Count
        $waivedYellow=@($waivedCategory|Where-Object OriginalState -eq 'Yellow').Count
        $waivedRed=@($waivedCategory|Where-Object OriginalState -eq 'Red').Count
        $categoryRows+=[pscustomobject]@{
            Category=$category
            EffectiveHealth=(Get-WorstState $effectiveCategory)
            Green=@($rawCategory|Where-Object State -eq 'Green').Count
            OriginalYellow=@($rawCategory|Where-Object State -eq 'Yellow').Count
            WaivedYellow=$waivedYellow
            RemainingYellow=$effectiveYellow
            OriginalRed=@($rawCategory|Where-Object State -eq 'Red').Count
            WaivedRed=$waivedRed
            RemainingRed=$effectiveRed
        }
    }
    $body+=New-HtmlSection 'Health by Diagnostic Category' (New-HtmlTable $categoryRows @('Category','EffectiveHealth','Green','OriginalYellow','WaivedYellow','RemainingYellow','OriginalRed','WaivedRed','RemainingRed'))
    $categoryNote="<div class='notice'><b>How to read this table:</b> Original Yellow and Original Red show all findings detected before waivers. Waived Yellow and Waived Red show approved findings removed from effective scoring. Remaining Yellow and Remaining Red show findings still affecting the effective category health and overall grade.</div>"
    $body+=New-HtmlSection 'Diagnostic Category Count Definitions' $categoryNote
    $positiveControls=@($rawFindings|Where-Object State -eq 'Green'|ForEach-Object{[pscustomobject]@{Scope=$_.Scope;Category=$_.Category;Result=$_.Title;Evidence=$_.Detail;Source=$_.Source}})
    $body+=New-HtmlSection 'Positive Health Controls' (New-HtmlTable $positiveControls @('Scope','Category','Result','Evidence','Source'))
    $whyGrade=@($categoryRows|Where-Object{$_.RemainingRed -gt 0}|ForEach-Object{[pscustomobject]@{Category=$_.Category;RedRootCauses=$_.RemainingRed;Explanation=switch($_.Category){'DNS'{'Actionable failed DNS tests, invalid forwarders, or missing registrations'};'DCDiag'{'Explicit DCDiag failed-test results only'};'Replication'{'Parsed non-zero Repadmin failure evidence'};'SYSVOL'{'SYSVOL, NETLOGON, or DFSR migration failure'};'Connectivity'{'Required AD TCP ports that were closed or timed out'};'Event Log'{'AD-impacting DNS, AD DS, or DFSR events only'};default{'Critical findings detected'}}}})
    $body+=New-HtmlSection 'Why This Grade' (New-HtmlTable $whyGrade @('Category','RedRootCauses','Explanation'))
    $body+=New-HtmlSection 'Approved Waivers Applied' (New-HtmlTable $waivedFindings @('FindingId','Scope','Category','OriginalState','Title','Approver','ApprovedDate','ExpirationDate','Reason','TicketOrChange'))
    $waiverInstructions="<div class='notice'><b>Waiver workflow:</b> AD-Health-Waiver-Review.csv contains only Yellow and Red findings. Green positive controls are excluded because they never lower the grade. Set Approved=True and complete Approver, ApprovedDate, and Reason, then rerun with -WaiverPath.</div>"
    $body+=New-HtmlSection 'Waiver Approval Workflow' $waiverInstructions
    $body+=New-HtmlSection 'Change Recommendations Based on Current Health' (New-HtmlTable $changeRecommendations @('ProposedChange','Recommended','RequiredHealth','Reason'))
    $body+=New-HtmlSection 'Domain Controller Availability and Reachability' (New-HtmlTable $availabilityRows @('HostName','IPv4Address','Enabled','Reachable','AssessmentBasis','CollectorPackage'))
    $body+=New-HtmlSection 'Domain Controllers Not Online or Reachable' (New-HtmlTable $unreachableRows @('HostName','IPv4Address','Enabled','Reachable','AssessmentBasis','CollectorPackage'))
    $body+=New-HtmlSection 'DNS Servers Detected in Domain' (New-HtmlTable $dnsRows @('HostName','IPv4Address','Site','DnsServerPresent','AssessmentBasis'))
    $upgradeSummary=@([pscustomobject]@{Target='Windows Server 2016';DomainEligible=$upgrade.Eligible2016;ForestEligible=$upgrade.Eligible2016;ImpactOnHealth='Yes, customer target';Blockers=if($upgrade.Eligible2016){'None'}else{(@($upgrade.Blockers2016.Title)-join'; ')}},[pscustomobject]@{Target='Windows Server 2025';DomainEligible=$upgrade.Eligible2025;ForestEligible=$upgrade.Eligible2025;ImpactOnHealth='No, future readiness only';Blockers=if($upgrade.Eligible2025){'None'}else{(@($upgrade.Blockers2025|ForEach-Object{$_.HostName+' - '+$_.Reason})-join'; ')}})
    $body+=New-HtmlSection 'Functional-Level Readiness by Target' (New-HtmlTable $upgradeSummary @('Target','DomainEligible','ForestEligible','ImpactOnHealth','Blockers'))
    $body+=New-HtmlSection 'Domain Controller Functional-Level Eligibility' (New-HtmlTable $upgrade.Rows @('HostName','OperatingSystem','EligibleFor2016','EligibleFor2025'))
    $body+=New-HtmlSection 'Domain Controllers' (New-HtmlTable $allDomainControllers @('HostName','IPv4Address','Site','OperatingSystem','OperatingSystemVersion','IsGlobalCatalog','IsReadOnly','Enabled'))
    $body+=New-HtmlSection 'FSMO Role Holders' (New-HtmlTable $fsmoRows @('Role','Holder'))
    $body+=New-HtmlSection 'Global Catalog Servers' (New-HtmlTable $gcRows @('HostName','IPv4Address','Site'))

    $changeBlockers=@($allFindings|Where-Object{$_.State -eq 'Red' -and $_.Category -in @('DNS','Replication','SYSVOL','DCDiag','Connectivity','Event Log','Functional Level')}|ForEach-Object{[pscustomobject]@{TargetChange='Windows Server 2016 domain and forest functional levels';Category=$_.Category;Blocker=$_.Title;Evidence=$_.Detail;Source=$_.Source}})
    if(!$upgrade.Eligible2016){$changeBlockers+=@($upgrade.Blockers2016|ForEach-Object{[pscustomobject]@{TargetChange='Windows Server 2016 domain and forest functional levels';Category='Operating System';Blocker=$_.Title;Evidence=$_.Detail;Source=$_.Source}})}
    $body+=New-HtmlSection 'Windows Server 2016 Change Blockers' (New-HtmlTable $changeBlockers @('TargetChange','Category','Blocker','Evidence','Source'))
    $validationGaps=@()
    $missingCollectors=@($allDomainControllers|Where-Object{$name=[string]$_.HostName;@($packages|Where-Object{$_.Manifest.ComputerFqdn -ieq $name}).Count -eq 0})
    if($missingCollectors.Count){$validationGaps+=[pscustomobject]@{Area='Local per-DC evidence';Status='Incomplete';Detail=("No local package for {0} of {1} DCs" -f $missingCollectors.Count,$allDomainControllers.Count)}}
    if(@($packages|Where-Object{@($_.DnsZones).Count -gt 0}).Count -eq 0){$validationGaps+=[pscustomobject]@{Area='DNS zone inventory';Status='Missing';Detail='No DNS zone inventory was available in the package'}}
    $body+=New-HtmlSection 'Validation Gaps' (New-HtmlTable $validationGaps @('Area','Status','Detail'))
    $redFindings=@($allFindings|Where-Object State -eq 'Red');$yellowFindings=@($allFindings|Where-Object State -eq 'Yellow')
    $body+=New-HtmlSection 'Red Findings Requiring Action' (New-HtmlTable $redFindings @('Scope','Category','State','Title','Detail','Source'))
    $body+=New-HtmlSection 'Yellow Findings Requiring Review' (New-HtmlTable $yellowFindings @('Scope','Category','State','Title','Detail','Source'))
    $packageRows=@($packages|ForEach-Object{[pscustomobject]@{ComputerName=$_.Manifest.ComputerName;ComputerFqdn=$_.Manifest.ComputerFqdn;CollectedUtc=$_.Manifest.CollectedUtc;OperatingSystem=$_.Manifest.OperatingSystem;Zip=$_.Zip.Name}})
    $connectivityRows=@()
    foreach($p in @($packages)){
        $records=@($p.Connectivity)
        if($records.Count -eq 0){$csvPath=Join-Path $p.Path 'forest-connectivity.csv';if(Test-Path $csvPath){$records=@(Import-Csv -LiteralPath $csvPath)}}
        foreach($record in $records){if($null -eq $record -or [string]::IsNullOrWhiteSpace([string]$record.Destination)){continue};$isOpen=([string]$record.Open -match '^(?i:true)$') -or ($record.Open -eq $true);$port=[int]$record.Port;$classification=if($port -in $requiredDcPorts){'Required'}elseif($port -in $recommendedDcPorts){'Recommended'}else{'Conditional'};$connectivityRows+=[pscustomobject]@{Source=$record.Source;Destination=$record.Destination;Site=$record.DestinationSite;Protocol='TCP';Port=$port;Requirement=$classification;AffectsGrade=($classification -eq 'Required');State=if($isOpen){'Open'}else{'Closed/Timeout'};LatencyMs=$record.LatencyMs;Error=$record.Error}}
    }
    $returnRows=@()
    foreach($p in @($packages)){foreach($r in @($p.ReturnPath)){if($null -eq $r -or [string]::IsNullOrWhiteSpace([string]$r.Source)){continue};if($r.RemoteExecution -eq 'Success'){foreach($x in @($r.Results)){if($null -eq $x){continue};$isOpen=([string]$x.Open -match '^(?i:true)$') -or ($x.Open -eq $true);$port=[int]$x.Port;$classification=if($port -in $requiredDcPorts){'Required'}elseif($port -in $recommendedDcPorts){'Recommended'}else{'Conditional'};$returnRows+=[pscustomobject]@{Source=$r.Source;Destination=$r.Destination;Protocol='TCP';Port=$port;Requirement=$classification;AffectsGrade=($classification -eq 'Required');State=if($isOpen){'Open'}else{'Closed/Timeout'};LatencyMs=$x.LatencyMs;Error=$x.Error}}}else{$returnRows+=[pscustomobject]@{Source=$r.Source;Destination=$r.Destination;Protocol='TCP';Port='Not tested';Requirement='Coverage';AffectsGrade=$false;State='Not Tested';LatencyMs='';Error=$r.Error}}}}
    $returnNotTestedCount=@($returnRows|Where-Object State -eq 'Not Tested').Count
    if($returnNotTestedCount -gt 0){$validationGaps+=[pscustomobject]@{Area='Return-path connectivity';Status='Incomplete';Detail=("$returnNotTestedCount remote source(s) could not execute the reverse test; this is not proof that AD ports are closed")}}
    $forwardSummary=@([pscustomobject]@{Metric='Destinations tested';Value=@($connectivityRows.Destination|Sort-Object -Unique).Count},[pscustomobject]@{Metric='TCP port tests';Value=$connectivityRows.Count},[pscustomobject]@{Metric='Open';Value=@($connectivityRows|Where-Object State -eq 'Open').Count},[pscustomobject]@{Metric='Required ports closed or timed out';Value=@($connectivityRows|Where-Object{$_.State -eq 'Closed/Timeout' -and $_.Requirement -eq 'Required'}).Count},[pscustomobject]@{Metric='Recommended or conditional ports closed or timed out';Value=@($connectivityRows|Where-Object{$_.State -eq 'Closed/Timeout' -and $_.Requirement -ne 'Required'}).Count})
    $returnSummary=@([pscustomobject]@{Metric='Successful port tests';Value=@($returnRows|Where-Object State -eq 'Open').Count},[pscustomobject]@{Metric='Closed or timed out';Value=@($returnRows|Where-Object State -eq 'Closed/Timeout').Count},[pscustomobject]@{Metric='Sources not tested';Value=@($returnRows|Where-Object State -eq 'Not Tested').Count})
    $portPolicyRows=@(
        [pscustomobject]@{Protocol='TCP/UDP';Port='53';Service='DNS';Requirement='Required';AffectsGrade='Yes'},
        [pscustomobject]@{Protocol='TCP/UDP';Port='88';Service='Kerberos';Requirement='Required';AffectsGrade='Yes'},
        [pscustomobject]@{Protocol='TCP';Port='135';Service='RPC Endpoint Mapper';Requirement='Required';AffectsGrade='Yes'},
        [pscustomobject]@{Protocol='TCP/UDP';Port='389';Service='LDAP';Requirement='Required';AffectsGrade='Yes'},
        [pscustomobject]@{Protocol='TCP';Port='445';Service='SMB/SYSVOL';Requirement='Required';AffectsGrade='Yes'},
        [pscustomobject]@{Protocol='TCP';Port='49152-65535';Service='Dynamic RPC';Requirement='Required';AffectsGrade='Validated through RPC/replication diagnostics, not by scanning every port'},
        [pscustomobject]@{Protocol='TCP/UDP';Port='464';Service='Kerberos password change';Requirement='Recommended';AffectsGrade='No'},
        [pscustomobject]@{Protocol='TCP';Port='636';Service='LDAPS';Requirement='Conditional';AffectsGrade='No'},
        [pscustomobject]@{Protocol='TCP';Port='3268';Service='Global Catalog';Requirement='Conditional';AffectsGrade='No'},
        [pscustomobject]@{Protocol='TCP';Port='3269';Service='Global Catalog over TLS';Requirement='Conditional';AffectsGrade='No'},
        [pscustomobject]@{Protocol='TCP';Port='9389';Service='Active Directory Web Services';Requirement='Conditional';AffectsGrade='No'}
    )
    $body+=New-HtmlSection 'Domain Controller Connectivity Port Policy' (New-HtmlTable $portPolicyRows @('Protocol','Port','Service','Requirement','AffectsGrade'))
    $body+=New-HtmlSection 'Forest Connectivity Summary: Collector to Domain Controllers' (New-HtmlTable $forwardSummary @('Metric','Value'))
    $body+=New-HtmlSection 'Forest Connectivity: Collector to Domain Controllers' (New-HtmlTable $connectivityRows @('Source','Destination','Site','Protocol','Port','Requirement','AffectsGrade','State','LatencyMs','Error'))
    $body+=New-HtmlSection 'Forest Connectivity Summary: Return Path to Collector' (New-HtmlTable $returnSummary @('Metric','Value'))
    $body+=New-HtmlSection 'Forest Connectivity: Return Path to Collector' (New-HtmlTable $returnRows @('Source','Destination','Protocol','Port','Requirement','AffectsGrade','State','LatencyMs','Error'))
    $dnsIssueRows=Get-DnsIssueRows $packages;$body+=New-HtmlSection 'DNS Diagnostic Issues' (New-HtmlTable $dnsIssueRows @('DomainController','Severity','Issue','Source'))
    $zoneRows=@();foreach($p in @($packages)){foreach($z in @($p.DnsZones)){if($null-ne$z -and -not [string]::IsNullOrWhiteSpace([string]$z.ZoneName)){$zoneRows+=$z}}};$body+=New-HtmlSection 'DNS Zones' (New-HtmlTable $zoneRows @('ZoneName','ZoneType','IsDsIntegrated','IsReverseLookupZone','DynamicUpdate','ReplicationScope','IsPaused','IsShutdown'))
    $timeRows=Get-TimeRows $packages;$body+=New-HtmlSection 'Time Synchronization' (New-HtmlTable $timeRows @('DomainController','TimeSource','ConfiguredPeers','Type','LastSuccessfulSync','Stratum','ReferenceId','RootDelay','RootDispersion','ForestMonitor'))
    $body+=New-HtmlSection 'Collected Packages' (New-HtmlTable $packageRows @('ComputerName','ComputerFqdn','CollectedUtc','OperatingSystem','Zip'))
    $missing=@($allDomainControllers|Where-Object{$dcHostName=$_.HostName;@($packages|Where-Object{$_.Manifest.ComputerFqdn -ieq $dcHostName}).Count -eq 0});if($missing.Count){$body+=New-HtmlSection 'Collection Coverage Warning' ("<div class='notice'>No local collector package was provided for: $(ConvertTo-HtmlEncoded (($missing.HostName)-join ', ')). Health grading is incomplete until every DC package is supplied.</div>")}
    $reportHtml="<!doctype html><html><head><meta charset='utf-8'><title>AD Health - $(ConvertTo-HtmlEncoded $domainData.Name)</title><style>$Css</style></head><body><header><h1>Active Directory Forest and Domain Health Assessment</h1><div class='sub'>$(ConvertTo-HtmlEncoded $domainData.Name)</div><div class='meta'><div><b>Generated</b>$(Get-Date)</div><div><b>Packages</b>$($packages.Count)</div><div><b>Effective Health</b>$forestState / Grade $forestGrade</div><div><b>Raw Health</b>$rawForestState / Grade $rawForestGrade</div><div><b>Waivers</b>$($waivedFindings.Count)</div></div></header><main class='page'>$body</main><footer>Active Directory Health Raw Collector and Report Generator Rev 2.3</footer></body></html>"
    $reportPath=Join-Path $OutputDirectory 'Active-Directory-Consolidated-Report.html';Set-Content -LiteralPath $reportPath -Value $reportHtml -Encoding UTF8;Write-Host "Report created: $reportPath" -ForegroundColor Green;Write-Host "Waiver review file: $waiverReviewPath" -ForegroundColor Cyan
}
finally {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
}
