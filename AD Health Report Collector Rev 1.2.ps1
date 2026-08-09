<#
.SYNOPSIS
Active Directory Health Report Collector Rev 1.2 for Windows PowerShell 3.0+.
.DESCRIPTION
Run locally and elevated on one domain controller per domain. Collects local and forest-wide evidence,
forest/domain inventory, event logs, DCDiag, Repadmin, SYSVOL/DFSR state, roles,
services, software, and network data. Creates a ZIP for offline reporting.
#>
[CmdletBinding()]
param(
 [string]$OutputDirectory=(Join-Path $env:SystemDrive 'AD-Health-Exports'),
 [int]$EventLookbackDays=7,
 [switch]$SkipComprehensiveDcdiag,
 [switch]$SkipRemotePerspective,
 [int]$TcpTimeoutMilliseconds=1500,
 [switch]$KeepWorkingDirectory
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$CollectorVersion='1.2'
$ManualInstallUrl='https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools'
function Write-Log([string]$Message,[string]$Level='INFO'){$line='{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'),$Level,$Message;Write-Host $line;if($script:LogFile){Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8}}
function Test-Administrator{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id);$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
function Ensure-AdTools{
 Write-Log 'Checking Active Directory PowerShell and native diagnostic prerequisites.'
 $missing=@();if(-not(Get-Module -ListAvailable ActiveDirectory)){$missing+='ActiveDirectory module'};if(-not(Get-Command dcdiag.exe -ErrorAction SilentlyContinue)){$missing+='dcdiag.exe'};if(-not(Get-Command repadmin.exe -ErrorAction SilentlyContinue)){$missing+='repadmin.exe'}
 if($missing.Count){Write-Log ('Missing: '+($missing-join', ')) WARN;try{Import-Module ServerManager -ErrorAction Stop;foreach($f in 'RSAT-AD-PowerShell','RSAT-ADDS'){$x=Get-WindowsFeature $f -ErrorAction SilentlyContinue;if($x-and-not$x.Installed){Install-WindowsFeature $f -IncludeManagementTools -ErrorAction Stop|Out-Null}}}catch{Write-Log ('Automatic prerequisite installation failed: '+$_.Exception.Message) ERROR;Write-Host $ManualInstallUrl -ForegroundColor Cyan;throw 'Install AD DS and AD LDS Tools manually, then rerun.'}}
 Import-Module ActiveDirectory -ErrorAction Stop;foreach($c in 'dcdiag.exe','repadmin.exe'){if(-not(Get-Command $c -ErrorAction SilentlyContinue)){Write-Host $ManualInstallUrl -ForegroundColor Cyan;throw "$c is unavailable."}};Write-Log 'Prerequisite check passed.'
}
function Save-Json($Object,[string]$Path,[int]$Depth=10){$Object|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8}
function Invoke-NativeToFile([string]$File,[string[]]$Arguments,[string]$OutputPath,[int]$TimeoutSeconds=900){
 $so=$OutputPath+'.out.tmp';$se=$OutputPath+'.err.tmp';try{Write-Log ("Running: $File "+($Arguments-join' '));$p=Start-Process $File -ArgumentList $Arguments -RedirectStandardOutput $so -RedirectStandardError $se -PassThru -WindowStyle Hidden;$done=$p.WaitForExit($TimeoutSeconds*1000);if(-not$done){Write-Log "$File timed out after $TimeoutSeconds seconds; terminating." WARN;try{$p.Kill()}catch{};Start-Sleep 2};$o=if(Test-Path $so){Get-Content $so -Raw -ErrorAction SilentlyContinue}else{''};$e=if(Test-Path $se){Get-Content $se -Raw -ErrorAction SilentlyContinue}else{''};@("Command: $File $($Arguments-join' ')","Completed: $done","ExitCode: $(if($done){$p.ExitCode}else{'TIMEOUT'})",'','===== STANDARD OUTPUT =====',$o,'','===== STANDARD ERROR =====',$e)|Set-Content $OutputPath -Encoding UTF8;[pscustomobject]@{Command=$File;Arguments=($Arguments-join' ');Completed=$done;ExitCode=if($done){$p.ExitCode}else{$null};OutputFile=(Split-Path $OutputPath -Leaf)}}finally{Remove-Item $so,$se -Force -ErrorAction SilentlyContinue}
}
function Get-Software{$r=@();foreach($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'){$r+=Get-ItemProperty $k -ErrorAction SilentlyContinue|Where-Object DisplayName|Select-Object DisplayName,DisplayVersion,Publisher,InstallDate};$r|Sort-Object DisplayName,DisplayVersion -Unique}
function Get-Network{Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'|ForEach-Object{[pscustomobject]@{Description=$_.Description;MACAddress=$_.MACAddress;IPAddress=@($_.IPAddress);IPSubnet=@($_.IPSubnet);DefaultGateway=@($_.DefaultIPGateway);DNSServers=@($_.DNSServerSearchOrder);DNSDomain=$_.DNSDomain;DHCPEnabled=$_.DHCPEnabled}}}
function Compress-Directory([string]$Source,[string]$Destination){Add-Type -AssemblyName System.IO.Compression.FileSystem;if(Test-Path $Destination){Remove-Item $Destination -Force};[IO.Compression.ZipFile]::CreateFromDirectory($Source,$Destination,[IO.Compression.CompressionLevel]::Optimal,$false)}
function Test-TcpEndpoint {
 param([string]$ComputerName,[int]$Port,[int]$TimeoutMilliseconds=1500)
 $client=New-Object System.Net.Sockets.TcpClient;$watch=[Diagnostics.Stopwatch]::StartNew()
 try{$async=$client.BeginConnect($ComputerName,$Port,$null,$null);$ok=$async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds,$false);if(!$ok){return [pscustomobject]@{Open=$false;LatencyMs=$TimeoutMilliseconds;Error='Timeout'}};$client.EndConnect($async);[pscustomobject]@{Open=$true;LatencyMs=$watch.ElapsedMilliseconds;Error=''}}catch{[pscustomobject]@{Open=$false;LatencyMs=$watch.ElapsedMilliseconds;Error=$_.Exception.Message}}finally{$watch.Stop();$client.Close()}
}
function Get-AddressText([string]$Name){try{return @([Net.Dns]::GetHostAddresses($Name)|ForEach-Object{$_.IPAddressToString}) -join '; '}catch{return ''}}
function Invoke-RemoteReturnPathTest {
 param([string]$RemoteDc,[string]$CollectorFqdn,[int[]]$Ports,[int]$TimeoutMilliseconds)
 if($SkipRemotePerspective){return [pscustomobject]@{Source=$RemoteDc;Destination=$CollectorFqdn;RemoteExecution='Skipped';Results=@();Error='Skipped by parameter'}}
 try{
  $result=Invoke-Command -ComputerName $RemoteDc -ErrorAction Stop -ScriptBlock {
   param($Target,$PortList,$Timeout)
   $rows=@();foreach($port in $PortList){$c=New-Object Net.Sockets.TcpClient;$sw=[Diagnostics.Stopwatch]::StartNew();try{$a=$c.BeginConnect($Target,$port,$null,$null);$ok=$a.AsyncWaitHandle.WaitOne($Timeout,$false);if($ok){$c.EndConnect($a)};$rows+=[pscustomobject]@{Port=$port;Open=[bool]$ok;LatencyMs=$sw.ElapsedMilliseconds;Error=if($ok){''}else{'Timeout'}}}catch{$rows+=[pscustomobject]@{Port=$port;Open=$false;LatencyMs=$sw.ElapsedMilliseconds;Error=$_.Exception.Message}}finally{$sw.Stop();$c.Close()}};$rows
  } -ArgumentList $CollectorFqdn,$Ports,$TimeoutMilliseconds
  return [pscustomobject]@{Source=$RemoteDc;Destination=$CollectorFqdn;RemoteExecution='Success';Results=@($result);Error=''}
 }catch{return [pscustomobject]@{Source=$RemoteDc;Destination=$CollectorFqdn;RemoteExecution='Unavailable';Results=@();Error=$_.Exception.Message}}
}

if(-not(Test-Administrator)){throw 'Run Windows PowerShell as Administrator.'};if($PSVersionTable.PSVersion.Major-lt3){throw 'Windows PowerShell 3.0 or later is required.'}
New-Item -ItemType Directory $OutputDirectory -Force|Out-Null;$stamp=Get-Date -Format yyyyMMdd-HHmmss;$computer=$env:COMPUTERNAME;$work=Join-Path $OutputDirectory "AD-Health-Raw-$computer-$stamp";New-Item -ItemType Directory $work -Force|Out-Null;$script:LogFile=Join-Path $work collector.log
try{
 Write-Log "Collector v$CollectorVersion started on $computer using Windows PowerShell $($PSVersionTable.PSVersion).";Ensure-AdTools
 $localDc=Get-ADDomainController -Identity $computer;$domain=Get-ADDomain -Server $localDc.HostName;$forest=Get-ADForest -Server $localDc.HostName;$dcs=@(Get-ADDomainController -Filter * -Server $localDc.HostName)
 Save-Json ([pscustomobject]@{Name=$domain.DNSRoot;NetBIOSName=$domain.NetBIOSName;DistinguishedName=$domain.DistinguishedName;DomainMode=[string]$domain.DomainMode;PDCEmulator=$domain.PDCEmulator;RIDMaster=$domain.RIDMaster;InfrastructureMaster=$domain.InfrastructureMaster}) (Join-Path $work domain.json)
 Save-Json ([pscustomobject]@{Name=$forest.Name;RootDomain=$forest.RootDomain;ForestMode=[string]$forest.ForestMode;SchemaMaster=$forest.SchemaMaster;DomainNamingMaster=$forest.DomainNamingMaster;Domains=@($forest.Domains);GlobalCatalogs=@($forest.GlobalCatalogs);Sites=@($forest.Sites)}) (Join-Path $work forest.json)
 $dcData=@($dcs|ForEach-Object{[pscustomobject]@{HostName=$_.HostName;IPv4Address=[string]$_.IPv4Address;Site=$_.Site;OperatingSystem=$_.OperatingSystem;OperatingSystemVersion=$_.OperatingSystemVersion;IsGlobalCatalog=$_.IsGlobalCatalog;IsReadOnly=$_.IsReadOnly;Enabled=$_.Enabled;Reachable=[bool](Test-Connection $_.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue)}});Save-Json $dcData (Join-Path $work domain-controllers.json)
 $os=Get-WmiObject Win32_OperatingSystem;$cs=Get-WmiObject Win32_ComputerSystem;$features=@();try{Import-Module ServerManager -ErrorAction Stop;$features=@(Get-WindowsFeature -ErrorAction Stop|Where-Object{$_.Installed-eq$true}|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;DisplayName=[string]$_.DisplayName;InstallState=[string]$_.InstallState}});Write-Log "Windows role and feature inventory completed through ServerManager. Installed items: $($features.Count)."}catch{Write-Log ('ServerManager feature inventory failed: '+$_.Exception.Message+'. Attempting DISM fallback.') WARN;$dism=& dism.exe /Online /Get-Features /Format:Table 2>&1;$features=@($dism|ForEach-Object{if($_-match '^\s*([^|]+?)\s*\|\s*Enabled\s*$'){[pscustomobject]@{Name=$Matches[1].Trim();DisplayName=$Matches[1].Trim();InstallState='Installed'}}}|Where-Object{$_});Write-Log "Windows feature inventory completed through DISM fallback. Enabled items: $($features.Count)."}
 $local=[pscustomobject]@{ComputerName=$computer;Fqdn=$localDc.HostName;Site=$localDc.Site;Collected=(Get-Date).ToString('o');OS=$os.Caption;Version=$os.Version;Build=$os.BuildNumber;Architecture=$os.OSArchitecture;Manufacturer=$cs.Manufacturer;Model=$cs.Model;Domain=$cs.Domain;IsGlobalCatalog=$localDc.IsGlobalCatalog;IsReadOnly=$localDc.IsReadOnly;Features=$features;Services=@(Get-WmiObject Win32_Service|Select-Object Name,DisplayName,State,StartMode,StartName);Software=@(Get-Software);Network=@(Get-Network);Shares=@(Get-WmiObject Win32_Share|Where-Object{$_.Name-in'SYSVOL','NETLOGON'}|Select-Object Name,Path,Status)};Save-Json $local (Join-Path $work local-inventory.json)
 ipconfig /all|Set-Content (Join-Path $work ipconfig-all.txt) -Encoding UTF8;w32tm /query /status|Set-Content (Join-Path $work w32tm-status.txt) -Encoding UTF8;w32tm /query /configuration|Set-Content (Join-Path $work w32tm-configuration.txt) -Encoding UTF8;dfsrmig /getglobalstate|Set-Content (Join-Path $work dfsrmig-global-state.txt) -Encoding UTF8;dfsrmig /getmigrationstate|Set-Content (Join-Path $work dfsrmig-migration-state.txt) -Encoding UTF8
 $since=(Get-Date).AddDays(-$EventLookbackDays);$events=@();foreach($log in 'Directory Service','DNS Server','DFS Replication','System'){if(-not(Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue)){Write-Log "Event log '$log' is not registered." INFO;continue};$le=@(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$since;Level=1,2,3} -ErrorAction SilentlyContinue);if(!$le.Count){Write-Log "Event collection for ${log}: zero matching Critical, Error, or Warning events in the last $EventLookbackDays day(s)." INFO}else{$events+=@($le|Select-Object @{n='LogName';e={$log}},TimeCreated,Id,LevelDisplayName,ProviderName,Message);Write-Log "Event collection for ${log}: $($le.Count) matching event(s)."}};Save-Json $events (Join-Path $work events.json) 6
 # Forest-wide connectivity evidence from the collector DC to every discovered DC.
 $adPorts=@(53,88,135,389,445,464,636,3268,3269,9389)
 $connectivity=@();$returnPath=@();$targetedRepadmin=@();$targetedDcdiag=@()
 foreach($dc in $dcs){
  $target=[string]$dc.HostName;Write-Log "Testing DNS, ICMP, and AD TCP ports to $target."
  $resolved=Get-AddressText $target;$icmp=[bool](Test-Connection $target -Count 1 -Quiet -ErrorAction SilentlyContinue)
  foreach($port in $adPorts){$test=Test-TcpEndpoint $target $port $TcpTimeoutMilliseconds;$connectivity+=[pscustomobject]@{Source=$localDc.HostName;Destination=$target;DestinationSite=[string]$dc.Site;ResolvedAddresses=$resolved;IcmpReachable=$icmp;Port=$port;Open=$test.Open;LatencyMs=$test.LatencyMs;Error=$test.Error}}
  if($target -ine $localDc.HostName){$returnPath+=Invoke-RemoteReturnPathTest $target $localDc.HostName $adPorts $TcpTimeoutMilliseconds}
  $safe=($target-replace'[^A-Za-z0-9._-]','_')
  $targetedRepadmin+=Invoke-NativeToFile repadmin.exe @('/showrepl',$target,'/csv') (Join-Path $work "repadmin-showrepl-$safe.csv.txt") 300
  $targetedDcdiag+=Invoke-NativeToFile dcdiag.exe @('/test:Connectivity','/s:'+$target,'/v') (Join-Path $work "dcdiag-connectivity-$safe.txt") 300
 }
 Save-Json $connectivity (Join-Path $work 'forest-connectivity.json') 8
 Save-Json $returnPath (Join-Path $work 'forest-return-path.json') 10
 $connectivity|Export-Csv -LiteralPath (Join-Path $work 'forest-connectivity.csv') -NoTypeInformation -Encoding UTF8
 $native=@();$native+=Invoke-NativeToFile repadmin.exe @('/showrepl','*','/csv') (Join-Path $work repadmin-showrepl-all.csv.txt) 600;$native+=Invoke-NativeToFile repadmin.exe @('/replsummary') (Join-Path $work repadmin-replsummary.txt) 600;$native+=Invoke-NativeToFile repadmin.exe @('/queue','*') (Join-Path $work repadmin-queue.txt) 600;$native+=Invoke-NativeToFile dcdiag.exe @('/v',('/s:'+$computer)) (Join-Path $work dcdiag-local-verbose.txt) 900;if(-not$SkipComprehensiveDcdiag){$native+=Invoke-NativeToFile dcdiag.exe @('/v','/c','/e') (Join-Path $work dcdiag-enterprise-comprehensive-verbose.txt) 1800};$dnsTests=@();foreach($dc in $dcs){$dnsTests+=Invoke-NativeToFile dcdiag.exe @('/test:DNS','/v',('/s:'+$dc.HostName)) (Join-Path $work ("dcdiag-dns-"+($dc.HostName-replace'[^A-Za-z0-9._-]','_')+'.txt')) 600}
 foreach($f in Get-ChildItem $work -File|Where-Object Name -match '^(dcdiag|repadmin)'){if($f.Length-lt40){Write-Log "Evidence file is unexpectedly small: $($f.Name) ($($f.Length) bytes)." WARN}else{Write-Log "Evidence saved: $($f.Name) ($($f.Length) bytes)."}}
 Save-Json ([pscustomobject]@{SchemaVersion='2.0';CollectorVersion=$CollectorVersion;ComputerName=$computer;ComputerFqdn=$localDc.HostName;Domain=$domain.DNSRoot;Forest=$forest.Name;CollectedUtc=(Get-Date).ToUniversalTime().ToString('o');PowerShellVersion=[string]$PSVersionTable.PSVersion;OperatingSystem=$os.Caption;EventLookbackDays=$EventLookbackDays;NativeCommands=$native;DnsTests=$dnsTests;TargetedRepadmin=$targetedRepadmin;TargetedDcdiagConnectivity=$targetedDcdiag;ConnectivityPorts=$adPorts;RemotePerspectiveAttempted=(-not $SkipRemotePerspective)}) (Join-Path $work manifest.json)
 $zip=Join-Path $OutputDirectory "AD-Health-Raw-$computer-$stamp.zip";Compress-Directory $work $zip;Write-Log "Collection complete. ZIP: $zip";Write-Host "`nCompleted: $zip" -ForegroundColor Green
}finally{if(-not$KeepWorkingDirectory -and $work -and(Test-Path $work)){Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue}}
