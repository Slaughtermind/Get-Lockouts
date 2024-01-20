<#
.SYNOPSIS
Check users details in all domain controllers, force unlock.
Display basic lockout information, modify time, last logon, password set, etc.

.DESCRIPTION
Input username or a list of users from text file.
By default the script requires username as an input if no switch is specified.
Switch "-Export" always appends to existing file.

.Link
https://ps-solutions.net/index.php/lockouts/

.EXAMPLE
#
## Universal switch combination, allowed in any circumstances:

	-User <username> -Export <file.txt> -Credential <domain/user:password>
	-Credential <domain/user:password> # type password in plain text
	-Credential <domain/user> # prompts a window for secure type

===============================================================================

## Valid combination of the switches:
	
	### No switch specified - print or export all lockout events
	-User <user name> ## Not mandatory. Leave blank to print or export all lockout events
	-LocalHost	## get logs from this computer
	-ComputerName <computer name>		## get logs from specified computer
	-Server <computer name>		## the same as: -ComputerName
	-PDC	## get logs from the PDC in the current domain
	-Domain <domain.name>	## get logs from the PDC in specified domain
	-AllDomainControllers	## get logs from all servers in current domain
	-Domain <domain.name> -AllDomainControllers	## get logs from all servers in specified domain

.EXAMPLE
#
.\Lockouts.ps1 -User H24934 -LocalHost
.\Lockouts.ps1 H24934 -Server dcprod01
.\Lockouts.ps1 H24934 -PDC -Credential domain\user
.\Lockouts.ps1 H24934 -Domain prod.net -Credential domain\user:password
.\Lockouts.ps1 -Domain dev.net -Export Results.txt
#>

[cmdletbinding()]
Param(
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$User,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$LocalHost,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string][Alias("ComputerName")]$Server,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$Domain,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$PDC,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$AllDomainControllers,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$Export,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$Credential
)

$Valid = ([int]$LocalHost.IsPresent + [int]($PDC.IsPresent -or $Domain -ne "" -or $AllDomainControllers.IsPresent) +
			[int]($PDC.IsPresent -and $AllDomainControllers.IsPresent) + [int]($Server -ne ""))

if ($Valid -ne 1) {
	Write-Host "`nInvalid switch combination. For details type: Get-Help .\Lockouts.ps1 -Examples `n" -ForegroundColor Red
	Exit
}

if ($Credential -ne "") {
	if (($Credential.IndexOf(":") -gt 0) -and ($Credential.IndexOf(":") -ne $Credential.Length - 1)) {
		$SecurePassword = ConvertTo-SecureString $Credential.Substring($Credential.IndexOf(":") + 1) -AsPlainText -Force
		$SecureUsername = $Credential.Substring(0, $Credential.IndexOf(":"))
		$Creds = New-Object System.Management.Automation.PSCredential -ArgumentList $SecureUsername, $SecurePassword
	}
	else { $Creds = $Host.ui.PromptForCredential("Credentials required!", "`r`nInput credentials for server/domain:`r`n" + $Server, $Credential, "") }
}

if ($Export -eq "") { $OutFile = $False } else { $OutFile = $True}

$StartTime = Get-Date
$Output = "`r`nStart Time: " + $StartTime.ToString("dd'/'MM'/'yyyy HH:mm:ss")
Write-Host $Output
if ($OutFile) { $Output >> $Export }

Function EndScript ($StartTime) {
	$EndtTime = Get-Date
	$Output = "`r`nEnd Time: " + $EndtTime.ToString("dd'/'MM'/'yyyy HH:mm:ss")
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }

	$TotalTime = $EndtTime - $StartTime
	# $Output = "Execution time: " + ($EndtTime - $StartTime).ToString().Split(".")[0] + " ###`r`n"
	$Output = "Execution time: " + $TotalTime.Days + "d " + $TotalTime.Hours.ToString("00:") + $TotalTime.Minutes.ToString("00:") + $TotalTime.Seconds.ToString("00") + "`r`n"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	Exit
}

if ($LocalHost.IsPresent) { $Server = $env:COMPUTERNAME }
if ($Domain -eq "" -and ($PDC.IsPresent -or $AllDomainControllers.IsPresent)) { $Domain = $env:USERDNSDOMAIN }

if ($Domain -ne "") {
	Write-Host "`r`nGet information about domain $Domain."
	
	Try { Import-Module ActiveDirectory } Catch { Write-Host $_ -ForegroundColor Red; Exit}
	
	<#
	$global:i = 1
	if ($Credential -eq "") { Try { $ServersInfo = Get-ADDomainController -Server $Domain -Filter * | Select-Object @{Name="No."; Expression={$global:i; $global:i++}}, HostName, IsReadOnly, OperatingSystem, Site | Format-Table -AutoSize } Catch {}}
	else { Try { $ServersInfo = Get-ADDomainController -Server $Domain -Credential $Creds -Filter * | Select-Object @{Name="No."; Expression={$global:i; $global:i++}}, HostName, IsReadOnly, OperatingSystem, Site | Format-Table -AutoSize } Catch {}}
	$ServersInfo
	if ($OutFile) { $ServersInfo >> $Export }
	#>
	
	$Error.Clear()
	if ($Credential -eq "") { Try { $DomainInfo = Get-ADDomain -Server $Domain } Catch {}}
	else { Try { $DomainInfo = Get-ADDomain -Server $Domain -Credential $Creds } Catch {}}
	
	$dcs = $DomainInfo.ReplicaDirectoryServers
	$Rdcs = $DomainInfo.ReadOnlyReplicaDirectoryServers
	$Server = $DomainInfo.PDCEmulator
	$PrimaryDC = $DomainInfo.PDCEmulator
	#Write-Host ("DNSRoot: " + $DomainInfo.DNSRoot)
	#Write-Host ("NetBios: " + $DomainInfo.NetBIOSName + "`r`n")
	
	if (-not [string]::IsNullOrEmpty($Error)) {
		$Output = "`r`n" + $Error + "`r`n"
		Write-Host $Output -ForegroundColor Red
		if ($OutFile) { $Output >> $Export }
		EndScript $StartTime
	}
}

if ($AllDomainControllers.IsPresent) { $Servers = $dcs + $Rdcs }
else { $Servers = $Server }
$s = 1

foreach ($Server in $Servers) {
	$Line = "`r`nProcessing " + $s++ + " of " + ($Servers | Measure-Object).Count + " :: "
	Write-Host $Line -NoNewLine
	
	if ($PrimaryDC -eq $Server) {
		$Output = "Get events from PDC: $Server"
		Write-Host $Output -ForegroundColor Green
		if ($OutFile) { $Line + $Output >> $Export }
	}
	elseif ($dcs -like $Server) {
		$Output = "Get events from DC: $Server"
		Write-Host $Output
		if ($OutFile) { $Line + $Output >> $Export }
	}
	elseif ($Rdcs -like $Server ) {
		$Output = "Get events from Read Only DC: $Server"
		Write-Host $Output -ForegroundColor Yellow
		if ($OutFile) { $Line + $Output >> $Export }
	}
	else {
		$Output = "Get events from computer: $Server"
		Write-Host $Output
		if ($OutFile) { $Line + $Output >> $Export }
	}
	
	$Error.Clear()
	if ($Credential -eq "") { Try { $Events = Get-WinEvent -ComputerName $Server -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop }	Catch {}}
	else { Try { $Events = Get-WinEvent -ComputerName $Server -Credential $Creds -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop } Catch {}}
	
	if (-not [string]::IsNullOrEmpty($Error)) {
		if ($Error -like "*events were found*") {
			$Output = "There are no Security Events with ID 4740 on computer: $Server `r`n"
			Write-Host $Output -ForegroundColor Yellow
			if ($OutFile) { $Output >> $Export }
		}
		else {
			$Output = [String]$Error + "`r`n"
			Write-Host $Output -ForegroundColor Red
			if ($OutFile) { $Output >> $Export }
		}
		Continue
	}
	else {
		
		if ($User -eq "") {
			$n = ($Events | Measure-Object).Count
			$global:i = 1
			
			$Output = $Events | Sort-Object -Property @{Expression={$_.Properties[0].Value}; Ascending=1}, @{Expression={$_.TimeCreated}; Ascending=0} | `
			Select-Object @{Name="N=$n"; Expression={$global:i; $global:i++}}, `
			@{Name="User name`t"; Expression={$_.Properties[5].Value + "\" + $_.Properties[0].Value}}, @{Name="Lockout Location`t"; Expression={$_.Properties[1].Value}}, `
			@{Name="Lockout date and time"; Expression={$_.TimeCreated.ToString("dd'/'MM'/'yyyy HH:mm:ss")}} | Format-Table -AutoSize
			
			$Output
			if ($OutFile) { $Output >> $Export }
		}
		else {
			$UserEvents = $Events | Where-Object {$_.Properties[0].Value -eq $User}
			$n = ($UserEvents | Measure-Object).Count
			
			if ($n -eq 0) {
				$Output = "`r`nNo lockout details about account $User on server $Server.`r`n"
				Write-Host $Output -ForegroundColor Yellow
				if ($OutFile) { $Output >> $Export }
			}
			else {
				$global:i = 1
				$Output = $UserEvents | Sort-Object -Property @{Expression={$_.Properties[0].Value}; Ascending=1}, @{Expression={$_.TimeCreated}; Ascending=0} | `
				Select-Object @{Name="N=$n"; Expression={$global:i; $global:i++}}, `
				@{Name="User name`t"; Expression={$_.Properties[5].Value + "\" + $_.Properties[0].Value}}, @{Name="Lockout Location`t"; Expression={$_.Properties[1].Value}}, `
				@{Name="Lockout date and time"; Expression={$_.TimeCreated.ToString("dd'/'MM'/'yyyy HH:mm:ss")}} | Format-Table -AutoSize
				
				$Output
				if ($OutFile) { $Output >> $Export }
			}
		}
	}
}

EndScript $StartTime
