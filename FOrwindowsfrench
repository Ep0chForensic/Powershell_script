<#

 forensic in depth Script 
Author: Ep0ch
Version : 5.3 for PowerShell V2
#>

write-host ""
Write-host "**** Demarrage du script ****"
write-host ""

# Recolte des variables d'environement.
$CompName = (gi env:\Computername).Value
$UserDirectory = (gi env:\userprofile).value
$User = (gi env:\USERNAME).value
$Date = (Get-Date).ToString('MM.dd.yyyy')
$head = '<style> BODY{font-family:caibri; background-color:Aliceblue;}
TABLE{border-width: 1px;border-style: solid;border-color: black;bordercollapse:
collapse;} TH{font-size:1.1em; border-width: 1px;padding: 2px;borderstyle:
solid;border-color: black;background-color:PowderBlue} TD{border-width:
1px;padding: 2px;border-style: solid;border-color: black;backgroundcolor:white}
</style>'
$OutLevel1 = "$UserDirectory\desktop\$CompName-$User-$Date-Level1.html"
$TList = @(tasklist /V /FO CSV | ConvertFrom-Csv)
$ExecutableFiles = @("*.EXE","*.COM","*.BAT","*.BIN", "*.JOB","*.WS",".WSF","*.PS1",".PAF","*.MSI","*.CGI","*.CMD","*.JAR","*.JSE","*.SCR","*.SCRIPT","*.VB","*.VBE","*.VBS","*.VBSCRIPT","*.DLL")
# construction du rapport html.
ConvertTo-Html -Head $head -Title " SOC Response script for $CompName.$User" -Body "<h1> SOC Forensics Script <p> Computer Name : $CompName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp User ID : $User </p> </h1>" > $OutLevel1
#Programme principal
#Enregistrement du début de la collecte d'information
write-host ""
write-host "Debut de la collecte des programmes persistants"
date | select DateTime | ConvertTo-html -Body "<H2> Heure et Date </H2>" >> $OutLevel1
systeminfo /FO CSV | ConvertFrom-Csv | select-object * -ExcludeProperty 'Correctif(s)','Carte(s) réseau' | ConvertTo-html -Body "<H2>Information du syst&egraveme </H2>" >> $OutLevel1
gwmi -ea 0 Win32_UserProfile | select LocalPath, SID,@{NAME='lastused';EXPRESSION={$_.ConvertToDateTime($_.lastusetime)}} | ConvertTo-html -Body "<H2> User accounts and current login Information </H2>" >> $OutLevel1
gwmi -ea 0 Win32_NetworkAdapterConfiguration |where{$_.IPEnabled -eq 'True'} |select DHCPEnabled,@{Name='IpAddress';Expression={$_.IpAddress -join ';'}},@{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join ';'}},DNSDomain | ConvertTo-html -Body "<H2> Network Configuration Information
</H2>" >> $OutLevel1
gwmi -ea 0 Win32_StartupCommand | select command,user,caption | ConvertTo-html -Body "<H2> Startup Applications </H2>" >> $OutLevel1
gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
gp -ea 0 'hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\ Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
gp -ea 0 'hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\ Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1
write-host ""
write-host "Collecte OK"
# On récupére les infos de connections
write-host ""
write-host "Recuperation des donnees reseaux"
$cmd = netstat -nao | select-string "ESTA"
foreach ($element in $cmd)
{
$data = $element -split ' ' | where {$_ -ne ''}
New-Object -TypeName psobject -Property @{
'Local IP : Port#'=$data[1];
'Remote IP : Port#'=$data[2];
'Process ID'= $data[4];
'Process Name'=((Get-process |where {$_.ID -eq $data[4]})).Name
'Process File Path'=((Get-process |where {$_.ID -eq $data[4]})).path
'Process Start Time'=((Get-process |where {$_.ID -eq $data[4]})).starttime
'Associated DLLs and File Path'=((Get-process |where {$_.ID -eq
$data[4]})).Modules |select @{Name='Module';Expression={$_.filename -join '; '
} } |out-string
} | ConvertTo-html -Property 'Local IP : Port#', 'Remote IP :
Port#','Process ID','Process Name','Process Start Time','Process File
Path','Associated DLLs and File Path' -Body "<H2> Information sur les connections etablis </H2>" >> $OutLevel1
}
write-host ""
write-host "Recuperation OK"
write-host ""
write-host "Collecte des processus de la machine"

gwmi -ea 0 win32_process | select processname,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},ProcessId,ParentProcessId,CommandLine,sessionID |sort ParentProcessId -desc | ConvertTo-html -Body "<H2> Running Processes sorted by ParentProcessID
</H2>" >> $OutLevel1
gwmi -ea 0 win32_process | where {$_.name -eq 'svchost.exe'} | select ProcessId|foreach-object {$P = $_.ProcessID ;gwmi win32_service |where {$_.processId -eq $P} | select processID,name,DisplayName,state,startmode,PathName} | ConvertTo-html -Body "<H2> Running SVCHOST and associated Processes </H2>" >> $OutLevel1
gwmi -ea 0 win32_Service | select Name,ProcessId,State,DisplayName,PathName |sort state | ConvertTo-html -Body "<H2> Running Services - Sorted by State </H2>" >> $OutLevel1
driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select 'Display Name','Start Mode', Path | sort Path | ConvertTo-html -Body "<H2> Drivers running, Startup mode and Path - Sorted by Path </H2>" >> $OutLevel1
write-host ""
write-host "Veuillez patienter ..."
gci -r -ea 0 c:\ -include *.dll | select Name,CreationTime,LastAccessTime,Directory | sort CreationTime -desc | select -first 50 | ConvertTo-html -Body "<H2> Last 50 DLLs created - Sorted by CreationTime </H2>" >> $OutLevel1
write-host ""
write-host "Collecte OK"
write-host ""
write-host "Collecte des dossiers partages"
openfiles /query > "$UserDirectory\desktop\$CompName-$User-$Date-OpenFiles.txt"
gwmi -ea 0 Win32_Share | select name,path,description | ConvertTo-html -Body "<H2> Open Shares </H2>" >> $OutLevel1
write-host ""
write-host "Collecte OK"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Mapped Drives </H2>" >> $OutLevel1

#Recuperer les taches planifiées

write-host ""
write-host "Collecte des taches planifiees"

function getTasks($path) {
    $out = @()

    # Avoir les taches planifiees root
    $schedule.GetFolder($path).GetTasks(0) | % {
        $xml = [xml]$_.xml
        $out += New-Object psobject -Property @{
            "Name" = $_.Name
            "Path" = $_.Path
            "LastRunTime" = $_.LastRunTime
            "NextRunTime" = $_.NextRunTime
            "Actions" = ($xml.Task.Actions.Exec | % { "$($_.Command) $($_.Arguments)" }) -join "`n"
        }
    }

    # Avoir les taches planifiees des sous dossiers
    $schedule.GetFolder($path).GetFolders(0) | % {
        $out += getTasks($_.Path)
    }

    #Output
    $out
}

$tasks = @()

$schedule = New-Object -ComObject "Schedule.Service"
$schedule.Connect() 

# Start inventory
$tasks += getTasks("\")

[System.Runtime.Interopservices.Marshal]::ReleaseComObject($schedule) | Out-Null
Remove-Variable schedule

# Output all tasks
$tasks | ConvertTo-html -Body "<H2> Scheduled Jobs </H2>" >> $OutLevel1

write-host ""
write-host "Collecte des taches planifiees  OK  "

#historique USB
gci -recurse HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR | ConvertTo-html -Body "<H2> Historic USB </H2>" >> $OutLevel1
#historique USB ID
gci -recurse HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR | ? { $_.PSParentPath -match ".*Disk&Ven[^\\]*$" }  | select PSChildName | ConvertTo-html -Body "<H2> Historic USB ID </H2>" >> $OutLevel1
#Applications installés
write-host ""
write-host "Collecte des applications  "
#gp -ea 0 HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | Sort InstallDate -Desc | ConvertTo-html -Body "<H2> Installed Applications - Sorted by Installed Date </H2>" >> $OutLevel1
Get-WmiObject -Class Win32_Product | Select-Object -Property Name | Sort InstallDate -Desc | ConvertTo-html -Body "<H2> Installed Applications - Sorted by Installed Date </H2>" >> $OutLevel1
write-host ""
write-host "Collecte des applications OK "
write-host ""
write-host "Collecte des dernieres modifications sur les fichiers  "
gwmi -ea 0 Win32_ShortcutFile | select FileName,caption,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},@{NAME="LastAccessed";EXPRESSION={$_.ConvertToDateTime($_.LastAccessed)}},@{NAME="LastModified";EXPRESSION={$_.ConvertToDateTime($_.LastModified)}},Target | Where-Object {$_.lastModified -gt ((Get-Date).addDays(-5)) }| sort LastModified -Descending | ConvertTo-html -Body "<H2> dernieres modifications sur les fichiers sur 5 jours </H2>" >> $OutLevel1
write-host ""
write-host "Collecte OK "
#Récupération des shadowcopy
gwmi -ea 0 Win32_ShadowCopy | select DeviceObject,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.InstallDate)}} | ConvertTo-html -Body "<H2> liste des ShadowCopy  </H2>" >> $OutLevel1
#Récupération des files prefecth
gci -path C:\windows\prefetch\*.pf -ea 0 | select Name,LastAccessTime,CreationTime | sort LastAccessTime | ConvertTo-html -Body "<H2> Prefetch Files </H2>" >> $OutLevel1
#Récupération du cache DNS
ipconfig /displaydns | select-string "Nom d'enregistrement" | sort  | ConvertTo-html -Body "<H2> DNS Cache </H2>" >> $OutLevel1
#Récupération des requetes dns inaboutit
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=1014} | select TimeCreated,ID,Message |  ConvertTo-html -Body "<H2> DNS fail </H2>" >> $OutLevel1
#Récupération error log level warning
Get-WinEvent application | ?{$_.Level -eq 2 -or $_.Level -eq 3} |  ConvertTo-html -Body "<H2> error log</H2>" >> $OutLevel1
#Récupération des fichiers internet temporaire
$la = $env:LOCALAPPDATA ;gci -r -ea 0 $la\Microsoft\Windows\'Temporary Internet Files' | select Name, LastWriteTime, CreationTime,Directory| Where-Object {$_.lastwritetime -gt ((Get-Date).addDays(-5)) }| Sort creationtime -Desc | ConvertTo-html -Body "<H2> Temporary Internet Files - Last 5 days - Sorted by CreationTime </H2>"  >> $OutLevel1
#Récupération des cookies
$a = $env:APPDATA ;gci -r -ea 0 $a\Microsoft\Windows\cookies | select Name |foreach-object {$N = $_.Name ;get-content -ea 0 $a\Microsoft\Windows\cookies\$N | select-string '/'} | ConvertTo-html -Body "<H2> Cookies </H2>" >> $OutLevel1
#Récupération des URL IE
gp -ea 0 'hkcu:\Software\Microsoft\Internet Explorer\TypedUrls' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Typed URLs IE </H2>" >> $OutLevel1
#Récupération des DLL charger par EXPLORER.Exe
gp -ea 0 'hklm:\software\microsoft\windows nt\CurrentVersion\winlogon\*\*' | select '(default)',DllName | ConvertTo-html -Body "<H2> DLL loaded by explorer.exe </H2>" >> $OutLevel1
#Récupération des commandes fait par "RUN"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\RunMru' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> commande executer par run </H2>" >> $OutLevel1
#clef de registre start menu
gp -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\explorer\Startmenu' | select * -ExcludeProperty PS*  | ConvertTo-html -Body "<H2> start menu </H2>" >> $OutLevel1
# Popup message upon completion
(New-Object -ComObject wscript.shell).popup("Execution du script terminee")
#cmd.exe /c del prefecth\*.* /Q since: 2015/07/10 20:51:12	~ 2015/08/03 ==> antiforensic

