# ***************************************************************************
# * Windows Script                                                          *
# * Run this local                                                          *
# ***************************************************************************
clear # just like the defibrillator paddle prep :-)

# Quick and Dirty error handling will fine tune after functional
$ErroractionPreference = "Silentlycontinue"

$Sname = hostname

# IP Addresses
$IPFile = New-Item -type file -force "IPFile-Out.csv" #/System Information Out File
$IPFileEntry = '"IP"' + ","
$IPFileEntry = $IPFileEntry + '"' + "Family" + '"'
$IPFileEntry | Out-File $IPFile -encoding ASCII -append

# [System.Net.Dns]::GetHostAddresses($Sname) | select-object IPAddressToString -expandproperty  IPAddressToString | out-file $IPFile -encoding ASCII -append
[System.Net.Dns]::GetHostAddresses($Sname) | Foreach-object {
    $AddFam = $_.AddressFamily
    $Add6Multi = $_.IsIPv6Multicast
    $Add6Link = $_.IsIPv6LinkLocal
    $Add6Site = $_.IsIPv6SiteLocal
    $AddStr = $_.IPAddressToString
    #Write IP record
    $IPInfoEntry = '"' + $AddStr + '"' + ","
    $IPInfoEntry = $IPInfoEntry + '"' + $AddFam + '"'
    $IPInfoEntry | Out-File $IPFile -encoding ASCII -append}

# System Information File Out 
$SysFile = New-Item -type file -force "SysInfo-Out-v19.csv" #/System Information Out File
$SysInfoEntry = '"System"'
# $SysInfoEntry = $SysInfoEntry + "," + '"IP"'
$SysInfoEntry = $SysInfoEntry + "," + '"AV Name"'
$SysInfoEntry = $SysInfoEntry + "," + '"AV Exe"'
$SysInfoEntry = $SysInfoEntry + "," + '"AV Definition"'
$SysInfoEntry = $SysInfoEntry + "," + '"AV Real Time"'
$SysInfoEntry = $SysInfoEntry + "," + '"OS Version"'
$SysInfoEntry = $SysInfoEntry + "," + '"Domain"'
$SysInfoEntry = $SysInfoEntry + "," + '"Crash Dump"'
$SysInfoEntry = $SysInfoEntry + "," + '"CD Auto Run"'
$SysInfoEntry = $SysInfoEntry + "," + '"Time Server"'
$SysInfoEntry = $SysInfoEntry + "," + '"Firewall Dom"'
$SysInfoEntry = $SysInfoEntry + "," + '"Firewall Pub"'
$SysInfoEntry = $SysInfoEntry + "," + '"Firewall Stand"'
$SysInfoEntry = $SysInfoEntry + "," + '"Restrict Anonymous"'
$SysInfoEntry = $SysInfoEntry + "," + '"RM Max Idle Time"'
$SysInfoEntry = $SysInfoEntry + "," + '"RM Inherit"'
$SysInfoEntry = $SysInfoEntry + "," + '"Min Encrypt"'
$SysInfoEntry = $SysInfoEntry + "," + '"Screen Saver Secure"'
$SysInfoEntry = $SysInfoEntry + "," + '"Screen Saver Timeout"'
$SysInfoEntry = $SysInfoEntry + "," + '"Pwd History"'
$SysInfoEntry = $SysInfoEntry + "," + '"Pwd Max Age"'
$SysInfoEntry = $SysInfoEntry + "," + '"Pwd Min Length"'
$SysInfoEntry = $SysInfoEntry + "," + '"Pwd Complexity"'
$SysInfoEntry = $SysInfoEntry + "," + '"Pwd Lock Out"'
$SysInfoEntry = $SysInfoEntry + "," + '"Bad Login Lock"'
$SysInfoEntry = $SysInfoEntry + "," + '"Guest Disabled"'
$SysInfoEntry = $SysInfoEntry + "," + '"Admin Renamed"'
$SysInfoEntry = $SysInfoEntry + "," + '"No LM Hash"'
$SysInfoEntry = $SysInfoEntry + "," + '"NTLMv2 Req"'
$SysInfoEntry = $SysInfoEntry + "," + '"Clear Pagefile"'
$SysInfoEntry = $SysInfoEntry + "," + '"Network Everyone"'
$SysInfoEntry | Out-File $SysFile -encoding ASCII -append # Write Header
#********************************************************

# Patch File Out
$PFile = New-Item -type file -force "PchInfo-Out.csv" # Patch Information Out File
$PatchEntry = '"System"' # Server/System
$PatchEntry = $PatchEntry + "," + '"Patch ID"'
$PatchEntry = $PatchEntry + "," + '"Patch Description"' 
$PatchEntry = $PatchEntry + "," + '"Patch Date"'
$PatchEntry | Out-File $PFile -encoding ASCII -append
#****************************************************

# Services File Out
$SFile = New-Item -type file -force "SvcInfo-Out.csv" # Service Information Out File
$ServiceEntry = '"System"' # Server/System
$ServiceEntry = $ServiceEntry + "," + '"Status"' 
$ServiceEntry = $ServiceEntry + "," + '"Service"' 
$ServiceEntry = $ServiceEntry + "," + '"Service Display Name"' 
$ServiceEntry | Out-File $SFile -encoding ASCII -append
#******************************************************

# Shares File Out
$SHFile = New-Item -type file -force "ShInfo-Out.csv" #/ Share Information Out File
$ShareEntry = '"System"'   # Server/System
$ShareEntry = $ShareEntry + "," + '"Name"' 
$ShareEntry = $ShareEntry + "," + '"Path"' 
$ShareEntry = $ShareEntry + "," + '"Description"' 
$ShareEntry | Out-File $ShFile -encoding ASCII -append
#*****************************************************

# Application Versions File Out
$AppFile = New-Item -type file -force "AppInfo-Out.csv" #/ App Versions Information Out File
$AppEntry = '"System"'  # Server/System
$AppEntry = $AppEntry + "," + '"Application"'
$AppEntry = $AppEntry + "," + '"Vendor"'
$AppEntry = $AppEntry + "," + '"Description"'
$AppEntry = $AppEntry + "," + '"Version"'
$AppEntry = $AppEntry + "," + '"InstallDate"'
$AppEntry | Out-File $AppFile -encoding ASCII -append
#****************************************************

# Disk File Out
$DiskFile1 = New-Item -type file -force "DiskInfo-Out.csv" #/ Disk Information Out File
$DiskEntry = '"System"'  # Server/System
$DiskEntry = $DiskEntry + "," + '"Disk Name"'
$DiskEntry = $DiskEntry + "," + '"Disk Vol"'
$DiskEntry = $DiskEntry + "," + '"File Sys"'
$DiskEntry = $DiskEntry + "," + '"Disk Size"'
$DiskEntry = $DiskEntry + "," + '"Disk Free"'
$DiskEntry | Out-File $DiskFile1 -encoding ASCII -append
#******************************************************

# Log Permisions
$LogFile = New-Item -type file -force "LogInfo-Out.csv" #/ Disk Information Out File
$LogEntry = '"System"'   # Server/System
$LogEntry = $LogEntry + "," + '"' + $LogName + '"'
$LogEntry = $LogEntry + "," + '"' + $LogType + '"'
$LogEntry = $LogEntry + "," + '"' + $LogSize + '"'
$LogEntry = $LogEntry + "," + '"' + $LogMax + '"'
$LogEntry = $LogEntry + "," + '"' + $LogMode + '"'
$LogEntry = $LogEntry + "," + '"' + $LogPath + '"'
$LogEntry = $LogEntry + "," + '"' + $LogSec + '"'

$LogEntry | Out-File $LogFile -encoding ASCII -append
#****************************************************    

# Processes Running File Out
$PsFile = New-Item -type file -force "PsInfo-Out.csv" # Running Processes Information Out File
$ProcessEntry = '"System"' 
$ProcessEntry = $ProcessEntry + "," + '"Process ID"'
$ProcessEntry = $ProcessEntry + "," + '"Process Name"'
$ProcessEntry | Out-File $PsFile -encoding ASCII -append
#*******************************************************

# Accounts
$AcctFile = New-Item -type file -force "AcctInfo-Out.csv" # Local Accounts Information Out File
$AcctEntry = '"System"'   # Server/System
$AcctEntry = $AcctEntry + "," + '"Name"'
$AcctEntry = $AcctEntry + "," + '"Disabled"'
$AcctEntry = $AcctEntry + "," + '"Locked"'
$AcctEntry = $AcctEntry + "," + '"Status"'
$AcctEntry = $AcctEntry + "," + '"Full Name"'
$AcctEntry = $AcctEntry + "," + '"Description"'
$AcctEntry | Out-File $AcctFile -encoding ASCII -append
#******************************************************

# Groups
$GrpFile = New-Item -type file -force "GrpInfo-Out.csv" # Local Accounts Information Out File
$GroupEntry = '"System"'   # Server/System
$GroupEntry = $GroupEntry + "," + '"Group"'
$GroupEntry = $GroupEntry + "," + '"User"'
$GroupEntry | Out-File $GrpFile -encoding ASCII -append

# Network Adapters
$NetFile = New-Item -type file -force "NetInfo-Out.csv" # Network Adapter Information Out File
$NetEntry = '"System"' # Server/System
$NetEntry = $NetEntry + "," + '"Connection Type"' 
$NetEntry = $NetEntry + "," + '"Connection Name"'
$NetEntry = $NettEntry + "," + '"Enabled"'
$NetEntry | Out-File $NetFile -encoding ASCII -append
#**************************************************

# Audit Polciy
$AudFile = New-Item -type file -force "AudInfo-Out.csv" # Audit Information Out File
$AudEntry = '"System"'
$AudEntry = $AudEntry + "," + '"Policy"'
$AudEntry = $AudEntry + "," + '"Setting"'
$AudEntry | Out-File $AudFile -encoding ASCII -append
#*****************************************************

# **************************************************************
# * End of Prep output files (Update these as items are added) *
# **************************************************************


    $Sname = $SName # Talk about quick and dirty
    # $Sip = [System.Net.Dns]::GetHostAddresses($sname) | select-object IPAddressToString -expandproperty  IPAddressToString

    "Processing System: " + $SName   
    $NBSys = gwmi win32_computersystem -ComputerName $Sname 
    $NBName = $NBSys.Name # Get actual computer name
     
    # Appliction Versions 
      ## Get-WMIObject -Class win32_product -ComputerName $SName | ForEach-Object{ *** was causing updates ***
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | ForEach-Object{ 
    $AppN = $_.DisplayName
    $AppVend = $_.Publisher
    $AppD = $_.Comments
    $AppVer = $_.DisplayVersion
    $AppIDate = $_.InstallDate
    $AppEntry = '"' + $Sname + '"'  # Server/System
    $AppEntry = $AppEntry + "," + '"' + $AppN + '"'
    $AppEntry = $AppEntry + "," + '"' + $AppVend + '"' 
    $AppEntry = $AppEntry + "," + '"' + $AppD + '"'
    $AppEntry = $AppEntry + "," + '"' + $AppVer + '"'
    $AppEntry = $AppEntry + "," + '"' + $AppIDate + '"'
    $AppEntry | Out-File $AppFile -encoding ASCII -append
    }#***************************************************
    
    # File Systems
    Get-WmiObject -Class win32_logicaldisk -ComputerName $Sname | ForEach-Object{
    $DiskName = $_.Name
    $DiskVol = $_.VolumeName
    $DiskFile = $_.FileSystem
    $DiskSize = $_.Size
    $DiskFree = $_.Freespace
    $DiskEntry = '"' + $Sname + '"'  # Server/System
    $DiskEntry = $DiskEntry + "," + '"' + $DiskName + '"'
    $DiskEntry = $DiskEntry + "," + '"' + $DiskVol + '"'
    $DiskEntry = $DiskEntry + "," + '"' + $DiskFile + '"'
    $DiskEntry = $DiskEntry + "," + '"' + $DiskSize + '"'
    $DiskEntry = $DiskEntry + "," + '"' + $DiskFree + '"'
    $DiskEntry | Out-File $DiskFile1 -encoding ASCII -append
    }#******************************************************
    
    # Windows Event Logs
    $l = Get-WinEvent -ComputerName $SName -ListLog * | ForEach-Object{
    $LogName = $_.Name
    $LogType = $_.LogType
    $LogSize = $_.FileSize
    $LogMax = $_.MaximumSizeInBytes
    $LogMode = $_.LogMode
    $LogPath = $_.LogFilePath
    $LogSec = $_.SecurityDescriptor 
    $LogEntry = '"' + $Sname + '"'   # Server/System
    $LogEntry = $LogEntry + "," + '"' + $LogName + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogType + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogSize + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogMax + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogMode + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogPath + '"'
    $LogEntry = $LogEntry + "," + '"' + $LogSec + '"'
    $LogEntry | Out-File $LogFile -encoding ASCII -append
    }#***************************************************

       
    # Services On Host
    get-service -ComputerName $SName | foreach-object{
    $ServiceEntry = '"' + $Sname + '"'   # Server/System
    $ServiceEntry = $ServiceEntry + "," + '"' + $_.status + '"'
    $ServiceEntry = $ServiceEntry + "," + '"' + $_.name + '"'
    $ServiceEntry = $ServiceEntry + "," + '"' + $_.displayname + '"' 
    $ServiceEntry | Out-File $SFile -encoding ASCII -append
    }#*****************************************************
    
    # Processes On Host
    get-process -ComputerName $SName | foreach-object{
    $ProcessEntry = '"' + $SName + "," 
    $ProcessEntry = $ProcessEntry + "," + '"' + $_.Id + '"'
    $ProcessEntry = $ProcessEntry + "," + '"' + $_.ProcessName + '"'
    $ProcessEntry | Out-File $PsFile -encoding ASCII -append
    }#******************************************************

    # Patches on host
    get-hotfix -ComputerName $SName | foreach-object{
    $PatchEntry = '"' + $SName + '"'
    $PatchEntry = $PatchEntry + "," + '"' + $_.hotfixid + '"'
    $PatchEntry = $PatchEntry + "," + '"' + $_.description + '"'
    $PatchEntry = $PatchEntry + "," + '"' + $_.installedon + '"'
    $PatchEntry | Out-File $PFile -encoding ASCII -append
    }#***************************************************

    # Shares on host
    get-WmiObject -ComputerName $SName -class win32_share | foreach-object{
    $ShareEntry = '"' + $Sname + '"' # Server/System
    $ShareEntry = $ShareEntry + "," + '"' + $_.name + '"'
    $ShareEntry = $ShareEntry + "," + '"' + $_.path + '"'
    $ShareEntry = $ShareEntry + "," + '"' + $_.description + '"'
    $ShareEntry | Out-File $ShFile -encoding ASCII -append
    }#****************************************************


    # ************************
    # System Settings/Services
    # ************************
    
    # AntiVirus
    $AntiVirusProduct = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct `
    -ComputerName $Sname
    #Switch to determine the status of antivirus definitions and real-time protection. 
    #The values in this switch-statement are retrieved from the following website: 
    # http://community.kaseya.com/resources/m/knowexch/1020.aspx 
    switch ($AntiVirusProduct.productState) { 
    "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
    "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
    "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
    "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
    "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
    "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
    "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
    "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
    "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
    "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
    default {$defstatus = "Unknown" ;$rtstatus = "Unknown"} 
    }
    $AvName = $AntiVirusProduct.displayName 
    $AvExe = $AntiVirusProduct.pathToSignedProductExe
    #************************************************
    
    $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]`
    "LocalMachine",$Sname)
       
    # OS Name
    $RegSubKeySM = $RegCon.OpenSubKey("software\\microsoft\\windows nt\\currentversion")
    $RegvOSVer = $RegSubkeySM.GetValue("ProductName")
    
    # Time Server
    $t = Get-Service -ComputerName $Sname -Name "w32time"
    if ($t.status -eq "Running")
      {
      $TimeServer = w32tm /query /computer:$Sname /source      
      }
    else
      {
      $TimeServer = "Not Running"
      }
    
        
    # Firewall Enabled
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile")
    $RegvFireDom = $RegSubKeySM.GetValue("EnableFirewall")
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile")
    $RegvFirePub = $RegSubKeySM.GetValue("EnableFirewall")
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile")
    $RegvFireStand = $RegSubKeySM.GetValue("EnableFirewall")
        
    # Crash Dump Enabled
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\control\\crashcontrol")
    $RegvDDump = $RegSubKeySM.GetValue("CrashDumpEnabled")
    # CDROM AutoRun
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\services\\cdrom")
    $RegvCDARun = $RegSubKeySM.GetValue("AutoRun")
    # Protect Registry
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\control\\LSA")
    $RegvRestAn = $RegSubKeySM.GetValue("RestrictAnonymous")
    
    # Remote Access
    <# $Remote Info MaxIdle = (Get-ItemProperty -Path $keyRemote -Name MaxIdleTime).MaxIdleTime
    Remote Sessions:
    $keyRemote = & 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    MaxIdleTime -> Maximum idle time in seconds for user sessions. 
    This value becomes effective only if you set the fInheritMaxIdleTime flag to 0.#>
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\control\\terminal server\\winstations\\rdp-tcp")
    $RegvRMIdle = $RegSubkeySM.GetValue("MaxIdleTime")
    $RegvRMInherit = $RegSubKeySM.GetValue("fInheritMaxIdleTime")
    $RegvRMMinEncrypt = $RegSubKeySM.GetValue("MinEncryptionLevel")
    # LAN Manager Hash
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\control\\LSA")
    $RegvNoLMHash = $RegSubkeySM.GetValue("NoLMHash")
    if ($RegvNoLMHash -eq 1)
      {$RegvNoLMHash = $true}
      else
      {$RegvNoLMHash = $false}
    # Network Security NTLMv2 only
    $RegvReqNTLM2 = $RegSubKeySM.GetValue("LmCompatibilityLevel") # 5 is NTLMv2 only https://technet.microsoft.com/en-us/library/cc960646.aspx
      <# if ($RegvReqNTLM2 -eq 5)
      {$RegvReqNTLM2 = $True}
      else
      {$RegvReqNTLM2 = $false} 
     #>  

    # Network Everyone Permission Apply to Anonymous (disable->0) should be false
    $RegvNetEvery = $RegSubkeySM.GetValue("Everyoneincludesanonymous")
    if ($RegvNetEvery -eq 1)
      {$RegvNetEvery = $True}
      else
      {$RegvNetEvery = $False}
    # Clear Virtual Memory - Shutdown
    $RegSubKeySM = $RegCon.OpenSubKey("system\\currentcontrolset\\control\\session manager\\memory management")
    $RegvClrPage = $RegSubkeySM.GetValue("ClearPageFileAtShutdown")
    if ($RegvClrPage -eq 1)
      {$RegvClrPage = $True}
      else
      {$RegvClrPage = $False}
         
    # Move to different hive HKCU
    $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]`
    "CurrentUser",$Sname)

    # No wireless config
    Get-WmiObject -class win32_networkadapter -ComputerName $SName -filter "netenabled='True'" | foreach-object{
    $NetvConID = _.netconnectionid
    $NetvName = _.name
    $NetvEnabled = _.netenabled
    $NetEntry = '"' + $Sname + '"' # Server/System
    $NetEntry = $NetEntry + "," + '"' + $_.netconnectionid + '"' 
    $NetEntry = $NetEntry + "," + '"' + $_.name + '"'
    $NetEntry = $NetEntry + "," + '"' + $_.netenabled + '"'
    $NetEntry | Out-File $NetFile -encoding ASCII -append
    } #**************************************************
    
    # Screen Saver
    $RegSubKeySM = $RegCon.OpenSubKey("control panel\Desktop")
    $RegvScrs = $RegSubKeySM.GetValue("ScreenSaverIsSecure")
    $RegvScrt = $RegSubKeySM.GetValue("ScreenSaveTimeout")

    # Disabled Guest
    $Guest = get-wmiobject -class win32_useraccount -ComputerName $SName -filter "name='Guest'"
    $Guest = $Guest.Disabled 

    # Rename Administrator
    $AdminRen = $null
    # $AdminRen = Get-WmiObject -class win32_useraccount -ComputerName $Sname -filter "name='Administrator'")
    if (get-wmiobject -class win32_useraccount -ComputerName $SName -filter "name='Administrator'")
      {
      $AdminRen = $False 
      }
    
    
    # Local Accounts
    get-WmiObject -ComputerName $SName -class win32_useraccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"| foreach-object{
    $AcctEntry = '"' + $Sname + '"' # Server/System
    $AcctEntry = $AcctEntry + "," + '"' + $_.name + '"' 
    $AcctEntry = $AcctEntry + "," + '"' + $_.disabled + '"'
    $AcctEntry = $AcctEntry + "," + '"' + $_.lockout + '"'
    $AcctEntry = $AcctEntry + "," + '"' + $_.status + '"'
    $AcctEntry = $AcctEntry + "," + '"' + $_.fullname + '"'
    $AcctEntry = $AcctEntry + "," + '"' + $_.description + '"'
    $AcctEntry | Out-File $AcctFile -encoding ASCII -append
    }#**********************************************************
    
    # Groups
    $computer = [ADSI]"WinNT://$Sname,computer"
    $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | 
      foreach {
        $groupname = $_.name
        $group =[ADSI]$_.psbase.Path
        $group.psbase.Invoke("Members") | 
          foreach {
            $member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
            $GroupEntry = '"' + $Sname + '"' # Server/System
            $GroupEntry = $GroupEntry + "," + '"' + $groupname + '"' 
            $GroupEntry = $GroupEntry + "," + '"' + $member + '"'
            $GroupEntry | Out-File $GrpFile -encoding ASCII -append
          } 
      }
    
    
    # ***********************************************************
    # Security Parameters use rsop if part of domain else secedit for non-domain systems and domain controllers
    
    # Check if system is a Domain Controller
    $IsDC = $False
    $CompConfig = gwmi win32_computersystem
    $DRole = $CompConfig.DomainRole
    if ($DRole -eq 5) {$IsDC = $True}
    
    if ((gwmi win32_computersystem).partofdomain -eq $true -And $IsDC -ne $True) {
    # ***********************************************************
    # Run RSOP and pull data from XML result to get actual settings for system
    # Get-gpresultantSetOfPolicy -computer $SName -ReportType xml -Path gpresult.xml **Doesn't work on older systems
    
    # $SNameXml = $SName + ".xml" 
    # gpresult /s $SName -X $SNameXml /F 
    
    gpresult /s $SName -X gpresult.xml /F
    # secedit 
    # cp gpresult.xml $SNameXml
    
    [xml]$filecontents = get-content -path gpresult.xml
    
    
    #$Dom = $filecontents.rsop.ComputerResults.Domain **1-4-15 George Mateaki - inconsistent results.
    $Dom = (get-wmiobject win32_computersystem).domain
    
    $inED = 0
    $inc = 0 # Array index, number of settings can vary in Account area
    
      $RsopLockOut = 0 # Initialize variable, values will be held from prior run
      $RsopPMaxAge = 0 # Initialize variable, values will be held from prior run
      $RsopLockBad = 0 # Initialize variable, values will be held from prior run
      $RsopPhist = 0 # Initialize variable, values will be held from prior run
      $RsopPLength = 0 # Initialize variable, values will be held from prior run
      $RsopPComplx = $null # Initialize variable, values will be held from prior run

      #Traverse Each ExtensioinData as XML location changes for some reason
      $filecontents.rsop.ComputerResults.ExtensionData | ForEach-Object {
        $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account | ForEach-Object {
        switch ($filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].name) 
        { 
        # "MaxRenewAge" {} 
        "LockoutDuration" {
          $RsopLockOut = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingNumber
          } 
        "MaximumPasswordAge" {
          $RsopPMaxAge = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingNumber
          } 
        # "MinimumPasswordAge" {} 
        # "ResetLockoutCount" {} 
        # "MaxServiceAge" {} 
        "LockoutBadCount" {
          $RsopLockBad = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingNumber
          }
        # "MaxClockSkew" {} 
        # "MaxTicketAge" {} 
        "PasswordHistorySize" {
          $RsopPhist = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingNumber
          } 
        "MinimumPasswordLength" {
          $RsopPLength = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingNumber
          } 
        "PasswordComplexity" {
          $RsopPComplx = $filecontents.rsop.ComputerResults.ExtensionData[$inED].extension.account[$inc].SettingBoolean
          } 
        # "ClearTestPassword" {} 
        # "TicketValidateClient" {} 
        # default {}
        } # End Switch
        
        $inc = $inc + 1 # Increment index, next item in accounts
      } # End ForEach-object
      $inc = 0
      $inED = $inED + 1
      } # End ExtensionData ForEachObject
   ############################################################################
    } else {
    SecEdit /export /cfg cfg.ini
    # $locsec = get-content cfg.ini
    # $MinPasAge = $locsec | select-string "MinimumPasswordAge"
    # $RsopPLength = right($MinPasAge,len($MinPasAge) - 21))
    
    Get-Content cfg.ini | Foreach-Object{
     if ($_.Startswith("LockoutDuration")) 
       {$pass = $_.Split('=')
        $RsopLockOut = $pass[1]
       }
 
     if ($_.Startswith("MaximumPasswordAge")) 
       {$pass = $_.Split('=')
        $RsopPMaxAge = $pass[1]
       }
     
     if ($_.Startswith("LockoutBadCount")) 
       {$pass = $_.Split('=')
        $RsopLockBad = $pass[1]
       }
  
     if ($_.Startswith("PasswordHistorySize")) 
       {$pass = $_.Split('=')
        $RsopPHist = $pass[1]
       }
    
     if ($_.Startswith("MinimumPasswordLength")) 
       {$pass = $_.Split('=')
        $RsopPLength = $pass[1]
       }
     
     if ($_.Startswith("PasswordComplexity")) 
       {$pass = $_.Split('=')
        $RsopPComplx = $pass[1]
       }
       
     } # End of foreach-object
    
    } # End of if on Domain or not
    
    
    # Audit Policy 
      $AudPol = auditpol /get /category:*
      $IncA = 0
      $AudPol | ForEach-Object {
      $AudItem = $AudPol.getvalue($IncA)
      $IncA = $IncA + 1
        if ($auditem.startswith("  ")){
        $APItemLen = $AudItem.Length
        $AudPolItem = $Auditem.Substring(2,40)
        $AudPolSet = $Auditem.Substring(42)
        $AudEntry = '"' + $Sname + '"'
        $AudEntry = $AudEntry + "," + '"' + $AudPolItem + '"'
        $AudEntry = $AudEntry + "," + '"' + $AudPolSet + '"'
        $AudEntry | Out-File $AudFile -encoding ASCII -append}
        } # End for each $AudPol
    #*****************************************************

    # Write out record for the current server
    $SysInfoEntry = '"' + $Sname + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $AvName + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $AvExe + '"' 
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $defstatus + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $rtStatus + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvOSVer + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $Dom + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvDDump + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvCDARun + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $TimeServer + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvFireDom + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvFirePub + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvFireStand + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvRestAn + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvRMIdle + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvRMInherit + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvRMMinEncrypt + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvScrs + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvScrt + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopPhist + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopPMaxAge + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopPLength + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopPComplx + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopLockOut + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RsopLockBad + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $Guest + '"'
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $AdminRen + '"'    
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvNoLMHash + '"'    
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvReqNTLM2 + '"'    
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvClrPage + '"'    
    $SysInfoEntry = $SysInfoEntry + "," + '"' + $RegvNetEvery + '"'
    $SysInfoEntry | Out-File $SysFile -encoding ASCII -append

# Clean Up
$RegCon.Close()
$RegCon.Dispose()
"Script Complete"
# SIG # Begin signature block
# MIIf9wYJKoZIhvcNAQcCoIIf6DCCH+QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUilsAGWkLIapT4TK/AQ9GZaeW
# pRmgghteMIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg
# +XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lT
# XDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5
# a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g
# 0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1
# roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
# GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3
# cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmr
# EthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+
# fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5Q
# Z7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu
# 838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw
# 8jCCBSwwggQUoAMCAQICEAerFk2QcBFF2MMlkeGbq2QwDQYJKoZIhvcNAQELBQAw
# cjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVk
# IElEIENvZGUgU2lnbmluZyBDQTAeFw0xNjEwMTEwMDAwMDBaFw0xNzEwMTgxMjAw
# MDBaMGkxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRVdGFoMQ0wCwYDVQQHEwRPcmVt
# MR0wGwYDVQQKExRTZWN1cml0eU1ldHJpY3MgSW5jLjEdMBsGA1UEAxMUU2VjdXJp
# dHlNZXRyaWNzIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDU
# s+Cz6da3tnq2CSkmmS+wlpb6ryDzfwoyHATypym+8g7fNDPiFPO/8TJQkFuC53tM
# 2tCvjJkFRoPq2rDoEoTtXk6Npm6C7ZpmCmwK6YSAFjc5uttPJZkT1XHtqqWUiH0C
# 31pYIL1llqxkBemk/FFhJTTi+FQlpv5ppLAmPf5EsYwXkhQFoBlGQsD/6/GsQEss
# r8Lz1uashInd7Zlxa451Vy6eRuJmMB8ZLZmtn/M8huS/6R6mEq9trSBMWb7VX8Uz
# 4jAThIAgC8hPQrpN6jG0NoFfBrLciPqEOw1YmefSKlxRvgYX6eEwM9UTSItHS+AT
# vyLD4kbsOqwSQL4FVMIjAgMBAAGjggHFMIIBwTAfBgNVHSMEGDAWgBRaxLl7Kgqj
# pepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQUBw2yYTHnLi3jlU+SuDz+6+2qtDAwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAz
# oDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEu
# Y3JsMDWgM6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVk
# LWNzLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIB
# FhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCBhAYIKwYB
# BQUHAQEEeDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# TgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFNIQTJBc3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMA0G
# CSqGSIb3DQEBCwUAA4IBAQCGwlDkFUB21FBrh+lZgz4odtKR6Ft+56KKrzeBjlXq
# RoxSz8hKtFHhCjsPRncuGnGp/D28APz/yMLjq2iW4X7a+pic1GopjBwxyrLfv4rj
# MhVUikF4ExCl6VPX1SPwxRTbKU1HIMK7pPYOPw1MjvnHIGozrWNgrCbLDJXGJ6Zl
# rFfBfBKDbZvy1Dcf1KmqvvXvAKMK32lbk1FHSng0Idr/L6Fy1Jsa8siG/PXXcO1u
# 5xFYrMjYmlNviN4bS2XpQgSupK95jCYdcpa/eplSrU5YGgqaOuSjU4FXRwgbyiGD
# zQLDc2YvgyQQLliR09EcYR3Wqmfsn6gyeWs0ri/l39FkMIIFMDCCBBigAwIBAgIQ
# BAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTMxMDIy
# MTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQD
# EyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+NOzHH8OEa9ndwfTCzFJGc/Q+0WZ
# sTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ1DcZ17aq8JyGpdglrA55KDp+6dFn
# 08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0sSgmuyRpwsJS8hRniolF1C2ho+mI
# LCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6scKKrzn/pfMuSoeU7MRzP6vIK5Fe7
# SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4TzrGdOtcT3jNEgJSPrCGQ+UpbB8g8S
# 9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg0A9kczyen6Yzqf0Z3yWT0QIDAQAB
# o4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEG
# A1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwTwYDVR0gBEgwRjA4Bgpg
# hkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNv
# bS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYEFFrEuXsqCqOl6nEDwGD5LfZldQ5Y
# MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUA
# A4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06GsTvMGHXfgtg/cM9D8Svi/3vKt8g
# VTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5jDhNLrddfRHnzNhQGivecRk5c/5Cx
# GwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgCPC6Ro8AlEeKcFEehemhor5unXCBc
# 2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIysjaKJAL+L3J+HNdJRZboWR3p+nRk
# a7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4GbT8aTEAb8B4H6i9r5gkn3Ym6hU/oS
# lBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIGajCCBVKgAwIBAgIQAwGaAjr/WLFr1tXq
# 5hfwZjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBBc3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAwMDAwWhcNMjQxMDIy
# MDAwMDAwWjBHMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNV
# BAMTHERpZ2lDZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvMbuBTqZ8fZFnmfGt/
# a4ydVfiS457VWmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ5fWRn8YUOawk6qhL
# LJGJzF4o9GS2ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOOhkRVfRiGBYxVh3lI
# RvfKDo2n3k5f4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2AY3vJ+P3mvBMMWSN
# 4+v6GYeofs/sjAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y/qpA8bLOcEaD6dpA
# oVk62RUJV5lWMJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMBAAGjggM1MIIDMTAO
# BgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIBkjAoBggrBgEF
# BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwIC
# MIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0
# AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBl
# AHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABD
# AFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABh
# AHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBp
# AHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBv
# AHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQBy
# AGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAUFQASKxOYspkH7R7f
# or5XDStnAs0wHQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6Jwcp9MH0GA1UdHwR2
# MHQwOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRENBLTEuY3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcnQw
# DQYJKoZIhvcNAQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+Ah+WI//+x1GosMe06
# FxlxF82pG7xaFjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFetW7easGAm6mlXIV00
# Lx9xsIOUGQVrNZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ8OxwYtNiS7Dgc6aS
# wNOOMdgv420XEwbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HRmXQNJsQOfxu19aDx
# xncGKBXp2JPlVRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd2vNtomHpigtt7BIY
# vfdVVEADkitrwlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQwggbNMIIFtaADAgEC
# AhAG/fkDlgOt6gAK6z8nu7obMA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0wNjEx
# MTAwMDAwMDBaFw0yMTExMTAwMDAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAOiCLZn5ysJClaWAc0Bw0p5WVFypxNJBBo/JM/xNRZFcgZ/t
# LJz4FlnfnrUkFcKYubR3SdyJxArar8tea+2tsHEx6886QAxGTZPsi3o2CAOrDDT+
# GEmC/sfHMUiAfB6iD5IOUMnGh+s2P9gww/+m9/uizW9zI/6sVgWQ8DIhFonGcIj5
# BZd9o8dD3QLoOz3tsUGj7T++25VIxO4es/K8DCuZ0MZdEkKB4YNugnM/JksUkK5Z
# ZgrEjb7SzgaurYRvSISbT0C58Uzyr5j79s5AXVz2qPEvr+yJIvJrGGWxwXOt1/HY
# zx4KdFxCuGh+t9V3CidWfA9ipD8yFGCV/QcEogkCAwEAAaOCA3owggN2MA4GA1Ud
# DwEB/wQEAwIBhjA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUF
# BwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwggHSBgNVHSAEggHJMIIBxTCCAbQGCmCG
# SAGG/WwAAQQwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNv
# bS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBB
# AG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBh
# AHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBj
# AGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABT
# ACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABB
# AGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBh
# AGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBh
# AHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAu
# MAsGCWCGSAGG/WwDFTASBgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsGAQUFBwEBBG0w
# azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF
# BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRw
# Oi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
# MB0GA1UdDgQWBBQVABIrE5iymQftHt+ivlcNK2cCzTAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEARlA+ybcoJKc4HbZb
# Ka9Sz1LpMUerVlx71Q0LQbPv7HUfdDjyslxhopyVw1Dkgrkj0bo6hnKtOHisdV0X
# FzRyR4WUVtHruzaEd8wkpfMEGVWp5+Pnq2LN+4stkMLA0rWUvV5PsQXSDj0aqRRb
# poYxYqioM+SbOafE9c4deHaUJXPkKqvPnHZL7V/CSxbkS3BMAIke/MV5vEwSV/5f
# 4R68Al2o/vsHOE8Nxl2RuQ9nRc3Wg+3nkg2NsWmMT/tZ4CMP0qquAHzunEIOz5HX
# J7cW7g/DvXwKoO4sCFWFIrjrGBpN/CohrUkxg0eVd3HcsRtLSxwQnHcUwZ1PL1qV
# CCkQJjGCBAMwggP/AgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAerFk2QcBFF
# 2MMlkeGbq2QwCQYFKw4DAhoFAKBAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MCMGCSqGSIb3DQEJBDEWBBSCVCOpqDE0cIwUk3nsveqbJmcirDANBgkqhkiG9w0B
# AQEFAASCAQALyFJHViUwVput4C5NKhA+aIeVFoP5j7OJ2Y0QgvA5S9TN1WAYkD55
# phfizhGxJD5mtG3VXs0v5H0xUC3QwgkxnjrFEhDRNWAPq+GhCgSBSHKtDJ2KCXwT
# Tut6NP7zvvQ/j4MpzK8KYPovZDqaIbWtE5oSFwY3HUm3injoZw5TAGn/noOhhECA
# 1qQoxCYYUbUTt+R+U0KhioJr/MfmNa71fZn+v08UoLUH3bazy2wiYCkjwyuraKi7
# UqKbJ3wrjiAV56HphiDWvM5TsXitNCalWN/QDtoYNrn23SW4P/sLliVZcVmCrSPF
# K8qm3PoqyYGONIoqVCV8luHT9I+E0fB6oYICDzCCAgsGCSqGSIb3DQEJBjGCAfww
# ggH4AgEBMHYwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNz
# dXJlZCBJRCBDQS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjEwMTExNTEx
# NTlaMCMGCSqGSIb3DQEJBDEWBBRPcDSwUpv6rLLiASRPvdXpOMjPUDANBgkqhkiG
# 9w0BAQEFAASCAQAdwtVqcqoWgSFKAxoiKy3JSsBtk1BdBmC7V83umppjkcb6DIrZ
# 3jWOGes+CgS2/yf0W8MA5/hVNBi7cdC1R6Jk1/Dk/JazilZxeeD1A8n5C1ja4CvB
# vPAnu5aoU6P1B1bWQUXEDPfe8VFw9Kd4U0VORxaIvsG/FPgct2r25bbVavEDPOQm
# QYNR4wBi5/0t/W0ditvCexyYm16nVJRfbPybI66pTjf+BXxF7WKdVOMkIzqA7AbR
# QDagUJHedkmBa4uuIyjjuDlpuvmIRJkzzsjebAjCOkHG50kGSVm7DVGCICK4tBex
# +UR7LiBkz0JUvI7uT7VxCt6hwDk4eOz0vBpl
# SIG # End signature block
