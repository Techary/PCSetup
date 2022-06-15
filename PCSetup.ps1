param([switch]$Elevated)

function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) 
    {
        # tried to elevate, did not work, aborting
    } 
    else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
}

exit

}

###############
## Functions ##
###############

#------------------------------------------------------------------------------------------------------------------------------------

function CountDown() {
    param($timeSpan)

    while ($timeSpan -gt 0)
  {
    Write-Host '.' -NoNewline
    $timeSpan = $timeSpan - 1
    Start-Sleep -Seconds 1
  }
}

Function invoke-debloat {

    $Bloatware = @(

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"

    )
    foreach ($Bloat in $Bloatware) 
        {
            Get-AppxPackage -Name $Bloat| Remove-AppxPackage
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
            Write-Output "Trying to remove $Bloat."
        }
}

function Remove-PreviousOfficeInstall {

    get-appxpackage | where {$_.name -like "*MicrosoftOfficeHub"} | remove-appxpackage

    new-item -ItemType "directory" -path C:\ODT -ErrorAction SilentlyContinue

    New-Item "C:\odt\configuration.xml"

    start-sleep 1

    Set-Content "C:\odt\configuration.xml" '<Configuration>
    <Display Level="none" CompletionNotice="no" SuppressModal="yes" AcceptEula="yes" />
    <Logging Level="Standard" Path="\\path\to\Logfile\RemoveOffice2016\Logs" />
    <Remove All="TRUE" />
    </Configuration>'

    start-sleep 1
    
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13929-20296.exe" -outfile "C:\odt\odt.exe"

    Set-Location C:\odt

    .\odt.exe /extract:C:\ODT /quiet

    start-sleep 1

    .\setup.exe /configure configuration.xml


}

function get-chrome {
    $url = "http://dl.google.com/chrome/install/375.126/chrome_installer.exe"
    $ChromePath = "C:\users\$env:username\chrome.exe"
    write-host "Downloading Google Chrome"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $ChromePath

    if((test-path $ChromePath) -eq "True")
        {

            Set-Location C:\users\$env:username
            .\chrome.exe /silent /install
            write-host "Installing chrome..."

        }
    else
        {

            Write-host "Chrome not downloaded, downloading..."
            get-chrome

        }
}

function get-office {

    new-item -ItemType "directory" -path C:\ODT -ErrorAction SilentlyContinue

    start-sleep 1

    Set-Content "C:\odt\configuration.xml" '<Configuration ID="ed9360b9-7bc9-42de-b1df-559951506f10">
                                            <Add OfficeClientEdition="64" Channel="Current">
                                                <Product ID="O365BusinessRetail">
                                                <Language ID="MatchOS" />
                                                <ExcludeApp ID="Groove" />
                                                </Product>
                                            </Add>
                                            <Property Name="SharedComputerLicensing" Value="0" />
                                            <Property Name="SCLCacheOverride" Value="0" />
                                            <Property Name="AUTOACTIVATE" Value="0" />
                                            <Property Name="FORCEAPPSHUTDOWN" Value="FALSE" />
                                            <Property Name="DeviceBasedLicensing" Value="0" />
                                            <Updates Enabled="TRUE" />
                                            <RemoveMSI />
                                            <AppSettings>
                                                <Setup Name="Company" Value=" " />
                                                <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas" />
                                                <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas" />
                                                <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas" />
                                            </AppSettings>
                                            <Display Level="none" AcceptEULA="TRUE" />
                                            </Configuration>'

    start-sleep 1

    Set-Location C:\odt

    .\setup.exe /configure configuration.xml

}

function get-Adobe {

    $url = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/2100120155/AcroRdrDC2100120155_en_US.exe"
    $AdobePath = "C:\users\$env:username\adobe.exe"
    write-host "Downloading Adobe Acrobat"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $AdobePath

    if((test-path -path $AdobePath) -eq "True")
        {

            Start-Process -filepath $AdobePath -ArgumentList "/sPB /rs"
            write-host "Installing Adobe... "

        }
    else
        {

            Write-host "Adobe Acrobat not downloaded, downloading..."
            get-adobe
            
        }
}

function Get-S1 {

    Param
        (

            [Parameter(Mandatory=$true)][string]$token

        )

    invoke-webrequest "content.techary.com/SentinelInstaller-x64_windows_64bit_v21_7_5_1080.exe" -OutFile "SentinelOneAgent.exe"


    .\SentinelOneAgent.exe /SITE_TOKEN=$token /silent /norestart


}

function add-VPN {

    function get-VPNInformation {

        $global:vpnName = read-host "`nEnter the name you want the VPN to display"

        $global:serveraddress = read-host "`nEnter the hostname (recommended) or IP of the VPN server"

        $global:psk = read-host "`nEnter the PSK of the L2TP VPN"

        $global:VPNUsername = read-host "`nEnter the username for the VPN"

        $global:VPNPassword = read-host "`nEnter the password for the VPN"

        do {
            $confirm = read-host "You have entered: `nVPN Name: $global:vpnname `nServer Address: $global:serveraddress `nPSK: $global:psk `nVPN Username: $global:VPNUsername `nVPN Password: $global:VPNPassword `nIs this correct? Y/N"
            switch ($confirm)
                    {
                        Y {add-vpn}
                        N {get-VPNInformation}
                        default {"You didn't enter an expected response, you idiot."}
                    } 
                } until ($confirm -eq 'Y' -or $confirm -eq 'N')

    }

    function add-vpn {

        try
            {

                Add-VpnConnection -Name $global:vpnName -ServerAddress $global:serveraddress  -TunnelType "L2tp" -L2tpPsk $global:psk -AuthenticationMethod Pap -SplitTunneling -RememberCredential -PassThru -ErrorAction SilentlyContinue

            }
        catch
            {

                Write-Output "Unable to add VPN"
                $_.Exception

            }       

    }

    get-VPNInformation

}

function connect-vpn {

    $vpn = Get-VpnConnection -Name $global:vpnName

    if($vpn.ConnectionStatus -eq "Disconnected"){
    rasdial $global:vpnName "$global:VPNUsername" "$global:VPNPassword";
    }

}
                
function add-domain {

    $domain = read-host "`nEnter the domain name"

    if ((Test-netconnection $domain).pingsucceeded){
            do 
                {
                    $joined = $true
                    $cred = Get-Credential
                    try 
                        {
                            Add-Computer -DomainName $Domain -Credential $cred -ErrorAction Stop
                        } 
                    catch 
                        {
                            $joined = $false
                            switch -regex ($_.Exception.Message) {
                            '.*unknown user name.*'     { ... }
                            '.*domain does not exist.*' { ... }
                            default                     { 'Unexpected error' }
                            }
                    }
                } until ($joined)
            }
    else {write-host -ForegroundColor Red "Domain not found, check DNS settings and try again."
          add-domain
        }  
}

function Install-allWindowsUpdates {

    if (get-module pswindowsupdate) 
        {
        
            write-output "PSwindowsupdate module found!"
        
        }
    else    
        {

            write-output "PSwindowsupdate module not found, installing..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider NuGet -force
            install-module pswindowsupdate -Force -SkipPublisherCheck
            import-module pswindowsupdate

        }

    $updates = get-windowsupdate | where {$_.LastDeploymentChangeTime -lt (get-date).AddDays(-7) -and $_.kb -ne ""}

    if ($null -ne $updates)
        {

            foreach($update in $updates) 
                {
                        if ($update.title -like "*Cumulative*" `
                            -or $update.title -like "*security*" `
                            -or $update.title -like "*Malicious*" `
                            -or $update.title -like "*update for windows*" `
                            -or $update.title -like "*update for microsoft defender")
                            {
                
                                Write-output "Installing $($update.kb)"
                                install-windowsupdate -KBArticleID $update.kb -AcceptAll -forceDownload -ForceInstall -IgnoreReboot | Select-Object result
                
                            }
                        
                }
        }
    else
        {

            write-output "No relevant updates found"

        }

}


function cleanUp {

    Remove-Item -recurse -force "C:\odt"

    Remove-Item -recurse "C:\users\$env:username\adobe.exe"

    Remove-Item -recurse "C:\users\$env:username\chrome.exe"


}

############
## Script ##
############


# -----------------------------------------------------------------------------------------------------------------

invoke-debloat

do {
    $Addvpn = read-host "Do you need to add a VPN? y/n "
    switch ($Addvpn)
        {
            y { add-VPN
                
            }

            n { continue }
            Default { "You didn't enter an expect response, you idiot." }
        }
     }
     until ($Addvpn-eq 'y' -or $Addvpn -eq 'n')

do {
    $dovpn = read-host "Do you need to connect to the previously added VPN? y/n "
    switch ($dovpn)
        {
            y { connect-vpn
            }

            n { continue }
            Default { "You didn't enter an expect response, you idiot." }
        }
        }
        until ($dovpn-eq 'y' -or $dovpn -eq 'n')

do {
    $doAddDomain = read-host "Do you need to connect to a domain? y/n "
    switch ($doAddDomain)
        {
            y { add-domain
                
            }

            n { continue }
            Default { "You didn't enter an expect response, you idiot." }
        }
     }
     until ($doAddDomain-eq 'y' -or $doAddDomain -eq 'n')

Remove-PreviousOfficeInstall

get-chrome

get-office

get-adobe

do {
    $DoS1 = read-host "Do you need to Install S1? Y/N"
    switch ($DoS1)
        {
            y {

               $token = read-host "Enter the S1 token. Copy and paste"
               get-s1 $token 
                
            }

            n { continue }
            Default { "You didn't enter an expect response, you idiot." }
        }
     }
     until ($DoS1-eq 'y' -or $DoS1 -eq 'n')

Install-allWindowsUpdates

cleanup