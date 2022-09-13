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

#Removes pre-installed windows bloatware
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
            Write-Output "Trying to remove $Bloat."
            try
                {

                    Get-AppxPackage -Name $Bloat -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
                    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction Stop

                }
            catch
                {
                    Write-Output "Unable to uninstall $bloat" $_.Exception
                    $uninstallError = $true
                }
            finally
                {

                    if ($uninstallError -ne $true)
                        {

                            write-output "$bloat uninstalled successfully"

                        }

                }


        }
}

#removes previous installations of office (either windows app store or standalone launcher)
function Remove-PreviousOfficeInstall {

    #Removes windows app store version of office
    get-appxpackage | where {$_.name -like "*MicrosoftOfficeHub"} | remove-appxpackage

    #Creates the configuration xml, blank
    New-Item "C:\temp\configuration.xml"

    start-sleep 1
    #Fills out the configuration xml with instructions to remove any instances of office installed via the standalone launcher
    Set-Content "C:\temp\configuration.xml" '<Configuration>
    <Display Level="none" CompletionNotice="no" SuppressModal="yes" AcceptEula="yes" />
    <Logging Level="Standard" Path="\\path\to\Logfile\RemoveOffice2016\Logs" />
    <Remove All="TRUE" />
    </Configuration>'

    start-sleep 1
    #Downloads the ODT tool
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13929-20296.exe" -outfile "C:\temp\odt.exe"

    Set-Location C:\temp
    #Extracts the setup.exe from the ODT tool
    .\odt.exe /extract:C:\temp /quiet

    start-sleep 1
    #Installs office via the setup.exe, using the configuration xml created on line 85
    .\setup.exe /configure configuration.xml


}

#Installs chrome
function get-chrome {
    #Downloads chrome installer
    $chrome = @{

                    uri = "http://dl.google.com/chrome/install/375.126/chrome_installer.exe"
                    outfile = "C:\temp\chrome.exe"

                }
    write-host "Downloading Google Chrome"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest @chrome
    #Ensures that chrome is downloaded (somtimes the download fails)
    if((test-path $Chrome.outfile) -eq "True")
        {
            #If downloaded, silently launches the installer
            start-process -filepath $chrome.outfile -ArgumentList "/silent /install" -Wait
            write-host "Installing chrome..."

        }
    else
        {
            #If not downloaded, downloads
            Write-host "Chrome not downloaded, downloading..."
            get-chrome

        }
}

#Installs office 365
function get-office {

    #Changes the configuration xml to install the correct version of office
    Set-Content "C:\temp\configuration.xml" '<Configuration ID="ed9360b9-7bc9-42de-b1df-559951506f10">
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

    Set-Location C:\temp
    #Installs office via the setup.exe, using the configuration xml created on line 138. If you're running this manually, ENSURE YOU HAVE RUN LINES 94 & 98 FIRST.
    .\setup.exe /configure configuration.xml

}

#Installs adobe
function get-Adobe {
    #Downloads the adobe installer
    $adobe = @{
                    uri = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/2100120155/AcroRdrDC2100120155_en_US.exe"
                    outfile = "C:\temp\adobe.exe"
              }
    write-host "Downloading Adobe Acrobat"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest @adobe
    #Ensures that adobe is downloaded (somtimes the download fails)
    if((test-path -path $Adobe.outfile) -eq "True")
        {
            #If downloaded, launches the installer
            Start-Process -filepath $Adobe.outfile -ArgumentList "/sPB /rs" -wait
            write-host "Installing Adobe... "

        }
    else
        {
            #If not downloaded, downloads
            Write-host "Adobe Acrobat not downloaded, downloading..."
            get-adobe

        }
}

#Installs S1 (THIS WILL NOT WORK WHEN RUNNING MANUALLY)
function Get-S1 {

    Param
        (

            [Parameter(Mandatory=$true)][string]$token

        )
    #Downloads the S1 installer from the Techary hosted FTP
    $s1 = @{

                uri = "content.techary.com/SentinelInstaller-x64_windows_64bit_v21_7_5_1080.exe"
                outfile = "C:\temp\SentinelOneAgent.exe"

            }
    $ProgressPreference = 'SilentlyContinue'
    invoke-webrequest @s1

    #Launches the S1 installer using the provided token
    start-process -FilePath $s1.outfile -ArgumentList "/SITE_TOKEN=$token /silent /norestart"


}

#Creates a windows VPN entry
function add-VPN {

    #Gets VPN setup info
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

    #Adds the VPN
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

#Connects to the VPN, if confirmed
function connect-vpn {

    $vpn = Get-VpnConnection -Name $global:vpnName

    if($vpn.ConnectionStatus -eq "Disconnected"){
    rasdial $global:vpnName "$global:VPNUsername" "$global:VPNPassword";
    }

}

#Adds to the domain
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

#Installs ALL released windows updates
function Install-allWindowsUpdates {

    #Installs the PSWINDOWSUPDATE module
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

    #Collats all windows updates
    $updates = Get-WindowsUpdate
    #Checks if $updates is null
    if ($null -ne $updates)
        {
            #If not null, only installs updates with titles that match the below strings
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

#Removes installers and created temp dir's
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
if ($Addvpn -eq "Y")
    {
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
    }

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