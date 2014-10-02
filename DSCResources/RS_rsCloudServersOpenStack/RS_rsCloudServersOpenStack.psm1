$VerbosePreference = "Continue"
. "C:\cloud-automation\secrets.ps1"

Function Get-ServiceCatalog {
   return (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
}
Function Get-DevicesInEnvironment {
   param (
      [string]$dataCenter,
      [string]$environmentGuid
   )
   $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dataCenter).publicURL
   write-verbose "Get-DevicesInEnvironment URI $uri"
   $returnValue = ((Invoke-RestMethod -Uri $($uri + "/servers/detail") -Method GET -Headers $AuthToken -ContentType application/json).servers)
   if ( ($returnValue.metadata | ? { $_ -like "*environmentGuid*"}).count -ne 0 )
   {
      $status = @("Deleted", "Error", "Unknown")
      $servers = $returnValue | ? {$_.metadata.environmentGuid -like $environmentGuid}
      $resultServers = @()
      foreach($server in $servers) {
         if($status -notcontains $server.status) {
            $resultServers += $server
         }
         
      }
   }
   else
   {
      $resultServers = $null
   }
   return $resultServers
}
Function Get-DevicesInConfiguration {
   param (
      [uint32]$minNumberOfDevices,
      [string]$namingConvention
   )
   $devices = @()
   for($x = 1; $x -lt $minNumberOfDevices + 1; $x++) {
      $devices += $namingConvention + "{0:D2}" -f $x
   }
   write-verbose "Building list of servers from DSC configuration"
   foreach($device in $devices) {
      write-verbose "Get-DevicesInConfiguration $device"
   }
   return $devices
}
Function Get-DevicesInPreferences {
   param (
      [string]$environmentGuid
   )
   $uri = "https://prefs.api.rackspacecloud.com/v1/WinDevOps"
   try {
      $testPrefs = (Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ContentType applicaton/json)
   }
   catch {
      if($testPrefs -eq $null) {
         $uri = "https://prefs.api.rackspacecloud.com/v1/WinDevOps"
         (Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Post -ContentType applicaton/json)
      }
   }
   $uri = ("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid, "servers" -join '/')
   try {
      write-verbose "retrieving list of servers in ServerMill Preferences"
      $returnValue = ((Invoke-RestMethod -Uri $uri -Headers $AuthToken -Method Get -ContentType applicaton/json).servers)
      foreach($value in $returnValue) {
         write-verbose "Devices Get-DevicesInPreferences $value.serverName"
      }
      return $returnValue
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve devices from ServerMill preferences `n $($_.Exception.Message)"
   }
}

Function Test-Environment {
   param (
      [string]$environmentGuid,
      [uint32]$minNumberOfDevices,
      [uint32]$maxNumberOfDevices,
      [string]$namingConvention,
      [string]$dataCenter,
      [string]$Ensure
   )
   $dscServers = (Get-DevicesInConfiguration -minNumberOfDevices $minNumberOfDevices -namingConvention $namingConvention)
   foreach($dscServer in $dscServers) {
      Write-Debug "dscservers $dscServer"
   }
   #$prefServers = ((Get-DevicesInPreferences -environmentGuid $environmentGuid).serverName)
   $prefServers = (Get-DevicesInPreferences -environmentGuid $environmentGuid)
   foreach($prefServer in $prefServers) {
      Write-Debug "prefservers $prefServer"
   }
   try {
      $prefsIPs = ((Get-DevicesInPreferences -environmentGuid $environmentGuid).public)
   }
   catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "No public IP address found in ServerMill preferences $($_.Exception.Message)"
   }
   $envServers = (Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid).name
   foreach($envServer in $envServers) {
      Write-Debug "envservers $envServer"
   }
   $spinUpServerList = @()
   $spinDownServerList = @()
   $updatePrefsList = @()
   
   foreach($dscServer in $dscServers) {
      ### ServerMill Prefs & DSC configuration shows this server should be spun up but is not found in the environment
      ### This looks like a manual spindown of a server
      if(($prefServers.serverName -contains $dscServer) -and $envServers -notcontains $dscServer) {
         Write-Debug $Ensure
         if($Ensure -eq "Present") {
            $spinUpServerList += $dscServer
            Write-Debug "Present T T F Spin Server $dscServer"
         }
      }
      if(($prefServers.servername -notcontains $dscServer) -and $envServers -notcontains $dscServer) {
         ### ServerMill Prefs does not have the server that DSC has and the server is not found in the environment
         ### This looks like a new server build
         if($Ensure -eq "Present") {
            $spinUpServerList += $dscServer
            Write-Debug "Present T F F Spin Server $dscServer and update prefs"
         }
      }
      if(($prefServers.serverName -notcontains $dscServer) -and $envServers -contains $dscServer) {
         ### ServerMill Prefs does not contain the server that DSC has and the server is found in the environment
         ### This looks like a mismatch with ServerMill prefs, will update to match DSC as DSC is authoritive
         if($Ensure -eq "Present") {
            $updatePrefsList += $dscServer
            Write-Debug "Present T F T update prefs"
         }
      }
   }
   foreach($envServer in $envServers) {
      ### ServerMill Prefs contains the server found in the environment but DSC does not have the server configured
      ### This looks like a new spin down
      if(($prefServers.serverName -contains $envServer) -and $dscServers -notcontains $envServer) {
         if($Ensure -eq "Present") {
            $spinDownServerList += $envServer
            Write-Debug "Present F T T Spin Down $envServer.name Update Prefs"
         }
      }
      # if(($prefServers -notcontains $envServer) -and $dscServers -notcontains $envServer) {
      # Write-Host "F F T Spin Down $envServer"
      # }
   }
   foreach($prefServer in $prefServers) {
      ### DSC configuration does not contain the server found in ServerMill Prefs and the server is not found in the environment
      ### This looks like a ServerMill mismatch and will update to match DSC as DSC is authoritive
      if(($dscServers -notcontains $prefServer.serverName) -and $envServers -notcontains $prefServer.serverName -or $prefServer.public -eq $null) {
         if($Ensure -eq "Present") {
            $updatePrefsList += $prefServer.serverName
            Write-Debug "Present F T F Extra server in Prefs Update Prefs"
         }
      }
      
   }
   return @{"spinUpServerList" = $spinUpServerList; "spinDownServerList" = $spinDownServerList; "updatePrefsList" = $updatePrefsList}
}




Function Get-TargetResource
{
   param
   (
      [ValidateSet('Present','Absent')][string]$Ensure = 'Present',
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$BuildTimeOut,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentGuid,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$minNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$maxNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$namingConvention,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$image,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$nflavor,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$dataCenter,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$role,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$pullServerName,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$validationKey,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$decryptionKey,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentName 
   )
   @{
        environmentGuid = $environmentGuid
        minNumberOfDevices = $minNumberOfDevices
        maxNumberOfDevices = $maxNumberOfDevices
        namingConvention = $namingConvention
        image = $image
        nflavor = $nflavor
        dataCenter = $dataCenter
        role = $role
        pullServerName = $pullServerName
        validationKey = $validationKey
        decryptionKey = $decryptionKey
        Ensure = $Ensure
        BuildTimeOut = $BuildTimeOut
        environmentName = $environmentName

    }
   
}

Function Test-TargetResource
{
   param
   (
      [ValidateSet('Present','Absent')][string]$Ensure = 'Present',
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$BuildTimeOut,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentGuid,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$minNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$maxNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$namingConvention,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$image,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$nflavor,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$dataCenter,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$role,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$pullServerName,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$validationKey,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$decryptionKey,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentName 
   )
   $Global:catalog = Get-ServiceCatalog
   $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   Write-Verbose "Test-TargetResource sending call to Test-Environment using $environmentGuid $minNumberOfDevices $maxNumberOfDevices $namingConvention $dataCenter"
   $testEnvironmentResults = Test-Environment -environmentGuid $environmentGuid -minNumberOfDevices $minNumberOfDevices -maxNumberOfDevices $maxNumberOfDevices -namingConvention $namingConvention -dataCenter $dataCenter -Ensure $Ensure
   $spinUpServerList = $testEnvironmentResults.spinUpServerList
   foreach($spinUpServerList1 in $spinUpServerList) {
      Write-Verbose "Test-TargetResource spinUpServerList $spinUpServerList1"
   }
   $spinDownServerList = $testEnvironmentResults.spinDownServerList
   foreach($spinDownServerList1 in $spinDownServerList) {
      Write-Verbose "Test-TargetResource spinDownServerList $spinDownServerList1"
   }
   $updatePrefsList = $testEnvironmentResults.updatePrefsList
   foreach($updatePrefsList1 in $updatePrefsList) {
      Write-Verbose "Test-TargetResource updatePresList $updatePrefsList1"
   }
   if($Ensure -eq "Absent") {
      return $false
   }
   if($spinUpServerList) {
      write-verbose "Test-TargetResource spinUpServerList is not null"
      return $false
   }
   if($spinDownServerList) {
      write-verbose "Test-TargetResource spinDownServerList is not null"
      return $false
   }
   if($updatePrefsList) {
      write-verbose "Test-TargetResource updatePrefsList is not null"
      return $false
   }
   else {
      write-verbose "Test-TargetResource Environment is good"
      return $true
   }
}

Function Set-TargetResource
{
   param
   (
      [ValidateSet('Present','Absent')][string]$Ensure = 'Present',
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$BuildTimeOut,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentGuid,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$minNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][uint32]$maxNumberOfDevices,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$namingConvention,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$image,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$nflavor,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$dataCenter,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$role,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$pullServerName,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$validationKey,
      [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$decryptionKey,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$environmentName 
   )
   $Global:catalog = Get-ServiceCatalog
   $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
   $imageUrl = ((($catalog.access.serviceCatalog | ? {$_.name -eq "cloudImages"}).endpoints) | ? {$_.region -eq $dataCenter}).publicURL
   $image = (Invoke-RestMethod -Uri $($imageUrl + "/images?name=$($image.Replace(" ","+"))") -Method Get -Headers $authToken -ContentType application/json).images.id
   if($Ensure -eq "Present") {
      # Load credentials and local variables
      . "C:\cloud-automation\secrets.ps1"
      write-verbose "Set-TargetResource sending call to Test-Environment using $environmentGuid $minNumberOfDevices $maxNumberOfDevices $namingConvention $dataCenter"
      
      $testEnvironmentResults = Test-Environment -environmentGuid $environmentGuid -minNumberOfDevices $minNumberOfDevices -maxNumberOfDevices $maxNumberOfDevices -namingConvention $namingConvention -dataCenter $dataCenter -Ensure $Ensure
      $spinUpServerList = $testEnvironmentResults.spinUpServerList
      $spinDownServerList = $testEnvironmentResults.spinDownServerList
      $updatePrefsList = $testEnvironmentResults.updatePrefsList
      
      $AuthToken = @{"X-Auth-Token"=$catalog.access.token.id}
      $localPath = "C:\cloud-automation\bootstrap.cmd"
      $secretLocalPath = "C:\cloud-automation\secrets"
      
      $path = "C:\cloud-automation\bootstrap.cmd"
      $Content = Get-Content -Path $localPath -Encoding Byte
      $Base64 = [System.Convert]::ToBase64String($Content)
      
      $secretPath = "C:\cloud-automation\secrets"
      $secretContent = Get-Content -Path $secretLocalPath -Encoding Byte
      $secretBase64 = [System.Convert]::ToBase64String($secretContent)
      
      $uri = (($catalog.access.serviceCatalog | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dataCenter).publicURL
      $prefsUri = ("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid, "servers" -join '/')
      $serverPrefsObject = (Invoke-RestMethod -Uri $prefsUri -Headers $AuthToken -Method Get -ContentType application/json).servers
      $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
      $tokenuri = ($monitoruri, "agent_tokens" -join '/')
      ### Spin up servers
      if($spinUpServerList) {
         write-verbose "spinUpServerList contains servers to spin up"
         $newServerInfo = @()
         if($serverPrefsObject) {
            $newServerInfo += $serverPrefsObject
         }
         foreach($missingServer in $spinUpServerList) {
            $body = @{ "server" = @{ "name" = $missingServer; "imageRef" = $image; "flavorRef" = $nflavor; "metadata" = @{"Role" = $role; "environmentGuid" = "$environmentGuid"}; "personality" = @( @{ "path" = $path; "contents" = $Base64}; @{"path" = $secretPath; "contents" = $secretBase64})}} | convertTo-Json -Depth 3
            try {
               $createServer = Invoke-RestMethod -Uri $($uri + "/servers") -Method POST -Headers $AuthToken -Body $body -ContentType application/json
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to Spin up server `n $($_.Exception.Message)"
            }
            try {
               if(Test-Path -Path ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $createServer.server.id + ".mof")) {
                  Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $createServer.server.id + "*") -Force
               }
               try {
                  $body = @{'label' = $($createServer.server.id);} | ConvertTo-Json
                  $tempToken = ((Invoke-WebRequest -UseBasicParsing -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json).Headers).'X-Object-ID'
               }
               catch {
                  Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create temporary monitoring token `n $($_.Exception.Message)"
               }
               powershell.exe $($d.wD, $d.mR, $($environmentName + ".ps1") -join '\') -Node $missingServer -ObjectGuid $createServer.server.id -MonitoringID $createServer.server.id -MonitoringToken $tempToken
               
               Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Creating MOF file for server $missingServer"
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create MOF file for server $missingServer with Guid $createServer.server.id `n $($_.Exception.Message)"
            }
            Write-Verbose $body
            if($newServerInfo.serverName -contains $missingServer) {
               ($newServerInfo | ? serverName -eq $missingServer).guid = $createServer.server.id
            }
            else {
               $newServerInfo += @{"serverName" = $missingServer; "guid" = $createServer.server.id; "environmentName" = $environmentName; "monitoringToken" = $tempToken;}
            }
            $logEntry = ("Spinning up Cloud server {0} with guid {1}" -f $missingServer, $createServer.server.id)
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1002 -Message $logEntry
            write-verbose "spinning up server $missingServer"
            Start-Sleep -m 100
         }
         $body = @{"servers" = @( $newServerInfo )} | ConvertTo-Json -Depth 2
         Invoke-RestMethod -Uri $prefsUri -Headers $AuthToken -Method Post -Body $body -ContentType application/json
      }
      
      ### Delete server in environment
      if($spinDownServerList) {
         $envServers = (Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid)
         write-verbose "Set-TargetResource spinDownServerList is not null"
         foreach($server in $spinDownServerList) {
            $serverId = ($envServers | ? name -eq $server).id
            $uri = ((((($catalog.access.serviceCatalog) | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dataCenter).publicURL), "servers", $serverId -join '/')
            Write-EventLog -LogName "DevOps" -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Cloud server $server is tagged for deletion, deleting cloud server $server $serverId `n $uri"
            try {
               Write-Verbose "deleting server $server $serverId"
               $deleteServer = Invoke-RestMethod -Uri $uri -Method Delete -Headers $AuthToken -ContentType application/json
            }
            catch {
               Write-EventLog -LogName "DevOps" -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1001 -Message "Spin down of Cloud server failed, sent delete request to $uri with Error Message: `n $($_.Exception.Message)"
            }
            try {
               if(Test-Path -Path ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $serverId + ".mof")) {
                  Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $serverId + "*") -Force
               }
               Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Removing MOF file for deleted server $server"
            }
            catch {
               Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to remove MOF file for server $server with Guid $serverId `n $($_.Exception.Message)"
            }
         }
         if($updatePrefsList) {
            write-verbose "Set-TargetResource updatePrefsList is not null"
            $updateList = @()
            $servers = Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid
            foreach($server in $servers) {
               $value = @{"serverName" = $server.name; "guid" = $server.id; "public" = ($server.addresses.public.Addr | ? {$_ -notmatch '^2001:'}); "private" = ($server.addresses.private.Addr); "environmentName" = $environmentName}
               $updateList += $value
            }
            $body = @{"servers" = @( $updateList )} | ConvertTo-Json -Depth 2
            Invoke-RestMethod -Uri $prefsUri -Headers $AuthToken -Method Post -Body $body -ContentType application/json
         }
         
         #return $false
      }
      if($updatePrefsList) {
         write-verbose "Set-TargetResource updatePrefsList is not null"
         $updateList = @()
         $servers = Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid
         foreach($server in $servers) {
            $value = @{"serverName" = $server.name; "guid" = $server.id; "public" = ($server.addresses.public.Addr | ? {$_ -notmatch '^2001:'}); "private" = ($server.addresses.private.Addr); "environmentName" = $environmentName}
            $updateList += $value
         }
         $body = @{"servers" = @( $updateList )} | ConvertTo-Json -Depth 2
         Invoke-RestMethod -Uri $prefsUri -Headers $AuthToken -Method Post -Body $body -ContentType application/json
      }
   }
   ### Environment set to ABSENT -- Remove all servers from environment and delete servermill preference environment guid container.
   if($Ensure -eq "Absent") {
      $serversToRemove = Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid
      foreach($server in $serversToRemove) {
         $uri = ((((($catalog.access.serviceCatalog) | ? name -eq "cloudServersOpenStack").endpoints | ? region -eq $dataCenter).publicURL), "servers", $server.id -join '/')
         Write-Verbose $uri
         Write-EventLog -LogName "DevOps" -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Cloud server environment set to ABSENT, deleting cloud server $server"
         try {
            $deleteServer = Invoke-RestMethod -Uri $uri -Method Delete -Headers $AuthToken -ContentType application/json
         }
         catch {
            Write-EventLog -LogName "DevOps" -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1001 -Message $($_.Exception.Message)
         }
         try {
            if(Test-Path -Path ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $serverId + ".mof")) {
               Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $serverId + ".mof" + "*") -Force
            }
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Removing MOF file for deleted server $server"
         }
         catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to remove MOF file for server $server with Guid $serverId `n $($_.Exception.Message)"
         }
      }
      $prefsUri = ("https://prefs.api.rackspacecloud.com/v1/WinDevOps", $environmentGuid -join '/')
      if((Invoke-RestMethod -Uri "https://prefs.api.rackspacecloud.com/v1/WinDevOps" -Method GET -Headers $AuthToken -ContentType application/json | Get-Member -MemberType NoteProperty).Name -contains $environmentGuid) {
         Write-Debug "Removing preferences information for $environmentGuid"
         Write-EventLog -LogName "DevOps" -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1001 -Message "Cloud server environment set to ABSENT, deleting preference information in ServerMill for environment guid $environmentGuid"
         Invoke-RestMethod -Uri $prefsUri -Headers $AuthToken -Method Delete -ContentType application/json
      }
   }
   
}


Export-ModuleMember -Function *-TargetResource