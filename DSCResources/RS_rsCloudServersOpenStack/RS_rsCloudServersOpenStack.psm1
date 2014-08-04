$VerbosePreference = "Continue"
. "C:\cloud-automation\secrets.ps1"
. "$($d.wD, $d.mR, "scriptData.ps1" -join '\')"

Function Get-ServiceCatalog {
  return (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $($d.cU); "apiKey" = $($d.cAPI)}}} | convertTo-Json) -ContentType application/json)
}

Function Test-PrefsContainer {
  param (
    [string]$container
  )
  if((Invoke-RestMethod -Uri "https://prefs.api.rackspacecloud.com/v1/" -Headers $AuthToken -Method Get -ContentType applicaton/json) -notcontains $container) {
    return $false
  }
  else {
    return $true
  }
}
Function Check-Log {
  if((Get-EventLog -List).Log -notcontains "DevOps") {
    New-EventLog -LogName "DevOps" -Source "RS_rsCloudServersOpenStack"
  }
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
    $returnvalue = $returnValue | ? {$_.metadata.environmentGuid -like $environmentGuid}
  }
  else
  {
    $returnvalue = $null
  }
  foreach($value in $returnValue) {
    write-verbose "Get-DevicesInEnvironment $value"
  }
  return $returnValue
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
Function Find-MissingDevices {
  param (
    [string[]]$actualDevices,
    [string[]]$configDevices
  )
  $missingDevices = @()
  foreach($actualDevice in $actualDevices) {
    if($configDevices -notcontains $actualDevice) {
      $missingDevices += $actualDevice
    }
  }
  write-verbose "Building list of Missing Servers"
  foreach($missingDevice in $missingDevices) {
    write-verbose "Find-MissingDevices $missingDevice"
  }
  return $missingDevices
  
}
Function Update-PreferenceContainer {
  param (
    [string]$container,
    [string]$body
  )
  $uri = ("https://prefs.api.rackspacecloud.com/v1/" + $container)
  Invoke-RestMethod -Uri "https://prefs.api.rackspacecloud.com/v1/" -Headers $AuthToken -Body $body -Method Post -ContentType applicaton/json
}
Function Create-MonitoringEntity {
  param (
    [string]$environmentGuid,
    [string]$dataCenter
  )
  
  $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
  $envServers = (Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid)
  $entityuri = ($monitoruri, "entities" -join '/')
  $tokenuri = ($monitoruri, "agent_tokens" -join '/')
  try {
    $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
  }
  catch {
    Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve agent_tokens `n $tokenuri `n $($_.Exception.Message)"
  }
  try {
    $entityIds = (((Invoke-RestMethod -Uri $entityuri -Method GET -Headers $AuthToken).values).agent_id)
  }
  catch {
    Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve entity IDs `n $entityuri `n $($_.Exception.Message)"
  }
  ### create entity
  foreach($server in $envServers) {
    if($entityIds -notcontains $server.id) {
      $ipobject = @{"public" = ($server.addresses.public.Addr | ? {$_ -notmatch '^2001:'}); "private" = ($server.addresses.private.Addr)}
      $serveruri = ((((($catalog.access.serviceCatalog | Where-Object Name -Match "cloudServersOpenStack").endpoints) | ? region -eq $dataCenter).publicURL), $server.id -join '/')
      $body = @{'label'=$server.name; 'ip_addresses'=$ipobject;'agent_id'=$server.id} | ConvertTo-Json
      try {
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Create Montitoring Entity `n $entityuri `n $body"
        Invoke-RestMethod -Uri $entityuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json
      }
      catch {
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create Montitoring Entity `n $entityuri `n $($_.Exception.Message)"
      }
    }
    if($agent_tokens.label -notcontains $server.id) {
      $body = @{'label' = $($server.id);} | ConvertTo-Json
      try {
        Invoke-RestMethod -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json
        $agentToken = (((Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values) | ? {$_.label -eq $server.id}).token 
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Getting Agent Token `n $($server.id) `n $agentToken"
      }
      catch {
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to Create Token `n $tokenuri `n $($_.Exception.Message)"
      }
      try {
        if(Test-Path -Path ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $server.id + ".mof")) {
          Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $server.id + "*") -Force
        }
        & $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.name -ObjectGuid $server.id -MonitoringID $server.id -MonitoringToken $agentToken
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Hash Mismatch: Creating MOF file for server $($server.name) $($server.id)"
      }
      catch {
        Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create MOF file for server $server with Guid $($server.id) `n $($_.Exception.Message)"
      }
    }
  }
}
Function Create-Mofs {
  param (
    [string]$environmentGuid,
    [string]$dataCenter
  )
  $envServers = (Get-DevicesInEnvironment -dataCenter $dataCenter -environmentGuid $environmentGuid)
  $checkHash = Get-FileHash $($d.wD, $d.mR, "ClientDSC.ps1" -join '\')
  $currentHash = Get-Content $($d.wD, $d.mR, "ClientDSC.hash" -join '\')
  $monitoruri = (($catalog.access.serviceCatalog | Where-Object Name -Match "cloudMonitoring").endpoints).publicURL
  $tokenuri = ($monitoruri, "agent_tokens" -join '/')
  try {
    $agent_tokens = (Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values
  }
  catch {
    Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve agent_tokens `n $tokenuri `n $($_.Exception.Message)"
  }
   <#foreach($server in $envServers) {
      if($agent_tokens.label -notcontains $server.id) {
         $body = @{'label' = $server.id} | ConvertTo-Json
         try {
            $agentToken = Invoke-RestMethod -Uri $tokenuri -Method POST -Headers $AuthToken -Body $body -ContentType application/json
         }
         catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve Agent Token `n $tokenuri `n $($_.Exception.Message)"
         }
      }
   }#>
  <#if($checkHash.Hash -ne $currentHash) {
    $dataCenters = @("DFW", "ORD", "IAD")
    try {
      $envs = ((Invoke-RestMethod -Uri "https://prefs.api.rackspacecloud.com/v1/WinDevOps" -Method GET -Headers $AuthToken -ContentType application/json | Get-Member -MemberType NoteProperty).Name)
    }
    catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to retrieve environment guids from ServerMill `n $($_.Exception.Message)"
    }
    Set-Content -Path $($d.wD, $d.mR, "ClientDSC.hash" -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, "ClientDSC.ps1" -join '\')).hash
    foreach($dc in $dataCenters) {
      foreach($env in $envs) {
        $envServers = (Get-DevicesInEnvironment -dataCenter $dc -environmentGuid $env)
        foreach($server in $envServers) {
          $agentToken = (((Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values) | ? {$_.label -eq $server.id}).token
          try {
            if(Test-Path -Path ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $server.id + ".mof")) {
              Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $server.id + "*") -Force
            }
            #& $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.name -ObjectGuid $server.id -MonitoringID $server.id -MonitoringToken $agentToken
            & $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.name -ObjectGuid $server.id
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Hash Mismatch: Creating MOF file for server $($server.name) $($server.id)"
          }
          catch {
            Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create MOF file for server $server with Guid $($server.id) `n $($_.Exception.Message)"
          }
        }
      }
    }
  }#>
  #else {
  #Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + "*") -Force
  $allGuids = (Invoke-RestMethod -Uri "https://prefs.api.rackspacecloud.com/v1/WinDevOps" -Method GET -Headers $AuthToken -ContentType application/json | Get-Member -MemberType NoteProperty).Name
  $serverGuids = @()
    foreach($eachGuid in $allGuids) {
      $serverGuids += (Get-DevicesInPreferences -environmentGuid $eachGuid)
    }


  foreach($server in $serverGuids) {
    #if($currentMofs -notcontains $server.id) {
    $agentToken = (((Invoke-RestMethod -Uri $tokenuri -Method GET -Headers $AuthToken).values) | ? {$_.label -eq $server.guid}).token
    try {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "Creating MOF file for server $($server.serverName) `n  $agentToken `n $currentMofs `n $($server.id)"
      Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $server.guid + "*") -Force
      & $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.serverName -ObjectGuid $server.guid -MonitoringID $server.guid -MonitoringToken $agentToken
      #& $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.name -ObjectGuid $server.id
    }
    catch {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Error -EventId 1002 -Message "Failed to create configuration .MOF file for $($server.serverName) `n $($_.Exception.Message)"
    }
    #}
  }
  $currentMofs = ((get-item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\*") | Select-Object -Property BaseName | ? {$_ -NotMatch ".mof"}).BaseName)
  <#foreach($currentMof in $currentMofs) {
    if($envServers.id -notcontains $currentMof) {
      Write-EventLog -LogName DevOps -Source RS_rsCloudServersOpenStack -EntryType Information -EventId 1000 -Message "deleting $currentMof"
      Remove-Item ("C:\Program Files\WindowsPowerShell\DscService\Configuration\" + $currentMof + "*") -Force
      
    }
  }#>
  #}
}
### compare against servers in DSC

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
    [Parameter][string]$validationKey,
    [Parameter][string]$decryptionKey
    
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
    [Parameter][string]$validationKey,
    [Parameter][string]$decryptionKey
    
  )
  $Global:catalog = Get-ServiceCatalog
  $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
  Check-Log
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
  if($Ensure -eq "Present") {
    Create-MonitoringEntity -environmentGuid $environmentGuid -dataCenter $dataCenter
    Create-Mofs -environmentGuid $environmentGuid -dataCenter $dataCenter
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
    [Parameter][string]$validationKey,
    [Parameter][string]$decryptionKey
    
  )
  $Global:catalog = Get-ServiceCatalog
  $Global:AuthToken = @{"X-Auth-Token"=($catalog.access.token.id)}
  Check-Log
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
    
    ### Spin up servers
    if($spinUpServerList) {
      write-verbose "spinUpServerList contains servers to spin up"
      foreach($spinUpServerList1 in $spinUpServerList) {
        write-verbose "SpinUpServer $spinUpServerList1"
      }
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
          powershell.exe (Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $missingServer, -ObjectGuid $createServer.server.id
          #& $(Join-Path $scriptData.Directory.scriptsRoot -ChildPath ClientDSC.ps1) -Node $server.name -ObjectGuid $missingServer.id -MonitoringID $missingServer.id -MonitoringToken $agentToken
          
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
          $newServerInfo += @{"serverName" = $missingServer; "guid" = $createServer.server.id}
        }
        $logEntry = ("Spinning up Cloud server {0} with guid {1} {2} body {3}" -f $missingServer, $createServer.server.id, $createServer.server, $body)
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
          $value = @{"serverName" = $server.name; "guid" = $server.id; "public" = ($server.addresses.public.Addr | ? {$_ -notmatch '^2001:'}); "private" = ($server.addresses.private.Addr)}
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
        $value = @{"serverName" = $server.name; "guid" = $server.id; "public" = ($server.addresses.public.Addr | ? {$_ -notmatch '^2001:'}); "private" = ($server.addresses.private.Addr)}
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