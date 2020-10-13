param(
    [Parameter(Mandatory=$true)]$ResourceGroup,
    [Parameter(Mandatory=$true)]$Workspace,
    [Parameter(Mandatory=$true)]$ConnectorsFile,
    [Parameter(Mandatory=$true)]$Location
)

Install-Module AzSentinel -Scope CurrentUser -AllowClobber

Connect-AzAccount

$context = Get-AzContext

$SubscriptionId = $context.Subscription.Id

#Create Log Analytics workspace
try {

    $WorkspaceObject = Get-AzOperationalInsightsWorkspace -Name $Workspace -ResourceGroupName $ResourceGroup  -ErrorAction Stop
    $ExistingtLocation = $WorkspaceObject.Location
    Write-Output "Workspace named $Workspace in region $ExistingLocation already exists."

} catch {

    Write-Output "Creating new workspace named $Workspace in region $Location..."
    # Create the new workspace for the given name, region, and resource group
    New-AzOperationalInsightsWorkspace -Location $Location -Name $Workspace -Sku Standard -ResourceGroupName $ResourceGroup

}

$solutions = Get-AzOperationalInsightsIntelligencePack -resourcegroupname $ResourceGroup -WorkspaceName $Workspace -WarningAction:SilentlyContinue

if (($solutions | Where-Object Name -eq 'SecurityInsights').Enabled) {
    Write-Host "SecurityInsights solution is already enabled for workspace $($Workspace)"
}
else {
    Set-AzSentinel -WorkspaceName $Workspace -Confirm:$false
}

#Resource URL to authentincate against
$Resource = "https://management.azure.com/"

#Urls to be used for Sentinel API calls
$baseUri = "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"


#Getting all rules from file
$connectors = Get-Content -Raw -Path $ConnectorsFile | ConvertFrom-Json

foreach ($connector in $connectors.connectors) {
    Write-Host "`r`nProcessing connector: " -NoNewline 
    Write-Host "$($connector.kind)" -ForegroundColor Blue

    #AzureActivityLog connector
    if ($connector.kind -eq "AzureActivityLog") {
        $SubNoHyphens = $SubscriptionId -replace '-',''
        $uri = "$baseUri/datasources/${SubNoHyphens}?api-version=2015-11-01-preview"
        $connectorBody = ""
        $activityEnabled = $false

        #Check if AzureActivityLog is already connected (there is no better way yet) [assuming there is only one AzureActivityLog from same subscription connected]
        try {
            # AzureActivityLog is already connected, compose body with existing etag for update
            $result = Invoke-AzRestMethod -Path $uri -Method GET
            if ($result.StatusCode -eq 200){
                Write-Host "Successfully queried data connector ${connector.kind} - already enabled"
                Write-Verbose $result
                Write-Host "Updating data connector $($connector.kind)"

                $activityEnabled = $true
            }
            else {
                Write-Host "$($connector.kind) data connector is not enabled yet"
                Write-Host "Enabling data connector $($connector.kind)"
                $activityEnabled = $false
            }
        }
        catch { 
            $errorReturn = $_
        }

        $connectorProperties = @{
            linkedResourceId = "/subscriptions/${SubscriptionId}/providers/microsoft.insights/eventtypes/management"
        }        
                
        $connectorBody = @{}

        $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
        $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connector.properties

        #Enable or Update AzureActivityLog Connector with http puth method
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($activityEnabled) {
                Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                Write-Host 
            }
            else {
                Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
            }
             
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_.Exception.Message
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }  
    }

    #AzureSecurityCenter connector
    elseif ($connector.kind -eq "AzureSecurityCenter") {
        $ascEnabled = $false
        $guid = (New-Guid).Guid
        $etag = ""
        $connectorBody = ""
        $uri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2020-01-01"

        #Query for connected datasources and search AzureSecurityCenter
        try {
            $result = (Invoke-AzRestMethod -Path $uri -Method GET).Content | ConvertFrom-Json
            foreach ($value in $result.value){
                # Check if ASC is already enabled (assuming there will be only one ASC per workspace)
                if ($value.kind -eq "AzureSecurityCenter") {
                    Write-Host "Successfully queried data connector $($value.kind) - already enabled"
                    Write-Verbose $value
                    $guid = $value.name
                    $etag = $value.etag
                    $ascEnabled = $true
                    break
                }
            }
        }
        catch {
            $errorReturn = $_
        }

        if ($ascEnabled) {
            # Compose body for connector update scenario
            Write-Host "Updating data connector $($connector.kind)"
            Write-Verbose "Name: $guid"
            Write-Verbose "Etag: $etag"
            
            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName subscriptionId -NotePropertyValue ${context}.Subscription.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $guid -Force
            $connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $etag -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connector.properties
        }
        else {
            # Compose body for connector enable scenario
            Write-Host "$($connector.kind) data connector is not enabled yet"
            Write-Host "Enabling data connector $($connector.kind)"
            Write-Verbose "Name: $guid"

            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName subscriptionId -NotePropertyValue ${context}.Subscription.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties

        }

        # Enable or update AzureSecurityCenter with http put method
        $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($result.StatusCode -eq 200) {
                if ($ascEnabled){
                    Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                }
                else {
                    Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
                }
            }
            else {
                Write-Error "Unable to enable data connector $($connector.kind) with error: $result.Content"
            }
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
    #Office365 connector
    elseif ($connector.kind -eq "Office365") {
        $o365Enabled = $false
        $guid = (New-Guid).Guid
        $etag = ""
        $connectorBody = ""
        $uri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2020-01-01"

        #Query for connected datasources and search Office365
        try {
            $result = (Invoke-AzRestMethod -Path $uri -Method GET).Content | ConvertFrom-Json
            foreach ($value in $result.value){
                # Check if O365 is already enabled 
                if ($value.kind -eq "Office365") {
                    Write-Host "Successfully queried data connector $($value.kind) - already enabled"
                    Write-Verbose $value
                    $guid = $value.name
                    $etag = $value.etag
                    $o365Enabled = $true
                    break
                }
            }
        }
        catch {
            $errorReturn = $_
        }

        if ($o365Enabled) {
            # Compose body for connector update scenario
            Write-Host "Updating data connector $($connector.kind)"
            Write-Verbose "Name: $guid"
            Write-Verbose "Etag: $etag"
            
            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $guid -Force
            $connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $etag -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties
        }
        else {
            # Compose body for connector enable scenario
            Write-Host "$($connector.kind) data connector is not enabled yet"
            Write-Host "Enabling data connector $($connector.kind)"
            Write-Verbose "Name: $guid"

            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties

        }

        # Enable or update Office365 with http put method
        $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($result.StatusCode -eq 200) {
                if ($o365Enabled){
                    Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                }
                else {
                    Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
                }
            }
            else {
                Write-Error "Unable to enable data connector $($connector.kind) with error: $result.Content"
            }
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
    #MicrosoftCloudAppSecurity connector
    elseif ($connector.kind -eq "MicrosoftCloudAppSecurity") {
        $mcasEnabled = $false
        $guid = (New-Guid).Guid
        $etag = ""
        $connectorBody = ""
        $uri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2020-01-01"

        #Query for connected datasources and search Office365
        try {
            $result = (Invoke-AzRestMethod -Path $uri -Method GET).Content | ConvertFrom-Json
            foreach ($value in $result.value){
                # Check if O365 is already enabled 
                if ($value.kind -eq "MicrosoftCloudAppSecurity") {
                    Write-Host "Successfully queried data connector $($value.kind) - already enabled"
                    Write-Verbose $value
                    $guid = $value.name
                    $etag = $value.etag
                    $mcasEnabled = $true
                    break
                }
            }
        }
        catch {
            $errorReturn = $_
        }

        if ($mcasEnabled) {
            # Compose body for connector update scenario
            Write-Host "Updating data connector $($connector.kind)"
            Write-Verbose "Name: $guid"
            Write-Verbose "Etag: $etag"
            
            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $guid -Force
            $connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $etag -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties
        }
        else {
            # Compose body for connector enable scenario
            Write-Host "$($connector.kind) data connector is not enabled yet"
            Write-Host "Enabling data connector $($connector.kind)"
            Write-Verbose "Name: $guid"

            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties

        }

        # Enable or update MicrosoftCloudAppSecurity with http put method
        $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($result.StatusCode -eq 200) {
                if ($mcasEnabled){
                    Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                }
                else {
                    Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
                }
            }
            else {
                Write-Error "Unable to enable data connector $($connector.kind) with error: $result.Content"
            }
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
    #AzureAdvancedThreatProtection connector
    elseif ($connector.kind -eq "AzureAdvancedThreatProtection") {
        $aatpEnabled = $false
        $guid = (New-Guid).Guid
        $etag = ""
        $connectorBody = ""
        $uri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2020-01-01"

        #Query for connected datasources and search AzureAdvancedThreatProtection
        try {
            $result = (Invoke-AzRestMethod -Path $uri -Method GET).Content | ConvertFrom-Json
            foreach ($value in $result.value){
                # Check if AATP is already enabled 
                if ($value.kind -eq "AzureAdvancedThreatProtection") {
                    Write-Host "Successfully queried data connector $($value.kind) - already enabled"
                    Write-Verbose $value
                    $guid = $value.name
                    $etag = $value.etag
                    $aatpEnabled = $true
                    break
                }
            }
        }
        catch {
            $errorReturn = $_
        }

        if ($aatpEnabled) {
            # Compose body for connector update scenario
            Write-Host "Updating data connector $($connector.kind)"
            Write-Verbose "Name: $guid"
            Write-Verbose "Etag: $etag"
            
            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $guid -Force
            $connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $etag -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties
        }
        else {
            # Compose body for connector enable scenario
            Write-Host "$($connector.kind) data connector is not enabled yet"
            Write-Host "Enabling data connector $($connector.kind)"
            Write-Verbose "Name: $guid"

            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties

        }

        # Enable or update AzureATP with http put method
        $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($result.StatusCode -eq 200) {
                if ($aatpEnabled){
                    Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                }
                else {
                    Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
                }
            }
            else {
                Write-Error "Unable to enable data connector $($connector.kind) with error: $result.Content"
            }
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
    #MicrosoftDefenderAdvancedThreatProtection connector
    elseif ($connector.kind -eq "MicrosoftDefenderAdvancedThreatProtection") {
        $mdatpEnabled = $false
        $guid = (New-Guid).Guid
        $etag = ""
        $connectorBody = ""
        $uri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2019-01-01-preview"

        #Query for connected datasources and search MicrosoftDefenderAdvancedThreatProtection
        try {
            $result = (Invoke-AzRestMethod -Path $uri -Method GET).Content | ConvertFrom-Json
            foreach ($value in $result.value){
                # Check if MDATP is already enabled 
                if ($value.kind -eq "MicrosoftDefenderAdvancedThreatProtection") {
                    Write-Host "Successfully queried data connector $($value.kind) - already enabled"
                    Write-Verbose $value
                    $guid = $value.name
                    $etag = $value.etag
                    $mdatpEnabled = $true
                    break
                }
            }
        }
        catch {
            $errorReturn = $_
        }

        if ($mdatpEnabled) {
            # Compose body for connector update scenario
            Write-Host "Updating data connector $($connector.kind)"
            Write-Verbose "Name: $guid"
            Write-Verbose "Etag: $etag"
            
            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue $guid -Force
            $connectorBody | Add-Member -NotePropertyName etag -NotePropertyValue $etag -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties
        }
        else {
            # Compose body for connector enable scenario
            Write-Host "$($connector.kind) data connector is not enabled yet"
            Write-Host "Enabling data connector $($connector.kind)"
            Write-Verbose "Name: $guid"

            $connectorProperties = $connector.properties
            $connectorProperties | Add-Member -NotePropertyName tenantId -NotePropertyValue ${context}.Tenant.Id

            $connectorBody = @{}

            $connectorBody | Add-Member -NotePropertyName kind -NotePropertyValue $connector.kind -Force
            $connectorBody | Add-Member -NotePropertyName properties -NotePropertyValue $connectorProperties

        }

        # Enable or update MicrosoftDefenderAdvancedThreatProtection with http put method
        $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            if ($result.StatusCode -eq 200) {
                if ($mdatpEnabled){
                    Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
                }
                else {
                    Write-Host "Successfully enabled data connector: $($connector.kind)" -ForegroundColor Green
                }
            }
            else {
                Write-Error "Unable to enable data connector $($connector.kind) with error: $result.Content"
            }
            Write-Verbose ($body.Properties | Format-List | Format-Table | Out-String)
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
    #AzureActiveDirectory
    elseif ($connector.kind -eq "AzureActiveDirectory") {
        <# Azure Active Directory Audit/SignIn logs - requires special call and is therefore not connectors file
        # Be aware that you executing SPN needs Owner rights on tenant scope for this operation, can be added with following CLI
        # az role assignment create --role Owner --scope "/" --assignee {13ece749-d0a0-46cf-8000-b2552b520631}#>
        $uri = "/providers/microsoft.aadiam/diagnosticSettings/AzureSentinel_${Workspace}?api-version=2017-04-01"
           
        $connectorProperties = $connector.properties
        $connectorProperties | Add-Member -NotePropertyName workspaceId -NotePropertyValue "/subscriptions/${SubscriptionId}/resourcegroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"

        $connectorBody = @{}

        $connectorBody | Add-Member -NotePropertyName name -NotePropertyValue "AzureSentinel_${Workspace}"
        $connectorBody.Add("properties",$connectorProperties)

        try {
            $result = Invoke-AzRestMethod -Path $uri -Method PUT -Payload ($connectorBody | ConvertTo-Json -Depth 3)
            Write-Host "Successfully updated data connector: $($connector.kind)" -ForegroundColor Green
        }
        catch {
            $errorReturn = $_
            $errorResult = ($errorReturn | ConvertFrom-Json ).error
            Write-Verbose $_
            Write-Error "Unable to invoke webrequest with error message: $($errorResult.message)" -ErrorAction Stop
        }
    }
        
    
}