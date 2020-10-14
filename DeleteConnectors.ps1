param(
    [Parameter(Mandatory=$true)]$ResourceGroup,
    [Parameter(Mandatory=$true)]$Workspace,
    [Parameter(Mandatory=$true)]$ConnectorsFile,
    [Parameter(Mandatory=$true)]$Location
)

function CheckModules($module) {
    $service = Get-Module -ListAvailable -Name $module
    if (-Not $service) {
        Install-Module -Name $module -Scope CurrentUser -Force
    }  
}


function DeleteDataConnector ($dataConnector, $dataConnectorUri) {
    #Enable or Update AzureActivityLog Connector with http put method
    try {
        $deleteResponse = Invoke-AzRestMethod -Path $dataConnectorUri -Method DELETE
        if ($deleteResponse.StatusCode -eq 200) {            
            Write-Host "Successfully deleted Data connector: $($dataConnector)" -ForegroundColor Green                        
        }
        else {
            Write-Host "Unable to delete Data connector $($dataConnector) with error: $($deleteResponse.message)" 
        }           
                    
    }
    catch {
        $errorReturn = $_
        Write-Verbose $_.Exception.Message
        Write-Error "Unable to invoke webrequest with error message: $errorReturn" -ErrorAction Stop
    }
    
}

CheckModules("Az.Resources")
CheckModules("Az.OperationalInsights")
CheckModules("AzSentinel")

$context = Get-AzContext

$SubscriptionId = $context.Subscription.Id

#Check Resource Group Existing or not
Get-AzResourceGroup -Name $ResourceGroup -ErrorVariable notPresent -ErrorAction SilentlyContinue
if ($notPresent){        
    Write-Host "ResourceGroup $($ResourceGroup) associated to Log Analytics Workspace - not found"
    Write-Host "Exiting.................." -ForegroundColor Red
    break
}

#Check Log Analytics workspace Existing or not
try {
    $WorkspaceObject = Get-AzOperationalInsightsWorkspace -Name $Workspace -ResourceGroupName $ResourceGroup  -ErrorAction Stop
    $ExistingLocation = $WorkspaceObject.Location
    Write-Output "Workspace $Workspace in region $ExistingLocation exists."
} catch {
    Write-Output "Provided Log Analytics Workspace $Workspace not found"
    Write-Host "Exiting.................." -ForegroundColor Red
    break
}

#Urls to be used for Sentinel API calls
$baseUri = "/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${Workspace}"

#Getting all data connectors connector to workspace
try{
    $connectorsUri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2020-01-01"
    $connectedDataConnectors = (Invoke-AzRestMethod -Path $connectorsUri -Method GET).Content | ConvertFrom-Json
    if ($connectedDataConnectors.value.Length -eq 0)
    {
        Write-Host "There were no Data connectors enabled on your Workspace $($Workspace)"
        Write-Host "Exiting.................." -ForegroundColor Red
        break
    }
}
catch {
    $errorReturn = $_
    Write-Error "Unable to invoke webrequest with error message: $errorReturn" -ErrorAction Stop
}
#Getting all rules from file
$connectorsToDelete = Get-Content -Raw -Path $ConnectorsFile | ConvertFrom-Json

foreach ($toBeDeletedConnector in $connectorsToDelete.connectors) {
    Write-Host "`r`nProcessing connector: " -NoNewline 
    Write-Host "$($toBeDeletedConnector.kind)" -ForegroundColor Blue
    
    foreach ($dataConnector in $connectedDataConnectors.value){
        # Check if ASC is already enabled (assuming there will be only one ASC per workspace)
        if ($dataConnector.kind -eq $toBeDeletedConnector.kind) {
            Write-Host "Data connector $($dataConnector.kind) - enabled"
            Write-Verbose $dataConnector
            $guid = $dataConnector.name                    
            $uri = "${baseUri}/providers/Microsoft.SecurityInsights/dataConnectors/${guid}?api-version=2020-01-01"
            DeleteDataConnector($dataConnector.kind, $uri)
            break     
        }        
    }    
}