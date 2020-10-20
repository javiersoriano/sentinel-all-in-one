$data = @()
$data += 'Kind,Display Name,Connector'

$alertTemplates = Get-AzSentinelAlertRuleTemplates -WorkspaceName cxe-javier

foreach ($item in $alertTemplates) {

    foreach ($conn in $item.properties.requiredDataConnectors){
        #Write-Host "Processing connector: " $conn.connectorId
    
        $data += $item.kind+','+$item.properties.displayName+','+$conn.connectorId
        #Write-Host $data
        Write-Host $item.properties.displayName
    }    
}

Write-Host "Done!"

Write-Host $data

$data > AnalyticsRulesTemplates.csv