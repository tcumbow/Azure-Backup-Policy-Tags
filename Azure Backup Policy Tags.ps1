# Tom Cumbow

param(
    [parameter(Mandatory=$false)]
    [bool]$Simulate = $true,
    [parameter(Mandatory=$false)]
    [switch]$LocalDevMode
)

$ScriptVersion = "0.0.1"
$ScriptName = "Azure Backup Policy Tags.ps1"

if ($LocalDevMode) {
    if (-not $GLOBAL:CheckedDependenciesForAzureBackupPolicyTags)
    {
        Install-Module Az.Resources -Scope CurrentUser
        Install-Module Az.RecoveryServices -Scope CurrentUser -Force
        $GLOBAL:CheckedDependenciesForAzureBackupPolicyTags = $true
    }
}

# This is a custom function for logging - this is a workaround for the failed logging in Azure Runbooks
function Log
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline)]
		[string]
		$Text,
		[Parameter(Mandatory=$false)]
		[switch]
		$Warning,
		[Parameter(Mandatory=$false)]
		[switch]
		$Error
	)
	function UpsertTableEntity($TableName, $RowKey, $Entity) {
		$StorageAccount = "tcumbowdartsandbox"
		$SasToken = "?st=2021-03-21T14%3A52%3A00Z&se=2042-03-23T14%3A52%3A00Z&sp=rau&sv=2018-03-28&tn=runbooklogs&sig=jG6lhLojZ%2F74SJllghtxHuvasLiruIK0hCP%2FSJn8igY%3D"
		$version = "2017-04-17"
		$PartitionKey = ((get-date -format "yyyyMM").ToString())
		$resource = "$tableName(PartitionKey='$PartitionKey',RowKey='$RowKey')$SasToken"
		$table_url = "https://$StorageAccount.table.core.windows.net/$resource"
		$GMTTime = (Get-Date).ToUniversalTime().toString('R')
		$headers = @{
			'x-ms-date'    = $GMTTime
			"x-ms-version" = $version
			Accept         = "application/json;odata=fullmetadata"
		}
		$body = $Entity | ConvertTo-Json
		$item = Invoke-RestMethod -Method MERGE -Uri $table_url -Headers $headers -Body $body -ContentType application/json
	}

	if ($Error) {Write-Error $Text}
	elseif ($Warning) {Write-Warning $Text}
	elseif ($LocalDevMode) {Write-Host $Text}
	else {Write-Verbose $Text}

	if ($LocalDevMode) {return}

	$HashTable = @{}
    $HashTable.Add("Text",$Text)
    $HashTable.Add("Level",$(if($Error){"Error"}elseif($Warning){"Warning"}else{"Verbose"}))
	$HashTable.Add("ScriptName",$ScriptName)
	$HashTable.Add("ScriptVersion",$ScriptVersion)
	UpsertTableEntity -TableName "RunbookLogs" -RowKey ([guid]::NewGuid().ToString()) -Entity $HashTable
}


# Main runbook content
try
{
	$ScriptStartTime = (Get-Date).ToUniversalTime()
    Log "Runbook started. Version: $ScriptVersion"
    if($Simulate)
    {
        Log "*** Running in SIMULATE mode. No actions will be taken. ***"
    }
    else
    {
        Log "*** Running in LIVE mode. Schedules will be enforced. ***"
    }

    # Authentication and connection
    if (-not $LocalDevMode) {
        $connectionName = "AzureRunAsConnection"
        $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName
        $DummyVariable = $(Add-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint)
        Log "Successfully logged into Azure subscription using Az cmdlets..."
    }

    Log "Getting all the resources from the subscription..."
    $AllResources = Get-AzResource

    Log "Processing [$($AllResources.Count)] resources found in subscription"
    foreach($resource in $AllResources)
    {
        # Check for tag
		if($resource.ResourceType -eq "Microsoft.Compute/virtualMachines" -and $resource.Tags.BackupPolicy)
		{
			$PolicyText = $resource.Tags.BackupPolicy
			Log "[$($resource.Name)]: Found BackupPolicy tag with value: $PolicyText"
		}
        else
        {
            Log "[$($Resource.Name)]: Not tagged for backup policy. Skipping this resource."
            continue
        }

        # Check that tag value was successfully obtained
        if($null -eq $PolicyText)
        {
            Log -Warning "[$($Resource.Name)]: Failed to get tag, skipping this resource."
            continue
        }

		# Enact backup policy based on tag
		if ($PolicyText -eq "SpecialPolicy") {
			$VaultID = Get-AzRecoveryServicesVault -ResourceGroupName "Sandbox" -Name "Test-Vault" | select -ExpandProperty ID
			Log "VaultID $VaultID"
			$PolicyObject = Get-AzRecoveryServicesBackupProtectionPolicy -Name "SpecialPolicy" -VaultId $VaultID
			$PolicyObject | ConvertTo-Json | Log
			$resource | ConvertTo-Json | Log
			$ExistingBackupItem = Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM -BackupManagementType AzureVM -Name $resource.Name -VaultId $VaultID
			Enable-AzRecoveryServicesBackupProtection -Item $ExistingBackupItem -Policy $PolicyObject -VaultId $VaultID
			# Enable-AzRecoveryServicesBackupProtection -Policy $PolicyObject -Name $resource.Name -ResourceGroupName $resource.ResourceGroupName -VaultId $VaultID
		}
    }

    Log "Finished processing Azure resources"
}
catch
{
    $errorMessage = $_.Exception.Message
	Log -Error "SEVERE Unexpected exception: $errorMessage"
    throw "Unexpected exception: $errorMessage"
}
finally
{
    Log "Runbook finished (Duration: $(("{0:hh\:mm\:ss}" -f ((Get-Date).ToUniversalTime() - $ScriptStartTime))))"
}