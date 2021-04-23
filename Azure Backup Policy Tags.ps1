# Tom Cumbow
# Required module: Az.Resources
# Required module: Az.RecoveryServices

param(
    [parameter(Mandatory=$false)]
    [bool]$SimulationOnly = $false
)

function Log ($Text) {
	Write-Verbose -Message $Text -Verbose
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