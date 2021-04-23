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

# Define backup policies by tag and region
function DetermineBackupPolicy ([string]$tag, $region) {
	$processedTag = $tag.replace("BackupRP", "Backup")
	return "$region-$processedTag"
}

# Main runbook content
try {
	$ScriptStartTime = (Get-Date).ToUniversalTime()
	Log "Runbook started."
	if ($Simulate) {
		Log "*** Running in SIMULATE mode. No actions will be taken. ***"
	}
	else {
		Log "*** Running in LIVE mode. Policies will be enforced. ***"
	}

	# Authentication and connection
	$connectionName = "AzureRunAsConnection"
	$servicePrincipalConnection=Get-AutomationConnection -Name $connectionName
	$DummyVariable = $(Add-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint)
	Log "Successfully logged into Azure subscription using Az cmdlets..."


	Log "Getting all the resources from the subscription..."
	$AllResources = Get-AzResource

	Log "Processing [$($AllResources.Count)] resources found in subscription"
	foreach ($resource in $AllResources) {
		# Check for tag
		if ($resource.ResourceType -eq "Microsoft.Compute/virtualMachines" -and $resource.Tags.BackupPolicy) {
			$PolicyText = $resource.Tags.BackupPolicy
			Log "[$($resource.Name)]: Found BackupPolicy tag with value: $PolicyText"
		}
		else {
			Log "[$($Resource.Name)]: Not tagged for backup policy. Skipping this resource."
			continue
		}

		# Check that tag value was successfully obtained
		if ($null -eq $PolicyText) {
			Log -Warning "[$($Resource.Name)]: Failed to get tag, skipping this resource."
			continue
		}

		# Enact backup policy based on tag
		if ($PolicyText -eq "SpecialPolicy") {
			$VaultID = Get-AzRecoveryServicesVault -ResourceGroupName "Sandbox" -Name "Test-Vault" | Select-Object -ExpandProperty ID
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
catch {
	$errorMessage = $_.Exception.Message
	Log -Error "SEVERE Unexpected exception: $errorMessage"
	throw "Unexpected exception: $errorMessage"
}
finally {
	Log "Runbook finished (Duration: $(("{0:hh\:mm\:ss}" -f ((Get-Date).ToUniversalTime() - $ScriptStartTime))))"
}