# Tom Cumbow
# Required module: Az.Resources
# Required module: Az.RecoveryServices

param(
	[parameter(Mandatory=$false)]
	[bool]$SimulationOnly = $true
)

function Main {
	# Verify subscription
	$DateString = get-date -format "yyyy-MM-dd"
	$SubscriptionName = (Get-AzContext).Subscription.Name
	if ($SubscriptionName -ne "Dart Primary Azure Subscription") {Write-Error "Not in the correct subscription"; exit}

	# Get Backup Vault/Policy info for later use
	$Script:AllBackupVaults = Get-AzRecoveryServicesVault
	$Script:AllBackupPoliciesByVault = @{}
	foreach ($EachVault in $Script:AllBackupVaults) {
        $ProtectionPolicies = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $EachVault.ID
        $Script:AllBackupPoliciesByVault[$EachVault.ID] = $ProtectionPolicies
    }

	# $Script:AllBackupPoliciesByVault | ConvertTo-Json -Depth 100 -EnumsAsStrings | Out-Host
	# exit

	# Get all resources
	$AllResources = Get-AzResource
	Log "Processing [$($AllResources.Count)] resources found in subscription"
	foreach ($EachResource in $AllResources) {

		# Check if resource type can be backed up
		if (-not (ResourceCanBeBackedUp $EachResource)) {
			# Log "[$($EachResource.Name)]: This resource type CANNOT be backed up; skipping..."
			continue
		}
		Log "[$($EachResource.Name)]: This resource type can be backed up; processing..."

		# Check if resource is already backed up somewhere
		$BackupStatus = Get-AzRecoveryServicesBackupStatus -ResourceId $EachResource.ResourceId -ErrorAction Stop
		if ($null -ne $BackupStatus.VaultId) {
			Log "[$($EachResource.Name)]: This resource is already backed up in vault $($BackupStatus.VaultId)"
			$ResourceIsAlreadyBackedUp = $true
		}
		else {
			$ResourceIsAlreadyBackedUp = $false
		}

		# Check for tag
		if ($EachResource.Tags.BackupPolicy -and ($null -ne $EachResource.Tags.BackupPolicy)) {
			$PolicyTagText = $EachResource.Tags.BackupPolicy
			Log "[$($EachResource.Name)]: Found BackupPolicy tag with value: $PolicyTagText"
			#TODO
		}
		else {
			Log "[$($EachResource.Name)]: BackupPolicy tag not found for this resource"
			#TODO
		}

		#TODO add "custom" tag

		if ($PolicyTagText -like "No Backup Required") {
			Log "[$($EachResource.Name)]: Skipping this resource"
			#TODO maybe fix the tag if it is the wrong case
			continue
		}


		# Enact backup policy based on tag
		Log "asdfasdf"
		$PolicyName = DetermineBackupPolicyAndVault $PolicyTagText $EachResource.Location

		# if ($null -eq $PolicyName) {
		# 	Write-Warning "Could not determine backup policy for resource [$($EachResource.Name)] in region [$Region] with tag [$PolicyTagText]"
		# }
		# else {
		# 	$VaultID = Get-AzRecoveryServicesVault -ResourceGroupName "Sandbox" -Name "Test-Vault" | Select-Object -ExpandProperty ID
		# 	Log "VaultID $VaultID"
		# 	$PolicyObject = Get-AzRecoveryServicesBackupProtectionPolicy -Name "SpecialPolicy" -VaultId $VaultID
		# 	$PolicyObject | ConvertTo-Json | Log
		# 	$EachResource | ConvertTo-Json | Log
		# 	$ExistingBackupItem = Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM -BackupManagementType AzureVM -Name $EachResource.Name -VaultId $VaultID
		# 	# Enable-AzRecoveryServicesBackupProtection -Item $ExistingBackupItem -Policy $PolicyObject -VaultId $VaultID
		# 	# Enable-AzRecoveryServicesBackupProtection -Policy $PolicyObject -Name $EachResource.Name -ResourceGroupName $EachResource.ResourceGroupName -VaultId $VaultID
		# }
	}
	Log "Finished processing Azure resources"
}

function Log ($Text) {
	Write-Verbose -Message $Text -Verbose
}

function ResourceCanBeBackedUp ($Resource) {
	$ResourceTypesThatCanBeBackedUp = @("Microsoft.Storage/storageAccounts", "Microsoft.Compute/virtualMachines")
	return ($Resource.ResourceType -in $ResourceTypesThatCanBeBackedUp)
}

# Define backup policies by tag and region
function DetermineBackupPolicyAndVault ([string]$tag, $region) {
	$PossibleBackupVaultsByLocation = $Script:AllBackupVaults | where {$_.Location -eq $region}
	$PossibleBackupPoliciesByLocation = $PossibleBackupVaultsByLocation | ForEach-Object {$Script:AllBackupPoliciesByVault[$_.ID]}

	$PossibleBackupPoliciesByLocation | ForEach-Object {Write-Host $_.Name}
	Write-Host "Exitting"
	exit
	return $null

	$processedTag = $tag.replace("BackupRP", "Backup")
	return "$region-$processedTag"
}

# Main runbook content
try {
	$ScriptStartTime = (Get-Date).ToUniversalTime()
	Log "Runbook started."
	if ($SimulationOnly) {
		Log "*** Running in SIMULATE mode. No actions will be taken. ***"
	}
	else {
		Log "*** Running in LIVE mode. Policies will be enforced. ***"
	}

	# Authentication and connection
	if ($env:COMPUTERNAME -eq "pks") {
		connectdartcredentials.ps1
		$CurrentPath = "C:\temp"
	}
	else {
		$connectionName = "AzureRunAsConnection"
		$servicePrincipalConnection=Get-AutomationConnection -Name $connectionName
		$DummyVariable = $(Add-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint)

		$CurrentPath = (Get-Location).Path
	}

	Main
}
catch {
	$errorMessage = $_.Exception.Message
	Write-Error "SEVERE Unexpected exception: $errorMessage"
	throw "Unexpected exception: $errorMessage"
}
finally {
	Log "Runbook finished (Duration: $(("{0:hh\:mm\:ss}" -f ((Get-Date).ToUniversalTime() - $ScriptStartTime))))"
}