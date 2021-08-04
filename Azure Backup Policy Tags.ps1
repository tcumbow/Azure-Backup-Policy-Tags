# Tom Cumbow
# Required module: Az.Resources
# Required module: Az.RecoveryServices

param(
	[parameter(Mandatory=$false)]
	[bool]$SimulationOnly = $true
)

function Main {

	$Script:HashtableOfResourcesWithCurrentBackupInfo = CreateHashtableOfAllAzureResourcesAndWhichVaultAndPolicyIsCurrentlyBackingThemUp

	$DateString = get-date -format "yyyy-MM-dd"
	# Verify subscription
	$SubscriptionName = (Get-AzContext).Subscription.Name
	if ($SubscriptionName -ne "Dart Primary Azure Subscription") {Write-Error "Not in the correct subscription"; exit}

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

		# Check for tag
		if ($EachResource.Tags["Backup Type"] -and ($null -ne $EachResource.Tags["Backup Type"])) {
			$PolicyTagText = $EachResource.Tags["Backup Type"]
			Log "[$($EachResource.Name)]: Found Backup Type tag with value: $PolicyTagText"
		}
		else {
			$PolicyTagText = $null
			Log "[$($EachResource.Name)]: Backup Type tag not found on this resource; reporting..."
			Report -Resource $EachResource -InfoText "tag is blank"
			continue
		}

		if ($PolicyTagText -like "No Backup") {
			$CurrentlyAssignedBackupVaultAndPolicy = $Script:HashtableOfResourcesWithCurrentBackupInfo[$EachResource.ResourceId]
			if ($null -eq $CurrentlyAssignedBackupVaultAndPolicy) {
				Log "[$($EachResource.Name)]: This resource is tagged for 'no backup' and no backup is currently assigned; moving to next resource..."
				continue
			}
			#TODO remove backup policy if applied
		}
		else {
			# Attempt to determine backup vault/policy based on tag and location
			$DeterminedVault, $DeterminedPolicy = DetermineCorrectBackupPolicyAndVault $PolicyTagText $EachResource.Location
			if ($null -eq $DeterminedVault -or $null -eq $DeterminedPolicy) {
				Log "[$($EachResource.Name)]: Tag not recognized; reporting..."
				Report -Resource $EachResource -InfoText "tag invalid"
				continue
			}
			else {
				Log "[$($EachResource.Name)]: Tag recognized successfully"
				# If assigned backup policy matches the policy determined by the tag, then no further action is required
				if ($DeterminedVault.ID -eq $CurrentlyAssignedBackupVaultAndPolicy.VaultID -and $DeterminedPolicy.ID -eq $CurrentlyAssignedBackupVaultAndPolicy.PolicyID) {
					Log "[$($EachResource.Name)]: Correct policy is already applied; moving on to next resource..."
					continue
				}
				# If assigned backup policy is wrong, remove it
				elseif ($null -ne $CurrentlyAssignedBackupVaultAndPolicy) {
					Log "[$($EachResource.Name)]: Incorrect backup policy applied [VaultID] $($CurrentlyAssignedBackupVaultAndPolicy.VaultID) [PolicyID] $($CurrentlyAssignedBackupVaultAndPolicy.PolicyID)"
					#TODO remove backup policy
				}
				# At this point, we can assume that no backup policy was assigned, or it was wrong and we removed it
				Log "[$($EachResource.Name)]: Attempting to assign backup policy $($DeterminedPolicy.ID)"
				#TODO assign backup policy
				#TODO verify backup policy
			}
		}


		# Check if resource is already backed up somewhere
		#TODO verify that this works for MSSQL
		$BackupStatus = Get-AzRecoveryServicesBackupStatus -ResourceId $EachResource.ResourceId -ErrorAction Stop #TODO
		if ($null -ne $BackupStatus.VaultId) {
			Log "[$($EachResource.Name)]: This resource is already backed up in vault $($BackupStatus.VaultId)"
			$ResourceIsAlreadyBackedUp = $true
		}
		else {
			$ResourceIsAlreadyBackedUp = $false
		}


		if ($PolicyTagText -like "No Backup") {
			#TODO maybe remove backup assignment if it is there
			Log "[$($EachResource.Name)]: Skipping this resource"
			#TODO maybe fix the tag if it is the wrong case
		}



		# (At this point, we've determined what vault/policy SHOULD be used to backup this resources)
		# Next up, check to see if the resource is already in a vault/policy


		#TODO remove this debug code
		Write-Host "vault = $($DeterminedVault.Name)"
		Write-Host "policy = $($DeterminedPolicy.Name)"

		#TODO remove this debug code
		Write-Host "Actual policy:"
		$ActualPolicy = $Script:HashtableOfResourcesWithCurrentBackupInfo[$($EachResource.ResourceId)]
		if ($null -ne $ActualPolicy) {$ActualPolicy | ConvertTo-Json -Depth 100 -EnumsAsStrings | Out-Host }



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

function Report ($Resource, $InfoText, $Details = $null) {
	Log "Reporting [$InfoText] for resource [$($Resource.Name)]"
	#TODO
}

function ResourceCanBeBackedUp ($Resource) {
	$ResourceTypesThatCanBeBackedUp = @("Microsoft.Storage/storageAccounts", "Microsoft.Compute/virtualMachines")
	return ($Resource.ResourceType -in $ResourceTypesThatCanBeBackedUp)
}

function CreateHashtableOfAllAzureResourcesAndWhichVaultAndPolicyIsCurrentlyBackingThemUp {
	# Assumes that we are already authenticated to Azure and associated with a subscription
	$HashTableToReturn = @{}
	Get-AzRecoveryServicesVault | ForEach-Object -ThrottleLimit 20 -Parallel {
		Get-AzRecoveryServicesBackupContainer -ContainerType AzureStorage -VaultId $_.ID -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.ID
		Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -VaultId $_.ID -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.ID
		Get-AzRecoveryServicesBackupContainer -ContainerType AzureSQL -VaultId $_.ID -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.ID
		Get-AzRecoveryServicesBackupContainer -ContainerType AzureVMAppContainer -VaultId $_.ID -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.ID
	} | ForEach-Object -ThrottleLimit 20 -Parallel {
		Get-AzRecoveryServicesBackupItem -VaultId $_.VaultID -Container $_ -WorkloadType AzureFiles -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.VaultID
		Get-AzRecoveryServicesBackupItem -VaultId $_.VaultID -Container $_ -WorkloadType AzureSQLDatabase -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.VaultID
		Get-AzRecoveryServicesBackupItem -VaultId $_.VaultID -Container $_ -WorkloadType AzureVM -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.VaultID
		Get-AzRecoveryServicesBackupItem -VaultId $_.VaultID -Container $_ -WorkloadType FileFolder -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.VaultID
		Get-AzRecoveryServicesBackupItem -VaultId $_.VaultID -Container $_ -WorkloadType MSSQL -ErrorAction SilentlyContinue | Add-Member -PassThru -MemberType NoteProperty -Name "VaultID" -Value $_.VaultID
	} | ForEach-Object {
		if ($_.SourceResourceId) {$HashTableToReturn[$_.SourceResourceId] = @{VaultID = $_.VaultID; PolicyID = $_.PolicyID}}
	}
	return $HashTableToReturn
}

function DetermineCorrectBackupPolicyAndVault ([string]$tag, $region) {
	$DesiredVaultTagText = $tag.Split('/')[0]
	$DesiredPolicyTagText = $tag.Split('/')[1]

	$PossibleBackupVaultsByLocation = $Script:AllBackupVaults | where {$_.Location -eq $region}
	$PossibleBackupVaultsByLocationAndName = $PossibleBackupVaultsByLocation | where {$_.Name -like "*$DesiredVaultTagText"}
	$CountOfPossibleVaults = $PossibleBackupVaultsByLocationAndName.Count
	Log "Determining correct backup vault based on tag, found $CountOfPossibleVaults"
	if ($CountOfPossibleVaults -eq 1) {
		$CorrectVault = $PossibleBackupVaultsByLocationAndName[0]
		Log "Correct vault is $($CorrectVault.Name)"
		$PossibleBackupPolicies = $Script:AllBackupPoliciesByVault[$CorrectVault.ID]
		$PossibleBackupPoliciesByName = $PossibleBackupPolicies | where {$_.Name.Split('BackupRP-')[1] -like $DesiredPolicyTagText}
		$CountOfPossiblePolicies = $PossibleBackupPoliciesByName.Count
		Log "Determining correct backup policy based on tag, found $CountOfPossiblePolicies"
		if ($CountOfPossiblePolicies -eq 1) {
			$CorrectPolicy = $PossibleBackupPoliciesByName[0]
			Log "Determined correct backup policy: $($CorrectPolicy.Name)"
			Write-Output $CorrectVault
			return $CorrectPolicy
		}
		elseif ($CountOfPossiblePolicies -eq 0) {
			Log "Could not find any policies that match tag=$tag and region=$region and vault=$($CorrectVault.Name)"
		}
		elseif ($CountOfPossiblePolicies -gt 1) {
			Log "Found multiple policies that could match tag=$tag and region=$region and vault=$($CorrectVault.Name)"
			$ArrayOfPolicyNames = $PossibleBackupPoliciesByName | % {$_.Name}
			$StringOfPolicyNames = [string]::Join(",",$ArrayOfPolicyNames)
			Log "Possible matches: $StringOfPolicyNames"
		}
		else {
			Write-Error "Unknown error"
			return $null
		}
	}
	elseif ($CountOfPossibleVaults -eq 0) {
		Log "Could not find any vaults that match tag=$tag and region=$region"
		return $null
	}
	elseif ($CountOfPossibleVaults -gt 1) {
		Log "Found multiple vaults that could match tag=$tag and region=$region"
		$ArrayOfVaultNames = $PossibleBackupVaultsByLocationAndName | % {$_.Name}
		$StringOfVaultNames = [string]::Join(",",$ArrayOfVaultNames)
		Log "Possible matches: $StringOfVaultNames"
		return $null
	}
	else {
		Write-Error "Unknown error"
		return $null
	}

	#TODO get rid of code below
	$PossibleBackupPoliciesByName | ForEach-Object {Write-Host $_.Name}
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