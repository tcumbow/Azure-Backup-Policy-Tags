function GetListOfBackupPolicies {
    $BackupPolicies = @{}
    $RecoveryVaultInfo = (Get-AzRecoveryServicesVault)
    foreach ($vault in $RecoveryVaultInfo) {
        $policy = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $vault.ID
        $tempobject = [PSCustomObject]@{
            PolicyName = $policy.Name
        }]
    }
    
}


# Do I want a custom struct, or should I just use the existing objects?

connectdartcredentials.ps1

