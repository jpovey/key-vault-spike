"Start..."

$azureAplicationId = "xxxx-xxxx-xxxx-xxxx"
$azureTenantId= "xxxx-xxxx-xxxx-xxxx"
$azurePassword = ConvertTo-SecureString "xxxx-xxxx-xxxx-xxxx" -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($azureAplicationId , $azurePassword)
Add-AzureRmAccount -Credential $psCred -TenantId $azureTenantId -ServicePrincipal 

Select-AzureRMSubscription -subscriptionId "xxxx-xxxx-xxxx-xxxx"
(Get-AzureRmContext).Subscription

Add-AzureKeyVaultKey -VaultName 'jontestvault1' -Name 'JonTestKey' -Destination 'Software'

"...Finish"