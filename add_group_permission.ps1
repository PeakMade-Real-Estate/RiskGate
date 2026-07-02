# Add Group.Read.All permission to SecurityScan app registration
# This script adds the required Microsoft Graph permission for reading groups

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "ADDING GROUP.READ.ALL PERMISSION TO SECURITYSCAN APP" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$AppId = "99b0438f-6b8c-41ff-86ee-0116481883ea"
$TenantId = "ea0cd29c-45e6-4ad1-94ff-2e9f36fb84b5"

# Microsoft Graph App ID (constant)
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Group.Read.All permission ID
$GroupReadAllId = "5b567255-7703-4780-807c-7be8301ae99b"

Write-Host "`nApp Registration ID: $AppId" -ForegroundColor Yellow
Write-Host "Tenant ID: $TenantId" -ForegroundColor Yellow

# Check if Azure CLI is installed
$azInstalled = Get-Command az -ErrorAction SilentlyContinue

if ($azInstalled) {
    Write-Host "`n✓ Azure CLI found" -ForegroundColor Green
    
    # Check if logged in
    Write-Host "`nChecking Azure CLI login status..." -ForegroundColor Yellow
    $account = az account show 2>$null | ConvertFrom-Json
    
    if ($account) {
        Write-Host "✓ Already logged in as: $($account.user.name)" -ForegroundColor Green
        Write-Host "  Tenant: $($account.tenantId)" -ForegroundColor Gray
    } else {
        Write-Host "⚠ Not logged in to Azure CLI" -ForegroundColor Yellow
        Write-Host "`nPlease log in to Azure..." -ForegroundColor Yellow
        az login --tenant $TenantId
    }
    
    Write-Host "`n================================================================================`n" -ForegroundColor Cyan
    Write-Host "Adding Group.Read.All permission..." -ForegroundColor Yellow
    
    # Add the API permission
    try {
        az ad app permission add `
            --id $AppId `
            --api $GraphAppId `
            --api-permissions "${GroupReadAllId}=Role"
        
        Write-Host "✓ Permission added successfully" -ForegroundColor Green
        
        Write-Host "`nGranting admin consent..." -ForegroundColor Yellow
        az ad app permission admin-consent --id $AppId
        
        Write-Host "✓ Admin consent granted!" -ForegroundColor Green
        
        Write-Host "`n================================================================================`n" -ForegroundColor Cyan
        Write-Host "SUCCESS! Group.Read.All permission has been added." -ForegroundColor Green
        Write-Host "`nYour SecurityScan app can now:" -ForegroundColor White
        Write-Host "  • Fetch groups from Entra ID" -ForegroundColor White
        Write-Host "  • Read group memberships" -ForegroundColor White
        Write-Host "  • Scan entire groups for impossible travel" -ForegroundColor White
        
        Write-Host "`nRun the test again to verify:" -ForegroundColor Yellow
        Write-Host "  python test_entra_groups.py" -ForegroundColor Cyan
        
    } catch {
        Write-Host "✗ Failed to add permission: $_" -ForegroundColor Red
        Write-Host "`nYou may need to add it manually via Azure Portal." -ForegroundColor Yellow
    }
    
} else {
    Write-Host "`n⚠ Azure CLI not installed" -ForegroundColor Yellow
    Write-Host "`nPlease add the permission manually:" -ForegroundColor White
    Write-Host "`n1. Open Azure Portal: https://portal.azure.com" -ForegroundColor Cyan
    Write-Host "2. Navigate to: Azure Active Directory > App registrations" -ForegroundColor Cyan
    Write-Host "3. Search for app: 99b0438f-6b8c-41ff-86ee-0116481883ea" -ForegroundColor Cyan
    Write-Host "4. Click 'API permissions' in the left menu" -ForegroundColor Cyan
    Write-Host "5. Click '+ Add a permission'" -ForegroundColor Cyan
    Write-Host "6. Select 'Microsoft Graph'" -ForegroundColor Cyan
    Write-Host "7. Select 'Application permissions'" -ForegroundColor Cyan
    Write-Host "8. Search for and select: Group.Read.All" -ForegroundColor Cyan
    Write-Host "9. Click 'Add permissions'" -ForegroundColor Cyan
    Write-Host "10. Click 'Grant admin consent for [your tenant]'" -ForegroundColor Cyan
    Write-Host "`nAfter adding, run: python test_entra_groups.py" -ForegroundColor Yellow
}

Write-Host "`n================================================================================`n" -ForegroundColor Cyan
