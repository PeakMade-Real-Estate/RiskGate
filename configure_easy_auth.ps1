# Configure Azure Easy Auth for RiskGate App Service
# This script sets up Microsoft Entra ID authentication

$appName = "RiskGate"
$resourceGroup = "SecurityScan"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Azure Easy Auth Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if logged in to Azure
Write-Host "Checking Azure login status..." -ForegroundColor Yellow
$account = az account show 2>$null | ConvertFrom-Json

if (-not $account) {
    Write-Host "Not logged in to Azure. Running 'az login'..." -ForegroundColor Yellow
    az login
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to log in to Azure." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✓ Logged in as: $($account.user.name)" -ForegroundColor Green
    Write-Host "✓ Subscription: $($account.name)" -ForegroundColor Green
}
Write-Host ""

# Get the App Service details
Write-Host "Getting App Service details..." -ForegroundColor Yellow
$appService = az webapp show --name $appName --resource-group $resourceGroup 2>$null | ConvertFrom-Json

if (-not $appService) {
    Write-Host "✗ Could not find App Service '$appName' in resource group '$resourceGroup'" -ForegroundColor Red
    Write-Host "Please verify the app name and resource group are correct." -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Found App Service: $($appService.name)" -ForegroundColor Green
Write-Host "  URL: $($appService.defaultHostName)" -ForegroundColor Cyan
Write-Host ""

# Check current authentication configuration
Write-Host "Checking current authentication configuration..." -ForegroundColor Yellow
$authConfig = az webapp auth show --name $appName --resource-group $resourceGroup 2>$null | ConvertFrom-Json

if ($authConfig.enabled -eq $true) {
    Write-Host "✓ Easy Auth is already enabled!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Current Configuration:" -ForegroundColor Cyan
    Write-Host "  Unauthenticated Action: $($authConfig.unauthenticatedClientAction)" -ForegroundColor White
    
    if ($authConfig.identityProviders.azureActiveDirectory) {
        Write-Host "  Microsoft Entra ID: Configured" -ForegroundColor Green
    }
    Write-Host ""
    
    $choice = Read-Host "Would you like to reconfigure Easy Auth? (y/n)"
    if ($choice -ne 'y') {
        Write-Host "Exiting without changes." -ForegroundColor Yellow
        exit 0
    }
} else {
    Write-Host "✗ Easy Auth is NOT enabled" -ForegroundColor Yellow
    Write-Host ""
}

# Configure Easy Auth with Microsoft Entra ID
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Configuring Easy Auth..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "This will:" -ForegroundColor Yellow
Write-Host "  1. Enable Microsoft Entra ID authentication" -ForegroundColor White
Write-Host "  2. Redirect unauthenticated users to login" -ForegroundColor White
Write-Host "  3. Allow only users in your organization to access the app" -ForegroundColor White
Write-Host ""

$confirm = Read-Host "Continue? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Configuration cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Enabling authentication..." -ForegroundColor Yellow

# Enable Microsoft Entra ID authentication
az webapp auth microsoft update `
    --name $appName `
    --resource-group $resourceGroup `
    --client-id "00000000-0000-0000-0000-000000000000" `
    --issuer "https://sts.windows.net/<tenant-id>/" `
    --allowed-audiences "https://$($appService.defaultHostName)" `
    --yes

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Failed to configure authentication." -ForegroundColor Red
    Write-Host ""
    Write-Host "ALTERNATIVE: Configure via Azure Portal" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Go to: https://portal.azure.com" -ForegroundColor White
    Write-Host "2. Navigate to: App Services → RiskGate" -ForegroundColor White
    Write-Host "3. Click: Authentication (in left menu)" -ForegroundColor White
    Write-Host "4. Click: 'Add identity provider'" -ForegroundColor White
    Write-Host "5. Select: 'Microsoft'" -ForegroundColor White
    Write-Host "6. Choose: 'Workforce configuration (current tenant)'" -ForegroundColor White
    Write-Host "7. Set 'Restrict access' to: 'Require authentication'" -ForegroundColor White
    Write-Host "8. Set 'Unauthenticated requests' to: 'HTTP 302 Found redirect: recommended for websites'" -ForegroundColor White
    Write-Host "9. Click: 'Add'" -ForegroundColor White
    Write-Host ""
    Write-Host "Important: The redirect URI should be:" -ForegroundColor Yellow
    Write-Host "  https://$($appService.defaultHostName)/.auth/login/aad/callback" -ForegroundColor Cyan
    exit 1
}

# Update auth settings to require authentication
Write-Host "Updating authentication settings..." -ForegroundColor Yellow
az webapp auth update `
    --name $appName `
    --resource-group $resourceGroup `
    --enabled true `
    --action RedirectToLoginPage

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ Easy Auth Configuration Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your app is now protected with Microsoft Entra ID authentication." -ForegroundColor Green
    Write-Host ""
    Write-Host "Test it now:" -ForegroundColor Cyan
    Write-Host "  https://$($appService.defaultHostName)" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "✗ Failed to update authentication settings." -ForegroundColor Red
}
