# Add User.Read.All permission to SecurityScan app registration

$AppId = "99b0438f-6b8c-41ff-86ee-0116481883ea"
$GraphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$UserReadAllId = "df021288-bdef-4463-88db-98f22de89214"  # User.Read.All permission ID

Write-Host "Adding User.Read.All permission..." -ForegroundColor Cyan
az ad app permission add --id $AppId --api $GraphAppId --api-permissions "$UserReadAllId=Role"

Write-Host "`nGranting admin consent..." -ForegroundColor Cyan
az ad app permission admin-consent --id $AppId

Write-Host "`nDone! User.Read.All permission added and consented." -ForegroundColor Green
Write-Host "Wait 10 seconds for permissions to propagate, then restart your Flask app." -ForegroundColor Yellow
