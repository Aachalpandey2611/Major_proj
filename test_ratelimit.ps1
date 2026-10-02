$targetId = "0841b434-9523-4775-8440-57217399efae"
$wrongKey = "wrong-key-test-123"

for ($i=1; $i -le 6; $i++) {
    $resp = curl.exe -s -o NUL -w "%{http_code}" `
        -X POST "http://localhost:8001/api/v1/scans/ci?target_id=$targetId" `
        -H "X-API-Key: $wrongKey"

    Write-Host "Attempt $i -> Status: $resp"
    Start-Sleep -Milliseconds 500
}