# =====================================================
# SAFE DEMO FILE - Sentinel AI Security Testing
# =====================================================
# This file is COMPLETELY HARMLESS but contains patterns
# that appear suspicious to malware detection systems.
# Perfect for demonstrating Sentinel AI's analysis.
# =====================================================

# Suspicious Pattern 1: Base64 Encoded Data
$encodedPayload = "VGhpcyBpcyBqdXN0IGEgdGVzdCBtZXNzYWdlIGZvciBkZW1vbnN0cmF0aW9uIHB1cnBvc2VzLiBObyBtYWx3YXJlIGhlcmUh"

# Suspicious Pattern 2: Encoding/Decoding Operations
$decodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedPayload))

# Suspicious Pattern 3: Network-Related API Calls (commented but still detected)
# Invoke-WebRequest -Uri "https://example.com/test.txt" -OutFile "test.txt"
# Start-Process "notepad.exe"
# Invoke-Expression $command

# Suspicious Pattern 4: Registry-Like Operations (harmless)
$registryPath = "HKCU:\Software\TestDemo"
# New-Item -Path $registryPath -Force
# Set-ItemProperty -Path $registryPath -Name "TestValue" -Value "Demo"

# Suspicious Pattern 5: File Operations
$tempFolder = $env:TEMP
$testFile = Join-Path $tempFolder "sentinel_demo.txt"

# Suspicious Pattern 6: Obfuscation-Like Variable Names
$x = "Demo"
$y = "Test"
$z = $x + $y

# Suspicious Pattern 7: Download Simulation (never executes)
function Simulate-Download {
    param([string]$url, [string]$output)
    Write-Host "DEMO: Would download from $url to $output (but won't actually do it)"
}

# Suspicious Pattern 8: Process-Related Keywords
$processInfo = @{
    Name = "DemoProcess"
    Action = "Simulate"
    Status = "Safe"
}

# Suspicious Pattern 9: Multiple encoding layers
$doubleEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($encodedPayload))

# Display safe output
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SENTINEL AI DEMO FILE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Decoded message: $decodedText" -ForegroundColor Yellow
Write-Host "Double encoded: $doubleEncoded" -ForegroundColor Yellow
Write-Host ""
Write-Host "This file contains suspicious PATTERNS but is completely SAFE." -ForegroundColor Green
Write-Host "Perfect for testing Sentinel AI's detection capabilities!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# The actual decoded message says:
# "This is just a test message for demonstration purposes. No malware here!"
