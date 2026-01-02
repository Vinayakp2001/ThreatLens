# ThreatLens System Testing Script (PowerShell)
# Tests all components before running full analysis

param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

Write-Host "🚀 ThreatLens System Testing" -ForegroundColor Green
Write-Host "=" * 50

$TestResults = @()

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Body = $null,
        [int]$TimeoutSec = 30
    )
    
    $StartTime = Get-Date
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            TimeoutSec = $TimeoutSec
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json)
            $params.ContentType = "application/json"
        }
        
        $Response = Invoke-RestMethod @params
        $Duration = (Get-Date) - $StartTime
        
        Write-Host "✅ PASS $Name ($($Duration.TotalSeconds.ToString('F2'))s)" -ForegroundColor Green
        
        $script:TestResults += @{
            Test = $Name
            Success = $true
            Duration = $Duration.TotalSeconds
            Details = "OK"
        }
        
        return $Response
    }
    catch {
        $Duration = (Get-Date) - $StartTime
        Write-Host "❌ FAIL $Name ($($Duration.TotalSeconds.ToString('F2'))s)" -ForegroundColor Red
        Write-Host "   $($_.Exception.Message)" -ForegroundColor Yellow
        
        $script:TestResults += @{
            Test = $Name
            Success = $false
            Duration = $Duration.TotalSeconds
            Details = $_.Exception.Message
        }
        
        return $null
    }
}

# Test 1: Basic Connectivity
Write-Host "`n🔌 Testing Basic Connectivity..." -ForegroundColor Cyan
$HealthResponse = Test-Endpoint "Server Connectivity" "$BaseUrl/health"

if ($HealthResponse) {
    Write-Host "   Status: $($HealthResponse.status)" -ForegroundColor Gray
}

# Test 2: System Diagnostics
Write-Host "`n🔍 Testing System Diagnostics..." -ForegroundColor Cyan
$DiagResponse = Test-Endpoint "System Diagnostics" "$BaseUrl/diagnostics"

# Test 3: Resource Status
Write-Host "`n💻 Testing Resource Status..." -ForegroundColor Cyan
$ResourceResponse = Test-Endpoint "Resource Status" "$BaseUrl/resources"

if ($ResourceResponse) {
    $HasGPU = $ResourceResponse.system_capabilities.has_gpu
    $ProcessingMode = $ResourceResponse.processing_mode
    Write-Host "   Mode: $ProcessingMode, GPU: $HasGPU" -ForegroundColor Gray
}

# Test 4: Database Connection
Write-Host "`n🗄️ Testing Database Connection..." -ForegroundColor Cyan
if ($HealthResponse) {
    $DbStatus = $HealthResponse.database_status
    if ($DbStatus -eq "healthy") {
        Write-Host "✅ PASS Database Connection" -ForegroundColor Green
        Write-Host "   Database: $DbStatus" -ForegroundColor Gray
    } else {
        Write-Host "❌ FAIL Database Connection" -ForegroundColor Red
        Write-Host "   Database: $DbStatus" -ForegroundColor Yellow
    }
}

# Test 5: LLM Connection
Write-Host "`n🤖 Testing LLM Connection..." -ForegroundColor Cyan
$ConfigResponse = Test-Endpoint "LLM Connection" "$BaseUrl/config/test" "POST"

# Test 6: Repository Validation
Write-Host "`n📁 Testing Repository Validation..." -ForegroundColor Cyan
$RepoBody = @{ repo_url = "https://github.com/octocat/Hello-World" }
$RepoResponse = Test-Endpoint "Repository Validation" "$BaseUrl/validate_repo" "POST" $RepoBody

if ($RepoResponse) {
    Write-Host "   Valid: $($RepoResponse.valid)" -ForegroundColor Gray
}

# Summary
Write-Host "`n" + "=" * 50
$PassedTests = ($TestResults | Where-Object { $_.Success }).Count
$TotalTests = $TestResults.Count

Write-Host "📊 Test Results: $PassedTests/$TotalTests tests passed" -ForegroundColor White

if ($PassedTests -eq $TotalTests) {
    Write-Host "🎉 All systems operational! Ready for repository analysis." -ForegroundColor Green
    exit 0
} else {
    Write-Host "⚠️  Some tests failed. Check the issues above before proceeding." -ForegroundColor Yellow
    
    Write-Host "`n📋 Failed Tests:" -ForegroundColor Red
    $TestResults | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Host "   ❌ $($_.Test): $($_.Details)" -ForegroundColor Red
    }
    
    exit 1
}