Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise GenAI & LLM Security Gateway on AWS" -ForegroundColor Cyan
Write-Host "  OWASP Top 10 for LLMs · Bedrock Zero-Trust Proxy" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    & $VenvPython -m src.cli simulate
} else {
    python -m src.cli simulate
}
