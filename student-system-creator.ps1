$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
$env:PYTHONPATH = (Join-Path $Root "src") + ";" + $env:PYTHONPATH
& $Py -m student_system_creator @args
exit $LASTEXITCODE
