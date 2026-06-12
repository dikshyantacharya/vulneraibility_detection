@echo off
set "ZIP_NAME=project.zip"

echo Starting high-speed compression...

:: Using Windows native tar (much faster than PowerShell)
tar -a -c -f %ZIP_NAME% ^
  --exclude=".idea" ^
  --exclude=".venv" ^
  --exclude="models" ^
  --exclude="outputs" ^
  --exclude="%ZIP_NAME%" ^
  --exclude="cache" ^
  --exclude="tools" ^
  --exclude="make_project_zip" ^
  --exclude="data" ^
    --exclude="dist" ^
    --exclude=".claude" ^
    --exclude="frontend/dist" ^
    --exclude="frontend/node_modules" ^
    --exclude="patches" ^
    --exclude=".pytest_cache" ^
    --exclude=".git" ^
    --exclude=".ruff_cache" ^
    --exclude=".gitignore" ^
    --exclude="make_project_zip.bat" ^
  *

echo.
echo Backup created successfully: %ZIP_NAME%
pause