@echo off
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
set "PYTHONPATH=%ROOT%src;%PYTHONPATH%"
"%PY%" -m student_system_creator %*
