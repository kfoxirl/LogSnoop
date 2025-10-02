@echo off
REM LogSnoop Windows Batch Wrapper
REM Provides a native Windows command experience for LogSnoop

setlocal enabledelayedexpansion

REM Get the directory where this batch file is located
set SCRIPT_DIR=%~dp0

REM Try to find LogSnoop installation
set LOGSNOOP_DIR=
set CLI_PATH=

REM Check if we're in the source directory
if exist "%SCRIPT_DIR%cli.py" (
    set LOGSNOOP_DIR=%SCRIPT_DIR%
    set CLI_PATH=%SCRIPT_DIR%cli.py
    goto :found_installation
)

REM Check if we're in a bin directory with source nearby
if exist "%SCRIPT_DIR%..\cli.py" (
    set LOGSNOOP_DIR=%SCRIPT_DIR%..
    set CLI_PATH=%SCRIPT_DIR%..\cli.py
    goto :found_installation
)

REM Check for virtual environment Python executable
:found_installation
if "%LOGSNOOP_DIR%"=="" (
    echo Error: Could not find LogSnoop installation.
    echo Make sure LogSnoop is properly installed or run from the source directory.
    exit /b 1
)

REM Find Python executable
set PYTHON_EXE=
if exist "%LOGSNOOP_DIR%\.venv\Scripts\python.exe" (
    set PYTHON_EXE=%LOGSNOOP_DIR%\.venv\Scripts\python.exe
) else if exist "%LOGSNOOP_DIR%\venv\Scripts\python.exe" (
    set PYTHON_EXE=%LOGSNOOP_DIR%\venv\Scripts\python.exe
) else (
    set PYTHON_EXE=python
)

REM Change to LogSnoop directory and execute
cd /d "%LOGSNOOP_DIR%"
"%PYTHON_EXE%" "%CLI_PATH%" %*

REM Preserve exit code
exit /b %ERRORLEVEL%