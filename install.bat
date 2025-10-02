@echo off
REM LogSnoop Windows Installation Script
REM Installs LogSnoop as a Windows command

setlocal enabledelayedexpansion

echo 🚀 Installing LogSnoop for Windows...

REM Default installation directory
set INSTALL_DIR=%USERPROFILE%\AppData\Local\LogSnoop
if "%1" NEQ "" set INSTALL_DIR=%1

echo Installation directory: %INSTALL_DIR%

REM Create installation directory
echo 📁 Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy LogSnoop files
echo 📋 Copying LogSnoop files...
xcopy /E /I /Y logsnoop "%INSTALL_DIR%\logsnoop\"
copy cli.py "%INSTALL_DIR%\"
copy requirements.txt "%INSTALL_DIR%\"
copy README.md "%INSTALL_DIR%\"
if exist bin xcopy /E /I /Y bin "%INSTALL_DIR%\bin\"

REM Create virtual environment and install dependencies
echo 🐍 Setting up Python environment...
cd /d "%INSTALL_DIR%"
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Create batch wrapper in a location that's likely in PATH
echo 🔗 Creating command wrapper...
set BATCH_CONTENT=@echo off
set BATCH_CONTENT=!BATCH_CONTENT!%newline%cd /d "%INSTALL_DIR%"
set BATCH_CONTENT=!BATCH_CONTENT!%newline%call .venv\Scripts\activate.bat
set BATCH_CONTENT=!BATCH_CONTENT!%newline%python cli.py %%*

echo !BATCH_CONTENT! > "%INSTALL_DIR%\logsnoop.bat"

REM Try to add to PATH or suggest manual addition
echo 🛤️ Setting up PATH...
set PATH_DIR=%INSTALL_DIR%

REM Check if we can modify PATH (requires admin rights for system-wide)
echo Adding LogSnoop to PATH...
setx PATH "%PATH%;%PATH_DIR%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo ✅ LogSnoop added to PATH successfully!
) else (
    echo ⚠️  Could not automatically add to PATH.
    echo Please add manually:
    echo   1. Open System Properties ^> Environment Variables
    echo   2. Add "%PATH_DIR%" to your PATH variable
    echo   Or run this in an elevated command prompt:
    echo   setx PATH "%%PATH%%;%PATH_DIR%" /M
)

echo.
echo ✅ LogSnoop installed successfully!
echo.
echo 📋 Installation Summary:
echo   • LogSnoop files: %INSTALL_DIR%
echo   • Command wrapper: %INSTALL_DIR%\logsnoop.bat
echo.
echo 🎯 Usage:
echo   • Open a new command prompt and run: logsnoop --help
echo   • List plugins: logsnoop list-plugins
echo   • Parse logs: logsnoop parse your-log-file.log plugin_name
echo.
echo 🔄 Restart your command prompt to use the logsnoop command.

pause