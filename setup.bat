@echo off
setlocal

:: Check Python version
for /f "tokens=2 delims==." %%a in ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"') do (
    set PYTHON_VERSION=%%a
    goto :check_version
)

:check_version
python -c "import sys; exit(0) if sys.version_info >= (3,12,0) else exit(1)"
if errorlevel 1 (
    echo Python 3.12.0 or higher is required.
    exit /b 1
)

:: Install requirements
pip install -r requirements.txt || exit /b 1

:: Determine install flag
set MODE=-e .
if "%1"=="--prod" set MODE=.

:: Install in order
cd edoi_net
pip install %MODE% || exit /b 1
cd ..

cd httpe_core
pip install %MODE% || exit /b 1
cd ..

cd httpe_client
pip install %MODE% || exit /b 1
cd ..

cd httpe_server
pip install %MODE% || exit /b 1
cd ..

echo Setup complete.
