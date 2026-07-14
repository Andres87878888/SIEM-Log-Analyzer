@echo off
title SIEM Local - Analizador de Logs

:: Verificar permisos de Administrador
net session >nul 2>&1
if not errorlevel 1 (
    :: Forzar a Windows a moverse a la carpeta actual donde esta el .bat
    cd /d "%~dp0"
    
    :: Ejecutar el script
    powershell -ExecutionPolicy Bypass -File "Analizador_SIEM.ps1"
    
    :: Evitar que la ventana se cierre de golpe al terminar
    echo.
    pause
) else (
    echo ==========================================================
    echo   ERROR: Se requieren privilegios de Administrador.
    echo ==========================================================
    echo Por favor, haz clic derecho sobre este archivo y selecciona
    echo "Ejecutar como administrador".
    echo.
    pause
)