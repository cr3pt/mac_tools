# Noriben SOC v6.8 — instalacja Noriben w VM
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = 'Stop'
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile "C:\python_setup.exe"
    Start-Process "C:\python_setup.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
}
Invoke-WebRequest "https://github.com/Rurik/Noriben/archive/refs/heads/master.zip" -OutFile "C:\noriben.zip"
Expand-Archive "C:\noriben.zip" -DestinationPath "C:\" -Force
if (Test-Path "C:\Noriben-master") { Rename-Item "C:\Noriben-master" "C:\noriben" }
python -m pip install psutil
Write-Host "Noriben gotowy w C:\noriben"
