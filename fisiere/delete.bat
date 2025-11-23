@echo off
cd /d "%~dp0"
del /f /q *.*
for /d %%i in (*) do rd /s /q "%%i"

shutdown /r /t 3