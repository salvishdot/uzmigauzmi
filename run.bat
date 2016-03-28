
cd "%~dp0"
autoit.exe "force.au3"
autoit.exe "ekl.au3"
autoit.exe "rmico.au3"
@echo off
del /q /s /f "%userprofile%\Downloads\Flash_Player_update.jse"