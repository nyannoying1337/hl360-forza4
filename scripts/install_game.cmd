@echo off
setlocal
if "%~1"=="" (
  echo Usage: install_game.cmd "Disc 1.iso" ["Disc 2.iso"]
  echo        install_game.cmd --title-update "extracted Disc 1 folder" "tu00000008_00000000"
  echo          Original USA disc ^(media 26FF1101^) + Title Update 4, see doc\title-update.md.
  exit /b 1
)
cd /d "%~dp0.."
set "BUILD=%CD%\out\build\win-amd64-release"
if /i "%~1"=="--title-update" goto title_update

set "PLAY_ISO=%~f1"
set "CONTENT_ISO=%~f2"
set "FM4_TOOL=%BUILD%\fm4tool.exe"
if not exist "%FM4_TOOL%" (
  echo Build fm4tool first. See README.md.
  exit /b 1
)
"%FM4_TOOL%" iso "%PLAY_ISO%" "%CD%\game\disc1" || exit /b 1
if "%CONTENT_ISO%"=="" exit /b 0
"%FM4_TOOL%" iso "%CONTENT_ISO%" "%CD%\game\disc2" || exit /b 1
"%FM4_TOOL%" install-dlc "%CD%\game\disc1" "%CD%\game\disc2" "%CD%\user"
exit /b %ERRORLEVEL%

:title_update
if "%~3"=="" (
  echo Usage: install_game.cmd --title-update "extracted Disc 1 folder" "tu00000008_00000000"
  exit /b 1
)
if not exist "%BUILD%\fm4tu.exe" (
  echo Build fm4tu first. See README.md.
  exit /b 1
)
if not exist "%~f2\default.xex" (
  echo "%~f2" is not an extracted Disc 1 ^(default.xex is missing^).
  exit /b 1
)
rem Copy first: fm4tu patches the copy, never the source folder.
robocopy "%~f2" "%CD%\game\disc1" /E /XD "$SystemUpdate" /NFL /NDL /NJH /NJS /NP
if %ERRORLEVEL% GEQ 8 exit /b 1
"%BUILD%\fm4tu.exe" apply "%CD%\game\disc1" "%~f3"
exit /b %ERRORLEVEL%
