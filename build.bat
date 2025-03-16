@echo off
if not exist build mkdir build

REM Ensure CGO is enabled for SQLite support
set CGO_ENABLED=1

REM Install rsrc tool for manifest embedding if not already installed
go install github.com/akavel/rsrc@latest

REM Generate the .syso file from the manifest
rsrc -manifest app.manifest -o cmd/netmonitor/rsrc.syso

REM Build the application
go build -v -o build/netmonitor.exe cmd/netmonitor/main.go

echo Build completed. Executable is in the build directory.



