@echo off
echo sign
mycms-tool sign --cms-out=cms1 --data-in=mycms-tool.exe --signer-cert="file:cert=gen\\test1.crt:key=gen\\test1.key"
if errorlevel 1 goto error
echo verify
mycms-tool verify --cms-in=cms1 --data-in=mycms-tool.exe --cert="gen\\test1.crt"
if errorlevel 1 goto error
echo success
goto end
:error
echo ERROR
:end
