@echo off
cd %1
if exist CHECK.OK del CHECK.OK
call CHECK.BAT
if exist CHECK.OK goto ok
echo %1 >> ..\CHK.LST
echo %1: FAILED >> ..\CHK.RES
goto end
:ok
del CHECK.OK
echo %1: OK >> ..\CHK.RES
:end
cd ..
