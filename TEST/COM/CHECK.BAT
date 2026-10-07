@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b T01.COM T01.REF
if errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
