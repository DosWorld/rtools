@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b DOSDLL.DLL DOSDLL.REF
if errorlevel 1 goto fail
fc /b T01.EXE T01.REF
if errorlevel 1 goto fail
echo OK
goto end
:fail
echo FAILED
:end
