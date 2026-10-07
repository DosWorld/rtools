@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b FWDDLL.DLL FWDDLL.REF
if errorlevel 1 goto fail
fc /b F02.EXE F02.REF
if errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
