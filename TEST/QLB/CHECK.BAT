@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b HELLO.QLB HELLO.REF
if errorlevel 1 goto fail
fc /b IMPORT.QLB IMPORT.REF
if errorlevel 1 goto fail
echo OK
goto end
:fail
echo FAILED
:end
