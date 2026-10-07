@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b T03.RDF T03.REF
if errorlevel 1 goto fail
echo OK
goto end
:fail
echo FAILED
:end
