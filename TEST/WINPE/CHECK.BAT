@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b T01.EXE T01.REF
if errorlevel 1 goto fail
fc /b MYDLL.DLL MYDLL.REF
if errorlevel 1 goto fail
fc /b T03.EXE T03.REF
if errorlevel 1 goto fail
fc /b T04.EXE T04.REF
if errorlevel 1 goto fail
fc /b MLRT.DLL MYDLL.REF
if errorlevel 1 goto fail
fc /b MLGEN.DEF MYDLL.DFR
if errorlevel 1 goto fail
echo OK
goto end
:fail
echo FAILED
:end
