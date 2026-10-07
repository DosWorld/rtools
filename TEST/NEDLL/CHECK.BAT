@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b MYLIB.DLL MYLIB.REF
if errorlevel 1 goto fail
fc /b MYLIB2.DLL MYLIB2.REF
if errorlevel 1 goto fail
fc /b T07.EXE T07.REF
if errorlevel 1 goto fail
fc /b T09.EXE T09.REF
if errorlevel 1 goto fail
fc /b MLRT.DLL MYLIB.REF
if errorlevel 1 goto fail
fc /b T11.EXE T11.REF
if errorlevel 1 goto fail
fc /b T11.OUT T11.DFR
if errorlevel 1 goto fail
fc /b T12.DLL T12.REF
if errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
