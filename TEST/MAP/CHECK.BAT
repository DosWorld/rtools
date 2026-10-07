@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b MCOM.MAP MCOM.REF
if errorlevel 1 goto fail
fc /b MS.MAP MS.REF
if errorlevel 1 goto fail
fc /b MZ.MAP MZ.REF
if errorlevel 1 goto fail
fc /b MNE.MAP MNE.REF
if errorlevel 1 goto fail
fc /b MPE.MAP MPE.REF
if errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
