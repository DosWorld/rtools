@echo off
copy /b S_HX16.STB + PAD.BIN BIG16.STB > NUL
copy /b S_ZRDX.STB + PAD.BIN BIGZ.STB > NUL
..\..\BIN\RESTUB ..\NE\T01.REF NE1.EXE BIG16.STB
if errorlevel 1 goto fail
..\..\BIN\RESTUB NE1.EXE NE2.EXE S_HX16.STB
if errorlevel 1 goto fail
fc /b NE2.EXE ..\NE\T01.REF
if errorlevel 1 goto fail
..\..\BIN\RESTUB ..\WINPE\T01.REF PE1.EXE S_HX32.STB
if errorlevel 1 goto fail
..\..\BIN\RESTUB PE1.EXE PE2.EXE S_WIN.STB
if errorlevel 1 goto fail
fc /b PE2.EXE ..\WINPE\T01.REF
if errorlevel 1 goto fail
..\..\BIN\RESTUB ..\DOSLE\T01.REF LE1.EXE BIGZ.STB
if errorlevel 1 goto fail
..\..\BIN\RESTUB LE1.EXE LE2.EXE S_ZRDX.STB
if errorlevel 1 goto fail
fc /b LE2.EXE ..\DOSLE\T01.REF
if errorlevel 1 goto fail
..\..\BIN\RESTUB ..\ADAM\T01.REF AD1.EXE S_SMALL.STB
if errorlevel 1 goto fail
..\..\BIN\RESTUB AD1.EXE AD2.EXE S_DOS32.STB
if errorlevel 1 goto fail
fc /b AD2.EXE ..\ADAM\T01.REF
if errorlevel 1 goto fail
..\..\BIN\RESTUB ..\ADAM\T01.REF AD3.EXE S_SIMP.STB
if not errorlevel 1 goto fail
..\..\BIN\RESTUB ..\NE\T01.REF NE3.EXE PAD.BIN
if not errorlevel 1 goto fail
..\..\BIN\RESTUB S_WIN.STB X.EXE S_WIN.STB
if not errorlevel 1 goto fail
..\..\BIN\RESTUB ..\NE\T01.REF ..\NE\T01.REF S_WIN.STB
if not errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
