@echo off
..\..\BIN\MAKE
if errorlevel 1 goto fail
fc /b T01.EXE T01.REF
if errorlevel 1 goto fail
fc /b T03.EXE T03.REF
if errorlevel 1 goto fail
fc /b T05.EXE T05.REF
if errorlevel 1 goto fail
nasm -f rdf T04.ASM
..\..\BIN\RLINK ne /o=T04.EXE T04.RDF T02.RDF
if not errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
