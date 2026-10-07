@echo off
if "%NASM%"=="" set NASM=..\BIN\NASM
if "%RLINK%"=="" set RLINK=..\BIN\RLINK
for %%f in (RDFLD32 RDFLD16 RDFLDR RDFEXEC) do %NASM% -f rdf %%f.ASM
if errorlevel 1 goto err
%RLINK% mzt /o=RDFLD32.EXE RDFLD32.RDF
if errorlevel 1 goto err
%RLINK% mzt /o=RDFLD16.EXE RDFLD16.RDF
if errorlevel 1 goto err
%RLINK% mzt /o=RDFLDR.EXE RDFLDR.RDF
if errorlevel 1 goto err
%RLINK% mzt /o=RDFEXEC.EXE RDFEXEC.RDF
if errorlevel 1 goto err
del *.RDF
goto end
:err
echo Build failed
:end
