@echo off
nasm -f rdf U0.ASM
nasm -f rdf U1.ASM
nasm -f rdf U2.ASM
nasm -f rdf U3.ASM
nasm -f rdf L1.ASM
nasm -f rdf L2.ASM
nasm -f rdf DA.ASM
nasm -f rdf DB.ASM
nasm -f rdf DC.ASM
..\..\BIN\RLINK mzs /o=A0.EXE U0.RDF
..\..\BIN\RLINK mzs /o=A1.EXE U1.RDF U0.RDF
if errorlevel 1 goto fail
fc /b A0.EXE A1.EXE
if errorlevel 1 goto fail
..\..\BIN\RLINK mzs /o=A2.EXE U0.RDF U2.RDF
if errorlevel 1 goto fail
fc /b A0.EXE A2.EXE
if errorlevel 1 goto fail
if exist A3.EXE del A3.EXE
..\..\BIN\RLINK mzs /o=A3.EXE U3.RDF
if not errorlevel 1 goto fail
if exist A3.EXE goto fail
..\..\BIN\RLIB c LIB.RDL
..\..\BIN\RLIB a LIB.RDL L2.RDF helper
..\..\BIN\RLIB a LIB.RDL U2.RDF helper2
..\..\BIN\RLINK mzs /o=B1.EXE L1.RDF LIB.RDL
if errorlevel 1 goto fail
..\..\BIN\RLINK mzs /o=B2.EXE L1.RDF L2.RDF
if errorlevel 1 goto fail
fc /b B1.EXE B2.EXE
if errorlevel 1 goto fail
..\..\BIN\RLIB a LIB.RDL L2.RDF helper
if not errorlevel 1 goto fail
..\..\BIN\RLIB d LIB.RDL helper2
if errorlevel 1 goto fail
..\..\BIN\RLIB x LIB.RDL helper X.RDF
if errorlevel 1 goto fail
fc /b X.RDF L2.RDF
if errorlevel 1 goto fail
..\..\BIN\RLIB d LIB.RDL nothere
if not errorlevel 1 goto fail
..\..\BIN\RLINK mzs /o=D1.EXE DA.RDF DB.RDF DC.RDF
..\..\BIN\RLINK mzs /o=E1.EXE DA.RDF DB.RDF
fc /b D1.EXE E1.EXE
if errorlevel 1 goto fail
..\..\BIN\RLINK mzs /o=D2.EXE DA.RDF DC.RDF DB.RDF
..\..\BIN\RLINK mzs /o=E2.EXE DA.RDF DC.RDF
fc /b D2.EXE E2.EXE
if errorlevel 1 goto fail
fc /b E1.EXE E2.EXE > NUL
if not errorlevel 1 goto fail
nasm -f rdf DE.ASM
..\..\BIN\RLINK mzs /o=S0.EXE DE.RDF
if not errorlevel 1 goto fail
..\..\BIN\RLINK mzs /s=0 /o=S1.EXE U0.RDF
if not errorlevel 1 goto fail
..\..\BIN\RLINK com /org=70000 /o=S2.COM U0.RDF
if not errorlevel 1 goto fail
..\..\BIN\RLINK rdf /map /o=S3.MAP U0.RDF
if not errorlevel 1 goto fail
if exist BIG.RDL del BIG.RDL
..\..\BIN\RLIB c BIG.RDL
for %%a in (0 1 2 3 4 5 6 7 8 9) do call BIGA.BAT %%a
..\..\BIN\RLINK mzs /o=BIG.EXE L1.RDF BIG.RDL
if errorlevel 1 goto fail
echo OK
echo OK > CHECK.OK
goto end
:fail
echo FAILED
:end
