@echo off
if exist CHK.LST del CHK.LST
if exist CHK.RES del CHK.RES
for %%d in (ADAM COM DOSLE DOSLE2 DOSLE3 DOSPE DOSPE2 DOSPE3 DOSPE4 LINK MZL MZS MAP MZT NE NEDLL QLB QLB21 RDF RESTUB WINPE WINPE2) do command /c CHK1.BAT %%d
type CHK.RES
del CHK.RES
if exist CHK.LST goto bad
echo ALL OK
goto end
:bad
echo FAILED:
type CHK.LST
del CHK.LST
:end
