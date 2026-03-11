uses rdfload;

type
TProc = procedure;

var     Module: PRDFModule;
        p : pointer;
        testProc : TProc;
begin
        Module := LoadLibrary('test.rdf');
        if Module <> nil then begin
                p := GetProcAddress(Module, 'print_msg');
                if p = nil then writeln('Exported function not found') else begin
                        testProc := TProc(p);
                        testProc;
                end;
        end else WriteLn('Error while load library!');
        FreeLibrary(Module);
end.

