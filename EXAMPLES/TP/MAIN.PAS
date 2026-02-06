uses rdfload;

type
TProc = procedure;

var Module: TRDFModule;
p : pointer;
testProc : TProc;
begin

        if Load('test.rdf',Module) then begin
                p := Find(Module, 'print_msg');
                if p = nil then writeln('Exported function not found') else begin
                        testProc := TProc(p);
                        testProc;
                end;
        end;
        Free(Module);
end.

