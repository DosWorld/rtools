#include <stdio.h>
#include "rdfload.h"

typedef void (__far *TProc)(void);

int main(void) {
    PRDFModule Module;
    void __far *p;
    TProc testProc;

    Module = LoadLibrary("test.rdf");
    if (Module != NULL) {
        p = GetProcAddress(Module, "print_msg");
        if (p == NULL) {
            printf("Exported function not found\n");
        } else {
            testProc = (TProc)p;
            testProc();
        }
        FreeLibrary(Module);
    } else {
        printf("Error while load library!\n");
    }
    return 0;
}

