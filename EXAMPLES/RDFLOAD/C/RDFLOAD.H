#ifndef RDFLOAD_H
#define RDFLOAD_H

typedef struct TExportSym {
    char Name[33];
    void __far *Addr;
    struct TExportSym __far *Next;
} TExportSym;
typedef TExportSym __far *PExportSym;

typedef struct TRDFModule {
    void __far *CodeBase;
    void __far *DataBase;
    unsigned short CodeSize;
    unsigned short DataSize;
    unsigned short DataRawSize;
    PExportSym Exports;
    struct TRDFModule __far *Next;
} TRDFModule;
typedef TRDFModule __far *PRDFModule;

#ifdef __cplusplus
extern "C" {
#endif

PRDFModule LoadLibrary(const char *FileName);
void __far *GetProcAddress(PRDFModule Module, const char *Name);
void FreeLibrary(PRDFModule Module);

#ifdef __cplusplus
}
#endif

#endif

