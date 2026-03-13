/*  MIT License

Copyright (c) 2026 Viacheslav Komenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <i86.h>
#include <stdint.h>
#include "rdfload.h"

#define REC_RELOC    1
#define REC_GLOBAL   3
#define REC_BSS      5
#define REC_SEGRELOC 6

typedef struct {
    char Sign[6];
    uint32_t ModSize;
    uint32_t HeadSize;
} TRDFHeader;

typedef struct {
    uint16_t SegType;
    uint16_t SegNum;
    uint16_t Reserved;
    uint32_t Length;
} TSegHeader;

typedef struct {
    uint8_t RecType;
    uint8_t RecLen;
} TRecHeader;

static uint16_t Align2(uint16_t size) {
    if (size & 1) size++;
    return size;
}

static void ExtractString(const uint8_t *buf, int offset, int maxlen, char *out) {
    int i = 0;
    while (offset + i < maxlen && buf[offset + i] != 0) {
        out[i] = buf[offset + i];
        i++;
    }
    out[i] = '\0';
}

static long GetBSSSize(int fd, long start, long end) {
    TRecHeader h;
    uint8_t buf[256];
    long total = 0;
    uint32_t val;

    lseek(fd, start, SEEK_SET);
    while (lseek(fd, 0, SEEK_CUR) < end) {
        if (read(fd, &h, sizeof(h)) != sizeof(h)) break;
        if (h.RecLen > 0) {
            if (read(fd, buf, h.RecLen) != h.RecLen) break;
        }
        if (h.RecType == REC_BSS) {
            val = (uint32_t)buf[0]
                | ((uint32_t)buf[1] << 8)
                | ((uint32_t)buf[2] << 16)
                | ((uint32_t)buf[3] << 24);
            total += val;
        }
    }
    return total;
}

static void ScanSegments(int fd, long start, long *csize, long *dsize) {
    TSegHeader sh;
    *csize = 0;
    *dsize = 0;

    lseek(fd, start, SEEK_SET);
    do {
        if (read(fd, &sh, sizeof(sh)) != sizeof(sh)) break;
        if (sh.SegType == 1) *csize += sh.Length;
        else if (sh.SegType == 2) *dsize += sh.Length;
        if (sh.Length > 0) lseek(fd, sh.Length, SEEK_CUR);
    } while (sh.SegType != 0);
}

static void LoadSegmentData(int fd, long start, PRDFModule mod) {
    TSegHeader sh;
    uint16_t curCodeOfs = 0, curDataOfs = 0;

    lseek(fd, start, SEEK_SET);
    do {
        if (read(fd, &sh, sizeof(sh)) != sizeof(sh)) break;
        if (sh.Length == 0) continue;

        if (sh.SegType == 1) {
            if (curCodeOfs + sh.Length <= mod->CodeSize) {
                read(fd, (char __far *)mod->CodeBase + curCodeOfs, (size_t)sh.Length);
                curCodeOfs += (uint16_t)sh.Length;
            } else {
                lseek(fd, sh.Length, SEEK_CUR);
            }
        } else if (sh.SegType == 2) {
            if (curDataOfs + sh.Length <= mod->DataRawSize) {
                read(fd, (char __far *)mod->DataBase + curDataOfs, (size_t)sh.Length);
                curDataOfs += (uint16_t)sh.Length;
            } else {
                lseek(fd, sh.Length, SEEK_CUR);
            }
        } else {
            lseek(fd, sh.Length, SEEK_CUR);
        }
    } while (sh.SegType != 0);
}

static void ApplyRecords(int fd, long start, long end, PRDFModule mod) {
    TRecHeader h;
    uint8_t buf[256];
    uint8_t flags, width, gseg;
    uint32_t offset, goffset;
    uint16_t rseg;
    void __far *base, *target, *patch;
    uint16_t delta;
    PExportSym newsym;

    lseek(fd, start, SEEK_SET);
    while (lseek(fd, 0, SEEK_CUR) < end) {
        if (read(fd, &h, sizeof(h)) != sizeof(h)) break;
        if (h.RecLen > 0) {
            if (read(fd, buf, h.RecLen) != h.RecLen) break;
        }

        switch (h.RecType) {
            case REC_RELOC:
            case REC_SEGRELOC:
                flags = buf[0];
                offset = (uint32_t)buf[1]
                       | ((uint32_t)buf[2] << 8)
                       | ((uint32_t)buf[3] << 16)
                       | ((uint32_t)buf[4] << 24);
                width = buf[5];
                rseg = (uint16_t)buf[6] | ((uint16_t)buf[7] << 8);

                if ((flags & 0x0F) == 0)
                    base = mod->CodeBase;
                else
                    base = mod->DataBase;

                patch = (char __far *)base + (uint16_t)offset;

                if (rseg == 0)
                    target = mod->CodeBase;
                else if (rseg == 1)
                    target = mod->DataBase;
                else if (rseg == 2)
                    target = (char __far *)mod->DataBase + mod->DataRawSize;
                else
                    target = mod->DataBase;

                if (h.RecType == REC_RELOC) {
                    if (width == 2) {
                        delta = FP_OFF(target);
                        *(uint16_t __far *)patch += delta;
                    }
                } else {
                    if (width == 2) {
                        *(uint16_t __far *)patch = FP_SEG(target);
                    }
                }
                break;

            case REC_GLOBAL:
                gseg = buf[1];
                goffset = (uint32_t)buf[2]
                        | ((uint32_t)buf[3] << 8)
                        | ((uint32_t)buf[4] << 16)
                        | ((uint32_t)buf[5] << 24);

                newsym = (PExportSym)malloc(sizeof(TExportSym));
                if (newsym == NULL) break;
                ExtractString(buf, 6, h.RecLen, newsym->Name);
                newsym->Next = mod->Exports;
                mod->Exports = newsym;

                if (gseg == 0)
                    newsym->Addr = (char __far *)mod->CodeBase + (uint16_t)goffset;
                else if (gseg == 2)
                    newsym->Addr = (char __far *)mod->DataBase + mod->DataRawSize + (uint16_t)goffset;
                else
                    newsym->Addr = (char __far *)mod->DataBase + (uint16_t)goffset;
                break;
        }
    }
}

PRDFModule LoadLibrary(const char *FileName) {
    int fd;
    TRDFHeader hdr;
    long rec_start, seg_start;
    long rcsize, rdsize, rbssize;
    PRDFModule mod = NULL;

    fd = open(FileName, O_RDONLY | O_BINARY);
    if (fd == -1) return NULL;

    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return NULL;
    }
    if (memcmp(hdr.Sign, "RDOFF2", 6) != 0) {
        close(fd);
        return NULL;
    }

    rec_start = lseek(fd, 0, SEEK_CUR);
    seg_start = rec_start + hdr.HeadSize;

    rbssize = GetBSSSize(fd, rec_start, seg_start);
    ScanSegments(fd, seg_start, &rcsize, &rdsize);

    if (rcsize > 65520L || (rdsize + rbssize) > 65520L) {
        close(fd);
        return NULL;
    }

    mod = (PRDFModule)malloc(sizeof(TRDFModule));
    if (mod == NULL) {
        close(fd);
        return NULL;
    }
    memset(mod, 0, sizeof(TRDFModule));

    mod->CodeSize = Align2((uint16_t)rcsize);
    mod->DataSize = Align2((uint16_t)(rdsize + rbssize));
    mod->DataRawSize = (uint16_t)rdsize;

    if (mod->CodeSize) {
        mod->CodeBase = _fmalloc(mod->CodeSize);
        if (mod->CodeBase == NULL) goto error;
    }
    if (mod->DataSize) {
        mod->DataBase = _fmalloc(mod->DataSize);
        if (mod->DataBase == NULL) goto error;
        _fmemset(mod->DataBase, 0, mod->DataSize);
    }

    LoadSegmentData(fd, seg_start, mod);
    ApplyRecords(fd, rec_start, seg_start, mod);

    close(fd);
    return mod;

error:
    if (mod->CodeBase) _ffree(mod->CodeBase);
    if (mod->DataBase) _ffree(mod->DataBase);
    free(mod);
    close(fd);
    return NULL;
}

void __far *GetProcAddress(PRDFModule Module, const char *Name) {
    PExportSym cur;
    if (Module == NULL || Name == NULL) return NULL;
    cur = Module->Exports;
    while (cur != NULL) {
        if (strcmp(cur->Name, Name) == 0)
            return cur->Addr;
        cur = cur->Next;
    }
    return NULL;
}

void FreeLibrary(PRDFModule Module) {
    PExportSym cur, next;
    if (Module == NULL) return;

    cur = Module->Exports;
    while (cur != NULL) {
        next = cur->Next;
        free(cur);
        cur = next;
    }

    if (Module->CodeSize && Module->CodeBase)
        _ffree(Module->CodeBase);
    if (Module->DataSize && Module->DataBase)
        _ffree(Module->DataBase);

    free(Module);
}
