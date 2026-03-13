# RDFLOAD Example for Open Watcom C x86 16-bit.

Open Watcom C x86 16-bit Optimizing Compiler
Version 2.0 beta Mar 21 2025 02:32:42 (32-bit)
Copyright (c) 2002-2025 The Open Watcom Contributors. All Rights Reserved.
Portions Copyright (c) 1984-2002 Sybase, Inc. All Rights Reserved.
Source code is available under the Sybase Open Watcom Public License.
See https://github.com/open-watcom/open-watcom-v2#readme for details.

This example show how to load RDF as external dynamic library
and make a call to exported RDF procedure.

MAIN.C - main file
RDFLOAD.C - library for loading RDF
TEST.ASM - contains "hello world"-procedure

So, MAIN.C load TEST.RDF with RDFLOAD.C help and call procedure print_msg.
