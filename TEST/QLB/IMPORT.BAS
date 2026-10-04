DECLARE FUNCTION twice% CDECL (n%)
DECLARE SUB RAISE5 ()
DECLARE FUNCTION SYMSEG% ()
n% = 21
PRINT "twice(21) ="; twice%(n%)
PRINT "symbol block segment ="; HEX$(SYMSEG%)
ON ERROR GOTO Handler
CALL RAISE5
PRINT "back from the library"
SYSTEM
Handler:
PRINT "BASIC error"; ERR
RESUME NEXT
