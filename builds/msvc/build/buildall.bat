@ECHO OFF
:: Usage: buildall.bat

:: Build all configurations for all solutions.
call buildbase.bat ..\vs2017\secp256k1.sln 15
ECHO.
CALL buildbase.bat ..\vs2015\secp256k1.sln 14
ECHO.
CALL buildbase.bat ..\vs2013\secp256k1.sln 12
ECHO.

PAUSE
