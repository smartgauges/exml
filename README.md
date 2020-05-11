# exml

- exml is a simple programm, it can decrypte/encrypte JLR exml/xml files.
Usage to decrypt: xml -decrypt VINDecode.exml
Usage to encrypt: xml VINDecode.xml

- hack.dll is a proxy dll, it can intercept CryptImportKey call.
This dll is compiled with [Detours](https://github.com/microsoft/Detours) and registry entry AppInit_DLLs can be used to inject hack.dll to JLR SDD.

