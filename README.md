# Get Signer information and certificate chain from a digitally signed EXE file AHK v1.1

A AHK v1 (Autohotkey v1.1) function that gets the chain of certificates from a digitally signed EXE file 

In details, This function retrieves digital certificate information from signed executable files (.exe). It examines the embedded PKCS#7 signature in the PE (Portable Executable) file's certificate store and returns an array containing all certificate subjects in the signature chain, including the end certificate (signer), intermediate certificates, and root certificate. The function supports both 32-bit and 64-bit environments through Windows Cryptography APIs.

GetSignatureInfo accepts a file path as input and returns either an object containing an array of certificate subjects (result.Certificates) or false if no valid certificates are found or an error occurs. 

The function is particularly useful for validating software authenticity by checking if specific trusted publishers appear anywhere in the certificate chain, not just the leaf certificate. 

You might be able to find more information here 
https://www.autohotkey.com/boards/viewtopic.php?f=6&t=135085

```ahk

GetSignatureInfo(FilePath) {
    static ENCODING := 0x10001
    static CERT_QUERY_OBJECT_FILE := 1
    static CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED := 0x400
    static CERT_QUERY_FORMAT_FLAG_BINARY := 2
    static CERT_NAME_SIMPLE_DISPLAY_TYPE := 4
    static PTR_SIZE := A_PtrSize ? A_PtrSize : 4    ; Get pointer size for current system
    
    if !(hCrypt32 := DllCall("LoadLibrary", "Str", "Crypt32.dll", "Ptr"))
        return false

    VarSetCapacity(dwEncoding, 4, 0)
    VarSetCapacity(dwContentType, 4, 0)
    VarSetCapacity(dwFormatType, 4, 0)
    VarSetCapacity(hStore, PTR_SIZE, 0)  
    VarSetCapacity(hMsg, PTR_SIZE, 0)  
    
    if !DllCall("Crypt32\CryptQueryObject"
        , "UInt", CERT_QUERY_OBJECT_FILE
        , "Str", FilePath
        , "UInt", CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
        , "UInt", CERT_QUERY_FORMAT_FLAG_BINARY
        , "UInt", 0
        , "UInt*", dwEncoding
        , "UInt*", dwContentType
        , "UInt*", dwFormatType
        , "Ptr*", hStore
        , "Ptr*", hMsg
        , "Ptr", 0) {
        DllCall("FreeLibrary", "Ptr", hCrypt32)
        return false
    }

    result := {}
    result.Certificates := []
    
    ; Start with no previous context
    pCertContext := 0
    
    ; Loop through all certificates in store
    while (pCertContext := DllCall("Crypt32\CertEnumCertificatesInStore"
        , "Ptr", hStore
        , "Ptr", pCertContext
        , "Ptr")) {
        
        nameSize := DllCall("Crypt32\CertGetNameStringW"
            , "Ptr", pCertContext
            , "UInt", CERT_NAME_SIMPLE_DISPLAY_TYPE
            , "UInt", 0
            , "Ptr", 0
            , "Ptr", 0
            , "UInt", 0)

        VarSetCapacity(SubjectName, nameSize * 2, 0)
        DllCall("Crypt32\CertGetNameStringW"
            , "Ptr", pCertContext
            , "UInt", CERT_NAME_SIMPLE_DISPLAY_TYPE
            , "UInt", 0
            , "Ptr", 0
            , "Str", SubjectName
            , "UInt", nameSize)
        
        ; Store each certificate subject
        result.Certificates.Push(SubjectName)
    }

    ; Clean up
    if (pCertContext)
        DllCall("Crypt32\CertFreeCertificateContext", "Ptr", pCertContext)
    
    DllCall("Crypt32\CertCloseStore", "Ptr", hStore, "UInt", 0)
    if (hMsg)
        DllCall("Crypt32\CryptMsgClose", "Ptr", hMsg)
    DllCall("FreeLibrary", "Ptr", hCrypt32)
    
    return result.Certificates.Length() > 0 ? result : false
}

; Example usage
;FilePath := A_Desktop . "\ChromeSetup.exe"
;FilePath := A_Desktop . "\AutoHotkey_1.1.37.02_setup.exe" 

info := GetSignatureInfo(FilePath)
if (info) {
    output := "Certificates found:`n`n"
    For index, cert in info.Certificates {
        output .= index . ": " . cert . "`n"
    }
    MsgBox % output
} else {
    MsgBox No valid certificates found
}
```
