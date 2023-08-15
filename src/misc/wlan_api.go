package main

import (
	"bytes"
	"flag"
	"fmt"
)

const (
	eapuserxml = `<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials">
<EapMethod>
<eapCommon:Type>25</eapCommon:Type>
<eapCommon:AuthorId>0</eapCommon:AuthorId>
</EapMethod>
<Credentials xmlns:eapUser="http://www.microsoft.com/provisioning/EapUserPropertiesV1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1" xmlns:MsPeap="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1" xmlns:MsChapV2="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1">
<baseEap:Eap>
<baseEap:Type>25</baseEap:Type>
<MsPeap:EapType>
<baseEap:Eap>
<baseEap:Type>26</baseEap:Type>
<MsChapV2:EapType>
<MsChapV2:Username>tejas</MsChapV2:Username>
<MsChapV2:Password>welcome123</MsChapV2:Password>
</MsChapV2:EapType>
</baseEap:Eap>
</MsPeap:EapType>
</baseEap:Eap>
</Credentials>
</EapHostUserCredentials>`
)

func main() {

	ssidName := flag.String("ssidname", "SSID_Test", "SSID name to set userprofile.")
	userName := flag.String("username", "Username_Test", "Username for 1x authentication.PEAP/MSCHAPv2")
	passWord := flag.String("password", "Password_Test", "Password for 1x authentication.PEAP/MSCAHPv2")
	guid := flag.String("guid", "{00000000-0000-0000-0000-000000000000}", "Interface GUID")
	flag.Parse()

	// Throw error and return if default values are present
	if *ssidName == "SSID_Test" || *userName == "Username_Test" || *passWord == "Password_Test" {
		fmt.Printf("ERROR: Default values are not accepted for SSID or Username or Password.")
		return
	}
	// Replace with username and password provided by command line values.
	fileBytes := []byte(eapuserxml)
	fileBytes = bytes.Replace(fileBytes, []byte("<MsChapV2:Username>tejas</MsChapV2:Username>"),
		[]byte("<MsChapV2:Username>"+*userName+"</MsChapV2:Username>"), 1)
	fileBytes = bytes.Replace(fileBytes, []byte("<MsChapV2:Password>welcome123</MsChapV2:Password>"),
		[]byte("<MsChapV2:Password>"+*passWord+"</MsChapV2:Password>"), 1)

	// Create session handle for api interaction.
	session, _, err := CreateClientSession(2)
	if err != nil {
		fmt.Printf("ERROR: PEAP credentials are not configured because of failure in client session creation due to %q", err)
		return
	}
	defer session.Close()

	// Get all available interface and iterate over all of them to set eapuser profile only
	// if interface is in connected state or disconnected state.
	// Also match interface GUID if provided
	areCredentialsSet := false
	errorDisplayed := false
	iil, err := session.Interfaces()
	defer iil.Close()
	for i := 0; i < int(iil.NumberOfItems); i++ {
		iif := iil.Item(uint32(i))
		if iif.State == InterfaceStateConnected || iif.State == InterfaceStateDisconnected && (iif.InterfaceGUID.String() == *guid || *guid == "{00000000-0000-0000-0000-000000000000}") {
			err := session.SetProfileEAPXMLUserData(&iif.InterfaceGUID, *ssidName, 1, string(fileBytes[:]))
			result := ""
			if err == nil {
				result = fmt.Sprintf("SUCCESS: PEAP credentials are configured for interface with GUID %s", iif.InterfaceGUID.String())
				areCredentialsSet = true
			} else {
				result = fmt.Sprintf("ERROR: PEAP credentials are not configured for interface with GUID %s due to %q", iif.InterfaceGUID.String(), err)
				errorDisplayed = true
			}
			fmt.Println(result)

			// Break from the loop and return if interface GUID is provided
			if *guid != "{00000000-0000-0000-0000-000000000000}" {
				return
			}
		}
	}

	if !areCredentialsSet && !errorDisplayed {
		fmt.Printf("ERROR: PEAP credentials are not configured. Possible reason is incorrect interface GUID provided.")
	}

	return
}
