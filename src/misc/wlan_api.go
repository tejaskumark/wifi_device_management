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
	flag.Parse()

	// Throw error and return if default values are present
	if *ssidName == "SSID_Test" || *userName == "Username_Test" || *passWord == "Password_Test" {
		fmt.Printf("Default values are not accepted for SSID or Username or Password.")
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
		return
	}
	defer session.Close()

	// Get all available interface and iterate over all of them to set eapuser profile only
	// if interface is in connected state or disconnected state.
	iil, err := session.Interfaces()
	defer iil.Close()
	for i := 0; i < int(iil.NumberOfItems); i++ {
		iif := iil.Item(uint32(i))
		if iif.State == InterfaceStateConnected || iif.State == InterfaceStateDisconnected {
			err := session.SetProfileEAPXMLUserData(&iif.InterfaceGUID, *ssidName, 1, string(fileBytes[:]))
			if err != nil {
				return
			}
		}
	}
	return
}
