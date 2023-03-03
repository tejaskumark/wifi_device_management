
package main

import (
	"unsafe"
	"golang.org/x/sys/windows"
)

//sys	wlanFreeMemory(memory unsafe.Pointer) = wlanapi.WlanFreeMemory
//sys	wlanOpenHandle(clientVersion uint32, reserved uintptr, negotiatedVersion *uint32, clientHandle *windows.Handle) (ret error) = wlanapi.WlanOpenHandle
//sys	wlanCloseHandle(clientHandle windows.Handle, reserved uintptr) (ret error) = wlanapi.WlanCloseHandle
//sys	wlanEnumInterfaces(clientHandle windows.Handle, reserved uintptr, interfaceList **InterfaceInfoList) (ret error) = wlanapi.WlanEnumInterfaces
//sys	wlanSetProfileEAPXMLUserData(clientHandle windows.Handle, interfaceGUID *windows.GUID, profileName *uint16, flags uint32, eapXMLUserData *uint16, reserved uintptr) (ret error) = wlanapi.WlanSetProfileEapXmlUserData

// InterfaceState is the state of the network (interface).
type InterfaceState uint32

const (
	InterfaceStateNotReady InterfaceState = iota
	InterfaceStateConnected
	InterfaceStateAdHocNetworkFormed
	InterfaceStateDisconnecting
	InterfaceStateDisconnected
	InterfaceStateAssociating
	InterfaceStateDiscovering
	InterfaceStateAuthenticating
)

const maxNameLength = 256

// InterfaceInfo defines the basic information for an interface
type InterfaceInfo struct {
	InterfaceGUID        windows.GUID
	InterfaceDescription [maxNameLength]uint16
	State                InterfaceState
}

// InterfaceInfoList contains an array of NIC interface information.
type InterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

// Item returns interface info at the given index.
func (iil *InterfaceInfoList) Item(idx uint32) *InterfaceInfo {
	if idx > iil.NumberOfItems {
		panic("index out of range")
	}
	addr := uintptr(unsafe.Pointer(iil))
	addr += unsafe.Sizeof(InterfaceInfoList{})
	addr += unsafe.Sizeof(InterfaceInfo{}) * uintptr(idx)
	return (*InterfaceInfo)(unsafe.Pointer(addr))
}

// InterfaceInfoGet Get individual item of interaface.
func (iif *InterfaceInfo) InterfaceInfoGet() (guid string, desc string, state InterfaceState) {
	guid = iif.InterfaceGUID.String()
	desc = windows.UTF16ToString(iif.InterfaceDescription[:])
	state = iif.State
	return guid, desc, state
}

// Close frees the memory.
func (iil *InterfaceInfoList) Close() {
	wlanFreeMemory(unsafe.Pointer(iil))
}

// ClientSession is the client's session handle.
type ClientSession windows.Handle

// CreateClientSession opens a connection to the server.
func CreateClientSession(clientVersion uint32) (session ClientSession, 
negotiatedVersion uint32, err error) {
	var handle windows.Handle
	err = wlanOpenHandle(clientVersion, 0, &negotiatedVersion, &handle)
	if err != nil {
		session = ClientSession(0)
		return
	}
	session = ClientSession(handle)
	return
}

// Close closes a connection to the server.
func (session ClientSession) Close() error {
	return wlanCloseHandle(windows.Handle(session), 0)
}

// Interfaces enumerates all of the wireless LAN interfaces currently enabled on the local
// computer. Call Close on InterfaceInfoList returned to free resources.
func (session ClientSession) Interfaces() (*InterfaceInfoList, error) {
	var iil *InterfaceInfoList
	err := wlanEnumInterfaces(windows.Handle(session), 0, &iil)
	if err != nil {
		return nil, err
	}
	return iil, nil
}

// SetProfileEAPXMLUserData sets the Extensible Authentication Protocol (EAP) user credentials as
// specified by an XML string. The user credentials apply to a profile on an adapter. These
// credentials can only be used by the caller.
func (session ClientSession) SetProfileEAPXMLUserData(interfaceGUID *windows.GUID, 
profileName string, flags uint32, eapXMLUserData string) error {
	profileName16, err := windows.UTF16PtrFromString(profileName)
	if err != nil {
		return err
	}
	eapXMLUserData16, err := windows.UTF16PtrFromString(eapXMLUserData)
	if err != nil {
		return err
	}
	return wlanSetProfileEAPXMLUserData(windows.Handle(session), interfaceGUID,
	profileName16, flags, eapXMLUserData16, 0)
}
