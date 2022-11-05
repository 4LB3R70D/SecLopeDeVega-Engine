/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - connection_register.go
=================================================
Author: Alberto Dominguez

This package contains the operation variables used in the system.
This file contains logic about the connection register used by the external connector
*/

package opvariables

import (
	"bytes"
	"crypto/cipher"
	"crypto/rsa"
	"strconv"
	"sync"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"golang.org/x/crypto/chacha20poly1305"
)

// ====================================================
// CONNECTION MANAGEMENT
// ====================================================

// lock for avoiding race conditions in the connection register between the external
// connector manager and the workers. It is called in all public funcitons
var crMutex = &sync.Mutex{}

// --------------------------------------
// CONNECTION OBJECT
// --------------------------------------

// connection 'object'
type Connection struct {
	startingTime         time.Time
	Group                string
	ApplicableGroupsFlag bool
	ExtConnIDBytes       []byte
	onBoarded            bool
	Active               bool
	encrypted            bool
	rsaPrivKey           *rsa.PrivateKey
	SessionCipher        *cipher.AEAD
	Nonce                []byte
	ID                   int
}

//function to create a new connection object
func newConnection(extConnIDBytes []byte, encrypted bool, rsaKeys *rsa.PrivateKey, id int) *Connection {
	//get current date and time
	dt := time.Now()

	// connection obect
	newConn := Connection{
		startingTime:   dt,
		ExtConnIDBytes: extConnIDBytes,
		encrypted:      encrypted,
		rsaPrivKey:     rsaKeys,
		Active:         true,
		ID:             id,
	}
	return &newConn
}

// function to update a connection once it is onboarded
func (conn *Connection) OnboardConnection(group string, applicableGroups, sessionEncrypted bool, sessionKey, nonce []byte) (bool, *cipher.AEAD) {

	//variable to return
	success := false
	var sessionCipher cipher.AEAD
	var err error
	conn.onBoarded = true
	conn.Group = group
	conn.ApplicableGroupsFlag = applicableGroups
	conn.encrypted = sessionEncrypted
	if sessionEncrypted {
		sessionCipher, err = chacha20poly1305.New(sessionKey)
		conn.Nonce = nonce
		if err != nil {
			englogging.ErrorLog("Error creating the ChaCha20 cipher", err)
		} else {
			conn.SessionCipher = &sessionCipher
			success = true
		}
	} else {
		success = true
		englogging.DebugLog("Connection "+strconv.Itoa(conn.ID)+" onboarded correctly", nil)
	}
	return success, &sessionCipher
}

// Function to get a copy of a connection
func (conn *Connection) getCopy() *Connection {

	connectionCopy := Connection{
		startingTime:         conn.startingTime,
		Group:                conn.Group,
		ApplicableGroupsFlag: conn.ApplicableGroupsFlag,
		ExtConnIDBytes:       conn.ExtConnIDBytes,
		onBoarded:            conn.onBoarded,
		Active:               conn.Active,
		encrypted:            conn.encrypted,
		rsaPrivKey:           conn.rsaPrivKey,
		SessionCipher:        conn.SessionCipher,
		Nonce:                conn.Nonce,
		ID:                   conn.ID,
	}
	return &connectionCopy
}

// Function to end an existing connection
func (conn *Connection) End() {
	conn.Active = false
}

// --------------------------------------
// CONNECTION REGISTER OBJECT
// --------------------------------------

// connection register to keep the control of the connections with external connectors
type ConnectionRegister struct {

	// Connection list
	connectionList []*Connection
	// last connection ID used
	lastConnectionID int
	// max number of external connectors allowed to interact with the engine
	maxNumberOfExternalConnectors int
	// current number of external connectors
	currentNumberOfExternalConnectors int
}

// function to create a new connection register
func NewConnectionRegister(cnfg *Config) *ConnectionRegister {

	var newConnList []*Connection

	ConnRegister := ConnectionRegister{
		maxNumberOfExternalConnectors:     cnfg.ExternalConnectors.MaxNumberOfExternalConnectors,
		currentNumberOfExternalConnectors: 0,
		lastConnectionID:                  1,
		connectionList:                    newConnList,
	}
	englogging.InfoLog("New connection register created", nil)
	return &ConnRegister
}

// Function to find a set of connections given an external connector ID
// this function is NOT THREAD SAFE
func (cr *ConnectionRegister) findConnectionsOfAnExternalConnector(extConnIDBytes []byte) []*Connection {

	var connectionsFound []*Connection

	for _, connection := range cr.connectionList {
		resultComparison := bytes.Compare(extConnIDBytes, connection.ExtConnIDBytes)
		// if they are the same ID
		if resultComparison == 0 {
			//add the connection reference (pointer) in the list to return
			connectionsFound = append(connectionsFound, connection)
		}
	}
	return connectionsFound
}

// function to get the active connection of an external connector
// in theory, there should be only one, so in case of severals,
// only the last one is returned.
func (cr *ConnectionRegister) FindActiveConnectionOfAnExternalConnector(extConnIDBytes []byte) (bool, *Connection) {

	crMutex.Lock()
	defer crMutex.Unlock()

	// variables to return
	var activeConnection *Connection
	found := false

	connectionsFound := cr.findConnectionsOfAnExternalConnector(extConnIDBytes)

	for _, connection := range connectionsFound {
		// if it is active
		if connection.Active {
			activeConnection = connection
			found = true
			englogging.DebugLog("Active connection found, ID: "+strconv.Itoa(connection.ID)+
				", for the external connector: "+string(extConnIDBytes), nil)
		}
	}
	return found, activeConnection
}

// function to end a connection of the connection register
func (cr *ConnectionRegister) EndConnection(extConnIDBytes []byte) {

	found, activeConnection := cr.FindActiveConnectionOfAnExternalConnector(extConnIDBytes)
	if found {
		crMutex.Lock()
		defer crMutex.Unlock()
		activeConnection.End()
		englogging.DebugLog("Ended connection ID: "+strconv.Itoa(activeConnection.ID)+
			", for the external connector: "+string(extConnIDBytes), nil)
	}
}

// function to check if the max number of connections are reached
func (cr *ConnectionRegister) ReachedLimitOfConnections() bool {

	crMutex.Lock()
	defer crMutex.Unlock()

	// varibale to return
	result := false

	if cr.currentNumberOfExternalConnectors >= cr.maxNumberOfExternalConnectors {
		result = true
	}
	return result
}

// function to add a new connection not onboarded yet (only pong message received). In case of the
// limit of connections is reached, the connection is refused (logically speaking)
func (cr *ConnectionRegister) AddNewNotOnboardedConnection(extConnIDBytes []byte, encrypted bool,
	rsaKeys *rsa.PrivateKey) {

	// connenction to add
	nConn := newConnection(extConnIDBytes, encrypted, rsaKeys, cr.lastConnectionID)

	crMutex.Lock()
	defer crMutex.Unlock()

	//add the new connection
	cr.connectionList = append(cr.connectionList, nConn)

	englogging.InfoLog("Added a new connection in the register for the external connector: "+
		string(extConnIDBytes)+
		", with the ID: "+strconv.Itoa(cr.lastConnectionID), nil)

	//update counters
	cr.currentNumberOfExternalConnectors += 1
	cr.lastConnectionID += 1
}

//function to do the onboarding of a connection, preregistered before
func (cr *ConnectionRegister) OnboardConnection(extConnIDBytes []byte, applicableGroups,
	sessionEncrypted bool, sessionKey, nounce []byte,
	group string) (bool, *cipher.AEAD, int) {

	// variables to return
	success := false
	var sessionCipher *cipher.AEAD
	var connectionID int

	// get the current connection
	found, currentConnection := cr.FindActiveConnectionOfAnExternalConnector(extConnIDBytes)

	// if the connection is found, onboard (or re-onboard = updating session key and nonce)
	if found {
		crMutex.Lock()
		defer crMutex.Unlock()
		success, sessionCipher = currentConnection.OnboardConnection(group, applicableGroups,
			sessionEncrypted, sessionKey, nounce)
		connectionID = currentConnection.ID
	}
	return success, sessionCipher, connectionID
}

// function to get the RSA keys of a connection given an external connector ID
func (cr *ConnectionRegister) GetRSAKeysOfOneConnection(extConnIDBytes []byte) (bool, *rsa.PrivateKey) {

	// varibales to return
	var rsaPrivKey *rsa.PrivateKey
	rsaKeysFound := false

	crMutex.Lock()
	defer crMutex.Unlock()

	connectionsFound := cr.findConnectionsOfAnExternalConnector(extConnIDBytes)

	for _, connection := range connectionsFound {
		// if the connection is active. In case of several, use the last one
		// there should be one connection per external connector
		if connection.Active {
			rsaKeysFound = true
			rsaPrivKey = connection.rsaPrivKey
		}
	}
	return rsaKeysFound, rsaPrivKey
}

// function to get the session key and nonce given an external connector ID
func (cr *ConnectionRegister) GetSessionKeyAndNoncefOneConnection(extConnIDBytes []byte) (bool, *cipher.AEAD, []byte) {

	// variables to return
	var connSessionCipher *cipher.AEAD
	var connNonce []byte
	found, currentConnection := cr.FindActiveConnectionOfAnExternalConnector(extConnIDBytes)

	if found {
		crMutex.Lock()
		defer crMutex.Unlock()
		connSessionCipher = currentConnection.SessionCipher
		connNonce = currentConnection.Nonce
	}
	return found, connSessionCipher, connNonce
}

// function to end all connections
func (cr *ConnectionRegister) GetAllConnections() []*Connection {

	crMutex.Lock()
	defer crMutex.Unlock()
	connectionsCopyList := make([]*Connection, 0)

	for _, connection := range cr.connectionList {
		connectionsCopyList = append(connectionsCopyList, connection.getCopy())
	}
	return connectionsCopyList
}
