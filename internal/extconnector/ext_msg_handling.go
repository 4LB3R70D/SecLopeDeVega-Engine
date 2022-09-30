/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - msg_handling.go
=========================================================
Author: Alberto Dominguez

This package manages the interaction with the external connectors, as well as the control of their status.
This file has the logic of the management of messages received from the external connector and the delivery
of the corresponding responses
*/
package extconnector

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	zmq "gopkg.in/zeromq/goczmq.v4"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
)

const (
	consMaxZeroMqDeliveryAttempts int = 3
)

// lock for avoiding race conditions at the time of sending 0mq messages
var zmqMutex = &sync.Mutex{}

// ==========================================================================================
// ENCRYPTED COMM FUNCTIONS
// ==========================================================================================

// function to get a public key formated using PEM ready to be sent to the external connector
func getPublicKeyReadyToBeSent(privkey *rsa.PrivateKey) (string, error) {

	var pubCommKeyB64 string
	// prepare the pub key to be sent to the external connector
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privkey.PublicKey)
	if err != nil {
		englogging.ErrorLog("Error marshaling the key to be sent to the external connector", err)
	} else {
		pubKeyPemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  consRSAPubKeyPEM,
			Bytes: pubKeyBytes,
		})
		// transform bytes to base64
		pubCommKeyB64 = b64.StdEncoding.EncodeToString(pubKeyPemBytes[:])
	}
	return pubCommKeyB64, err
}

// function to prepare a connection to be encrypted, it returns a public key
func (ecm ExtConnManager) startEncryptedComm(extConnIDBytes []byte) (string, *rsa.PrivateKey, error) {

	//variable to return
	var pubCommKeyB64 string
	privkey, err := rsa.GenerateKey(rand.Reader, ecm.RSAKeyLength)
	if err != nil {
		englogging.ErrorLog("Error creating the RSA the encryption keys for the connection", err)
	} else {
		pubCommKeyB64, err = getPublicKeyReadyToBeSent(privkey)
	}
	return pubCommKeyB64, privkey, err
}

// ==========================================================================================
// MESSAGE DELIVERY FUNCTIONS
// ==========================================================================================

// Function to send a 0mq message
func sendZeroMQMessage(zmqRouter *zmq.Sock, extConnIDBytes []byte, msg string, deliveryAttempt int) error {

	var err error
	// -------------------------------------
	// thread safe zone
	zmqMutex.Lock()
	if err = zmqRouter.SendFrame(extConnIDBytes, zmq.FlagMore); err == nil {
		err = zmqRouter.SendFrame([]byte(msg), zmq.FlagNone)
	}
	zmqMutex.Unlock()
	// -------------------------------------
	return err
}

// function to send a message to an external connector, optionally, encrypted or not,
// depending on the 'encrypted' flag
func messageDelivery(extConnIDBytes []byte, msgExType messages.ExMessageType, msgContent string,
	encrypted bool, sessionCipher *cipher.AEAD, nonce []byte, engineAuthCode, engineAuthCodeHashSha512 string,
	pubKeyB64 string, engineID string, useSignatureInsteadOfHash bool, zmqRouter *zmq.Sock) {

	msg, err := messages.ExtMessageBuilder(engineID, engineAuthCode, engineAuthCodeHashSha512, msgExType,
		msgContent, pubKeyB64, useSignatureInsteadOfHash, encrypted, sessionCipher, nonce)

	if err != nil {
		englogging.ErrorLog("Error building the message to be sent", err)

	} else {
		deliveryAttempt := 1
		success := false

		for deliveryAttempt < consMaxZeroMqDeliveryAttempts && !success {
			if err = sendZeroMQMessage(zmqRouter, extConnIDBytes, msg, deliveryAttempt); err != nil {
				logText := fmt.Sprintf("Something went wrong while sending a messages to an external "+
					"connector service: %+v. Attempt number: '%d'", err, deliveryAttempt)
				englogging.ErrorLog(logText, nil)
				deliveryAttempt = deliveryAttempt + 1
			} else {
				success = true
			}
		}
		if !success {
			englogging.WarnLog("Message not sent, max numbers of attempts reached!", nil)
		} else {
			logText := fmt.Sprintf("Message sent to external connector '%s' successfully", string(extConnIDBytes))
			englogging.DebugLog(logText, nil)
		}
	}
}

// function to send messages, it prepares the engine credentials to be sent
// and delegate the rest in other function
func sendMessage(extConnIDBytes []byte, msgExType messages.ExMessageType, msgContent string, encrypted bool,
	sessionCipher *cipher.AEAD, nonce []byte, useSignatureInsteadOfHash bool, engineAuthCodeSignatureUsingSHA512,
	engineAuthCodeHashBlake2b, engineAuthCodeHashSha512 string, privRSAkeyEngineSign *rsa.PrivateKey, engineID string,
	zmqRouter *zmq.Sock) {

	var engineAuthCode, pubKeyB64 string
	if useSignatureInsteadOfHash {
		engineAuthCode = engineAuthCodeSignatureUsingSHA512
		englogging.DebugLog("Using engine signature as authentication code for the next "+
			"message to be sent", nil)
	} else {
		engineAuthCode = engineAuthCodeHashBlake2b
		englogging.DebugLog("Using engine hash as authentication code for the next message to be sent", nil)
	}
	if encrypted {
		// prepare the pub key to be sent to the external connector
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privRSAkeyEngineSign.PublicKey)
		if err != nil {
			englogging.ErrorLog("Error serializing the key to be sent, the public key of the engine "+
				"for signature will not be sent", err)
		} else {
			pubKeyPemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  consRSAPubKeyPEM,
				Bytes: pubKeyBytes,
			})
			pubKeyB64 = b64.StdEncoding.EncodeToString(pubKeyPemBytes[:]) // transform bytes to base64
		}
	}
	messageDelivery(extConnIDBytes, msgExType, msgContent, encrypted, sessionCipher, nonce,
		engineAuthCode, engineAuthCodeHashSha512, pubKeyB64, engineID, useSignatureInsteadOfHash, zmqRouter)
}

// function to provide an interface to send a error message to an external connector
func sendErrorMessage(extConnIDByte []byte, errorMsg string, encrypted bool, sessionCipher *cipher.AEAD, nonce []byte,
	useSignatureInsteadOfHash bool, engineAuthCodeSignatureUsingSHA512, engineAuthCodeHashBlake2b,
	engineAuthCodeHashSha512 string, privRSAkeyEngineSign *rsa.PrivateKey, engineID string, zmqRouter *zmq.Sock) {

	sendMessage(extConnIDByte, messages.ConsExError, errorMsg, encrypted, sessionCipher, nonce,
		useSignatureInsteadOfHash, engineAuthCodeSignatureUsingSHA512,
		engineAuthCodeHashBlake2b, engineAuthCodeHashSha512, privRSAkeyEngineSign, engineID, zmqRouter)
}

// ==========================================================================================
// EXTERNAL CONNECTOR REQUEST PROCESSING FUNCTIONS FOR EXT CONNECTOR MANAGER
// ==========================================================================================

// function to delegate the response of a request from an external connector to external connector workers
func (ecm *ExtConnManager) delegateResponseInExtConnWorker(extConnIDByte []byte,
	msg_processed map[string]interface{}, isMessageEncrypted bool) {

	_, currentConnection := ecm.ConnRegister.FindActiveConnectionOfAnExternalConnector(
		extConnIDByte)

	if currentConnection != nil {
		// check if the number of max workers is reached
		if ecm.currentNumberOfExtConnWorkers <= ecm.maxNumberOfExtConnWorkers {
			ecw := NewExternalConnectorWorker(*ecm.EngineID, extConnIDByte, msg_processed,
				isMessageEncrypted, ecm.ConnRegister, ecm.engineDefaultSecret, ecm.extConnectorGroups,
				ecm.useSignatureInsteadOfHash, ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
				ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign, *ecm.EngineID, ecm.zmqRouter, ecm.conversationRulesSets,
				ecm.toExtConnMngrFromWorkers, ecm.toDataService, ecm.toAlertingService, ecm.toEngineCockpit, ecm.ecdsaPrivateKey,
				ecm.activitySignatureEnable, currentConnection.ID, currentConnection.Group, currentConnection.ApplicableGroupsFlag)
			// run the external connector worker in a different thread
			go ecw.Start()
			//update the counter
			ecm.IncreaseExtConnCounter()
		} else {
			englogging.WarnLog("Max number of external connector workers reached", nil)
			sendMessage(extConnIDByte, messages.ConsExBusy, messages.ConsExMessageEmptyContent,
				ecm.ZeroMQCommEncryption, nil, nil, ecm.useSignatureInsteadOfHash,
				ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
				ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign,
				*ecm.EngineID, ecm.zmqRouter)
		}
	} else {
		englogging.WarnLog("The detected external connector connection is null for message processing!", nil)
	}
}

// function to send a Pong message, depending on the configuration, it sends the public key or not
func (ecm *ExtConnManager) sendPongMessage(extConnIDBytes []byte) {

	//declaring function variables
	var found bool
	var rsaPrivKey *rsa.PrivateKey
	var publicCommKey string
	var err error

	// responding with a 'pong' message, if communications should be encrypted,
	// then the message content is the public key
	// for encrypting the session(shared) key
	if ecm.ZeroMQCommEncryption {
		englogging.DebugLog("Preparing the public and private keys for encrypting the connection"+
			"with the external connector", nil)

		// is there an existing pair of RSA keys in place? (It also means
		// there is a valid connection already registered)
		found, rsaPrivKey = ecm.ConnRegister.GetRSAKeysOfOneConnection(extConnIDBytes)
		if found {
			englogging.DebugLog("Existing RSA pair keys found for the external connector: "+
				string(extConnIDBytes), nil)
			publicCommKey, err = getPublicKeyReadyToBeSent(rsaPrivKey)
		} else {
			englogging.DebugLog("Not RSA pair keys found for the external connector: "+string(extConnIDBytes)+
				", creating a new pair", nil)
			publicCommKey, rsaPrivKey, err = ecm.startEncryptedComm(extConnIDBytes)
		}
		// error check
		if err != nil {
			sendErrorMessage(extConnIDBytes, "Error preparing the encryption for the connection",
				messages.ConsExMessageNotEncryptedFlag, nil, nil, ecm.useSignatureInsteadOfHash,
				ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
				ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign,
				*ecm.EngineID, ecm.zmqRouter)
		} else {
			sendMessage(extConnIDBytes, messages.ConsExPong, publicCommKey, ecm.ZeroMQCommEncryption,
				nil, nil, ecm.useSignatureInsteadOfHash, ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
				ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign, *ecm.EngineID, ecm.zmqRouter)
		}
	} else {
		// not encryption case, check if the connector is already registered 
		found, _ = ecm.ConnRegister.FindActiveConnectionOfAnExternalConnector(extConnIDBytes)

		// send the message to the external connector
		sendMessage(extConnIDBytes, messages.ConsExPong, messages.ConsExMessageEmptyContent, messages.ConsExMessageNotEncryptedFlag,
			nil, nil, ecm.useSignatureInsteadOfHash, ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
			ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign, *ecm.EngineID, ecm.zmqRouter)

	}
	// if a pair of RSA kys were found, it means the connection is already registered
	if !found {
		// update the connection register with a new potential communication
		ecm.ConnRegister.AddNewNotOnboardedConnection(extConnIDBytes, ecm.ZeroMQCommEncryption, rsaPrivKey)
	}
}

// This function processes the requests received from external connectors
func (ecm *ExtConnManager) processExtConnMessage(request [][]byte) {

	if len(request) > 0 {
		//request[0] ==> 0mq router frame, request[1] the content
		//get message
		raw_msg := string(request[consExtConnMessageContent])
		msg_processed, isMessageEncrypted, err := messages.ExtMessageProcessor(raw_msg)

		if err != nil {
			englogging.ErrorLog("The message received has not the right format", err)
			sendErrorMessage(request[consExtConnID], "Received message with incorrect format",
				ecm.ZeroMQCommEncryption, nil, nil, ecm.useSignatureInsteadOfHash,
				ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
				ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign,
				*ecm.EngineID, ecm.zmqRouter)
		} else {
			englogging.DebugLog("The message received has the right format", nil)
			// if it is a 'ping' message
			if msg_processed[messages.ConsExMessageType] == messages.ConsExPing.String() {
				// check if the max number of connections is reached
				if ecm.ConnRegister.ReachedLimitOfConnections() {
					englogging.WarnLog("Max number of connections reached", nil)
					sendMessage(request[consExtConnID], messages.ConsExBusy,
						messages.ConsExMessageEmptyContent,
						ecm.ZeroMQCommEncryption, nil, nil, ecm.useSignatureInsteadOfHash,
						ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
						ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign,
						*ecm.EngineID, ecm.zmqRouter)
				} else {
					ecm.sendPongMessage(request[consExtConnID])
				}
			} else {
				//if not ping, proceed as usual
				ecm.delegateResponseInExtConnWorker(request[consExtConnID], msg_processed,
					isMessageEncrypted)
			}
		}
	} else {
		englogging.WarnLog("Something weird happens at the time of recieving a message "+
			"from the external connectors, empty message received", nil)
	}
}

// ==========================================================================================
// OTHER FUNCTIONS
// ==========================================================================================

// Auxiliary function to get a set of conversation rules given a external connection group
func getConversationRules(applicableGroups bool, group string,
	conversationRulesSets []*opvariables.ConversationRules, JsonFormatFlag bool) (string,
	*opvariables.ConversationRules, error) {

	// variables to return
	var convRuleString string
	var err error
	//intermediate variables
	var convRulesStruct *opvariables.ConversationRules
	var found bool

	// find the conversation rule for the corresponding group. In case of several,
	// it stops in the first detection
	group = strings.ToLower(group)
	for _, convRules := range conversationRulesSets {

		if convRules != nil &&
			// A - default or empty group ==> default conversation rules (2 steps)
			// A1 - is the current conversation rules the default one (emty or 'default')?
			(((len(convRules.ExtConnGroup) == 0 ||
				strings.EqualFold(opvariables.ConsDefaultConversationRulesGroup,
					convRules.ExtConnGroup)) &&
				// A2 - and, is the current group the default one (emty or 'default')?
				(len(group) == 0 ||
					strings.EqualFold(opvariables.ConsDefaultConversationRulesGroup,
						group))) ||

				// B - or, does it belong to a group?
				strings.EqualFold(strings.ToLower(convRules.ExtConnGroup), group)) {

			convRulesStruct = convRules
			found = true
			if len(group) == 0 {
				group = opvariables.ConsDefaultConversationRulesGroup
			}
			englogging.DebugLog("Conversation Rules found for the group: '"+group+"'.", nil)
			break
		}
	}
	// if a group is found, it returns the rules in a string format
	if found && JsonFormatFlag {
		convRuleString, err = convRulesStruct.GetJSONFormat()
	} else if !found {
		englogging.WarnLog("Conversation rules not found", nil)
	}
	return convRuleString, convRulesStruct, err
}
