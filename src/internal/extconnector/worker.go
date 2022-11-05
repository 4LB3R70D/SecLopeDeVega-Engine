/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - worker.go
==========================================================
Author: Alberto Dominguez

This package manages the interaction with the external connectors, as well as the control of their status.
This file contains the operation logic of the external connector workers
*/
package extconnector

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"

	"golang.org/x/crypto/blake2b"
	zmq "gopkg.in/zeromq/goczmq.v4"
)

const (
	// RSA labels
	consRSALabelSession = "session"
	consRSALabelSecret  = "secret"
	// Constants of secret "structure" to send the session key to the engine
	ConsSessionKeyField = "session_key"
	ConsNonceField      = "nonce"
)

// ExternalConnectorWorker is an object cretated to process a request received from external connectors
type ExternalConnectorWorker struct {
	extConnMessageSenderBytes          []byte
	extConnMessageContent              map[string]interface{}
	connRegister                       *opvariables.ConnectionRegister
	engineID                           string
	encryptedComms                     bool
	engineDefaultSecret                string
	extConnectorGroups                 []opvariables.ExternalConnectorGroup
	toExtConnMngr                      chan<- messages.ChannelMessage
	toDataService                      chan<- messages.ChannelMessage
	toAlertingService                  chan<- messages.ChannelMessage
	toEngineCockpit                    chan<- messages.ChannelMessage
	useSignatureInsteadOfHash          bool
	engineAuthCodeSignatureUsingSHA512 string
	engineAuthCodeHashBlake2b          string
	engineAuthCodeHashSha512           string
	privRSAkeyEngineSign               *rsa.PrivateKey
	zmqRouter                          *zmq.Sock
	conversationRulesSets              []*opvariables.ConversationRules
	ecdsaPrivateKey                    *ecdsa.PrivateKey
	activitySignatureEnable            bool
	connectionID                       int
	applicableGroups                   bool
	convRulesGroup                     string
	reloadConvRules                    bool
	engineDir                          string
	conversationRulesPath              string
	relativePath                       bool
}

// function to create a new External Connector Worker
func NewExternalConnectorWorker(myEngineID string, extConnIDByte []byte,
	myExtConnMessageContent map[string]interface{}, encryptedComms bool,
	myConnRegister *opvariables.ConnectionRegister, myEngineDefaultSecret string,
	myExtConnectorGroups []opvariables.ExternalConnectorGroup, myUseSignatureInsteadOfHash bool,
	myEngineAuthCodeSignatureUsingSHA512, myEngineAuthCodeHashBlake2b,
	myEngineAuthCodeHashSha512 string, myPrivRSAkeyEngineSign *rsa.PrivateKey, engineID string,
	myZmqRouter *zmq.Sock, myConversationRulesSets []*opvariables.ConversationRules,
	myToExtConnMngr, myToDataService, myToAlertingServicechan,
	myToEngineCockpit chan<- messages.ChannelMessage, myEcdsaPrivateKey *ecdsa.PrivateKey,
	myActivitySignatureEnable bool, myConnectionID int, myGroup string, myApplicableGroupsFlag bool,
	reloadConvRules bool, engineDir string, conversationRulesPath string, relativePath bool) *ExternalConnectorWorker {

	extConnWorker := ExternalConnectorWorker{
		extConnMessageSenderBytes:          extConnIDByte,
		extConnMessageContent:              myExtConnMessageContent,
		connRegister:                       myConnRegister,
		engineID:                           myEngineID,
		encryptedComms:                     encryptedComms,
		engineDefaultSecret:                myEngineDefaultSecret,
		extConnectorGroups:                 myExtConnectorGroups,
		useSignatureInsteadOfHash:          myUseSignatureInsteadOfHash,
		engineAuthCodeSignatureUsingSHA512: myEngineAuthCodeSignatureUsingSHA512,
		engineAuthCodeHashBlake2b:          myEngineAuthCodeHashBlake2b,
		engineAuthCodeHashSha512:           myEngineAuthCodeHashSha512,
		privRSAkeyEngineSign:               myPrivRSAkeyEngineSign,
		zmqRouter:                          myZmqRouter,
		conversationRulesSets:              myConversationRulesSets,
		toExtConnMngr:                      myToExtConnMngr,
		toDataService:                      myToDataService,
		toAlertingService:                  myToAlertingServicechan,
		toEngineCockpit:                    myToEngineCockpit,
		ecdsaPrivateKey:                    myEcdsaPrivateKey,
		activitySignatureEnable:            myActivitySignatureEnable,
		connectionID:                       myConnectionID,
		applicableGroups:                   myApplicableGroupsFlag,
		convRulesGroup:                     myGroup,
		reloadConvRules:                    reloadConvRules,
		engineDir:                          engineDir,
		conversationRulesPath:              conversationRulesPath,
		relativePath:                       relativePath,
	}
	return &extConnWorker
}

// ==========================================================================================
// CRYPTO FUNCTIONS
// ==========================================================================================

// function to decrypt a content received encrypted using RSA
func (ecw *ExternalConnectorWorker) decryptRSAEncryptedContent(hexReceivedEncryptedContent,
	label string) (bool, []byte) {

	var decryptedSecretBytes []byte
	errorDetected := false
	found, rsaPrivKey := ecw.connRegister.GetRSAKeysOfOneConnection(ecw.extConnMessageSenderBytes)
	if found {
		bytesReceivedEncryptedSecret, err := hex.DecodeString(hexReceivedEncryptedContent)
		if err != nil {
			errorDetected = true
		} else {
			decryptedSecretBytes, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivKey,
				bytesReceivedEncryptedSecret, []byte(label))
			if err != nil {
				errorDetected = true
			}
		}
		if errorDetected {
			englogging.ErrorLog("Error decrypting the content encrypted using RSA by the the "+
				"external connector: "+string(ecw.extConnMessageSenderBytes), err)
		}
	} else {
		englogging.WarnLog("Not found the RSA keys for the external connector: "+
			string(ecw.extConnMessageSenderBytes), nil)
	}
	return errorDetected, decryptedSecretBytes
}

// function to decrypt the ChaCha20 session key and nounce sent by the external connector
func (ecw *ExternalConnectorWorker) extractSessionKeyAndNonce() (bool, []byte, []byte) {

	success := false
	var sessionKey []byte
	var nonce []byte

	errorDetected, rawSessionKeyAndNonceBytes := ecw.decryptRSAEncryptedContent(
		ecw.extConnMessageContent[messages.ConsExMessageBody].(string), consRSALabelSession)
	if errorDetected {
		englogging.WarnLog("Decrypted the session key and the nounce was not possible", nil)
	} else {
		rawSessionKeyAndNonceString := string(rawSessionKeyAndNonceBytes)
		englogging.DebugLog("Session Key and Nounce received from the external connector ("+
			string(ecw.extConnMessageSenderBytes)+") are: "+rawSessionKeyAndNonceString, nil)
		// transform string to map
		session_cryptography_processed := make(map[string]string)
		// parsing raw message
		err := json.Unmarshal([]byte(rawSessionKeyAndNonceString), &session_cryptography_processed)

		// if not errors
		if err != nil {
			englogging.ErrorLog("Error during the conversion of the decrypted session key and nounce "+
				"into a map from a raw string", err)
		} else {
			//obtaining the string values
			sessionKeyString := session_cryptography_processed[ConsSessionKeyField]
			nonceString := session_cryptography_processed[ConsNonceField]

			var errK, errN error
			// obtaining the byte value
			sessionKey, errK = hex.DecodeString(sessionKeyString)
			nonce, errN = hex.DecodeString(nonceString)

			if errK != nil {
				englogging.ErrorLog("Error decoding the session key encoded in hexadecimal", errK)
			} else if errN != nil {
				englogging.ErrorLog("Error decoding the nonce encoded in hexadecimal", errN)
			} else {
				// update operation status flag
				success = true
			}
		} // json parsing
	} // decrypting
	return success, sessionKey, nonce
}

// function to decrypt an encrypted message and it returns the corresponding cipher and nonce
func (ecw *ExternalConnectorWorker) decryptMessage() (bool, *cipher.AEAD, []byte) {

	success := false
	var decryptedContentBytes []byte
	extConnMessageSenderString := string(ecw.extConnMessageSenderBytes)
	// find the corresponding connection in the register
	found, sessionCipher, nonce := ecw.connRegister.GetSessionKeyAndNoncefOneConnection(ecw.extConnMessageSenderBytes)

	if found {
		// decrypt the message and save it in the
		chacha20Cipher := *sessionCipher
		messageContentEncryptedHex := ecw.extConnMessageContent[messages.ConsExMessageEncrypted].(string)
		englogging.DebugLog("Message encrypted in hexadecimal received from the external connector: "+
			extConnMessageSenderString+": "+messageContentEncryptedHex, nil)
		messageContentEncrypted, err := hex.DecodeString(messageContentEncryptedHex)
		if err != nil {
			englogging.ErrorLog("Error decoding the base64 encoding of an encrypted message received "+
				"from the external connector: "+extConnMessageSenderString, err)
		} else {
			engineAuthCodeHashSha512Bytes := []byte(ecw.engineAuthCodeHashSha512)
			decryptedContentBytes, err = chacha20Cipher.Open(nil, nonce, messageContentEncrypted,
				engineAuthCodeHashSha512Bytes)
			if err != nil {
				englogging.ErrorLog("Error decrypting a message received from the external connector: "+
					extConnMessageSenderString+".", err)
			} else {
				decryptedContentString := string(decryptedContentBytes)
				englogging.DebugLog("Message received from the external connector: "+extConnMessageSenderString+
					", decrypted successfully. Content: "+decryptedContentString, nil)
				msg_processed, _, err := messages.ExtMessageProcessor(decryptedContentString)
				if err != nil {
					englogging.ErrorLog("Error parsing the message after being decrypted from the external connector: "+
						extConnMessageSenderString, err)
				} else {
					ecw.extConnMessageContent = msg_processed
					success = true
					englogging.DebugLog("Message parsed successfully after being decrypted for the external connector: "+
						extConnMessageSenderString, nil)
				}
			} // message decrypted successfully
		} // decode b64 sucessfully
	} // crypto materials found
	return success, sessionCipher, nonce
}

// ==========================================================================================
// CREDENTIALS CHECKING FUNCTIONS
// ==========================================================================================

// function to check if a given external connector secret hash is ok. In case
func (ecw *ExternalConnectorWorker) checkExtConnSecret(applicableGroups bool, group string, configSecret string,
	messageType string) bool {

	var ok bool // variable to return
	var hexDigestConfigSecret string

	if applicableGroups {
		bytesDigestConfigSecret := blake2b.Sum512([]byte(configSecret))        // it returns an array
		hexDigestConfigSecret = hex.EncodeToString(bytesDigestConfigSecret[:]) //it uses a go slice
	} else {
		bytesDigestConfigSecret := blake2b.Sum512([]byte(ecw.engineDefaultSecret)) // it returns an array
		hexDigestConfigSecret = hex.EncodeToString(bytesDigestConfigSecret[:])     //it uses a go slice
	}
	englogging.DebugLog("Digest obtained from the corresponding secret in the config file is: "+
		hexDigestConfigSecret, nil)

	var receivedSecret string
	// if the message is a HELLO message, then the secret is encrypted (if body field is not empty).
	// For other messages, the whole message can be encrypted, but once decrypted, everything is in plain text.
	// Only the HELLO case with body with content is the case where the secret is encrypted
	if strings.EqualFold(messageType, messages.ConsExHello.String()) &&
		!(strings.EqualFold(ecw.extConnMessageContent[messages.ConsExMessageBody].(string),
			messages.ConsExMessageEmptyContent)) {
		englogging.DebugLog("The secret is encrypted, decrypting it...", nil)
		errorDetected, receivedSecretBytes := ecw.decryptRSAEncryptedContent(
			ecw.extConnMessageContent[messages.ConsExMessageSecret].(string),
			consRSALabelSecret)
		if !errorDetected {
			receivedSecret = string(receivedSecretBytes)
			englogging.DebugLog("Secret decrypted: "+receivedSecret, nil)
		}
	} else {
		receivedSecret = ecw.extConnMessageContent[messages.ConsExMessageSecret].(string)
	}
	// check if the hash received in the message is the same obtained from the secret in the config file
	if strings.EqualFold(receivedSecret, hexDigestConfigSecret) {
		ok = true
	}
	return ok
}

// function to check if a given external connector id is part of a group, and which one.
// it stops in the moment it finds the first match. If more, they are skipped
func (ecw *ExternalConnectorWorker) checkExtConnID() (bool, string, string) {

	// flag for answering: is it part of a group?
	var applicableGroups bool
	//if so, which group and secret?
	var group string
	var configSecret string

	// for each group defined
	for _, configGroup := range ecw.extConnectorGroups {
		// flag to control when to stop the exectuion of the first loop
		alreadyFound := false

		//for each external connector declared in each group
		for _, configExtConn := range configGroup.List {
			// check if the ID is present (all in lower case)
			if strings.EqualFold(strings.ToLower(ecw.extConnMessageContent[messages.ConsExMessageID].(string)),
				strings.ToLower(configExtConn.ID)) {

				group = configGroup.ID
				configSecret = configExtConn.Secret
				applicableGroups = true
				alreadyFound = true
				englogging.DebugLog("Found the external connector ID is in the group: "+group, nil)
				// stop the second for loop
				break
			}
		} // 2nd for loop
		if alreadyFound {
			// stop the first for loop
			break
		}
	} //1st for loop
	return applicableGroups, group, configSecret
}

// function to check if some credentials provided by an external connectors are ok or not
func (ecw *ExternalConnectorWorker) checkCredentials(messageType string) (bool, bool, string) {

	englogging.DebugLog("Checking external connector credentials...", nil)
	// ID: ecw.extConnMessageContent[messages.ConsExMessageID]
	// Secret Hash - BLake2b: ecw.extConnMessageContent[messages.ConsExMessageSecret]
	applicableGroups, group, configSecret := ecw.checkExtConnID()
	okSecret := ecw.checkExtConnSecret(applicableGroups, group, configSecret, messageType)
	return okSecret, applicableGroups, group
}

// ==========================================================================================
// STARTING FUNCTION
// ==========================================================================================

// method to start the process to manage a request depending on the type of messsage received
func (ecw *ExternalConnectorWorker) Start() {
	// crypto material declaration
	var sessionCipher *cipher.AEAD
	var nonce []byte
	var successCrypto bool

	// if message is encrypted, decrypt it then
	if ecw.encryptedComms {
		successCrypto, sessionCipher, nonce = ecw.decryptMessage()
		if !successCrypto {
			englogging.WarnLog("The session cryptographic material not found, message cannot be decrypted", nil)
			sendErrorMessage(ecw.extConnMessageSenderBytes, "Message cannot be decrypted",
				messages.ConsExMessageNotEncryptedFlag, nil, nil, ecw.useSignatureInsteadOfHash,
				ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
				ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
		}
	}
	// check external connector credentials
	messageString, stringOK := ecw.extConnMessageContent[messages.ConsExMessageType].(string)
	if stringOK {
		okSecret, applicableGroups, group := ecw.checkCredentials(messageString)
		// get the current connection

		if okSecret {
			englogging.DebugLog("External connector credentials are ok!", nil)
			// detect kind of message received
			switch ecw.extConnMessageContent[messages.ConsExMessageType] {

			// HELLO message
			case messages.ConsExHello.String():
				ecw.helloMessageProcessing(applicableGroups, group)

			// INFO message
			case messages.ConsExInfo.String():
				ecw.infoMessageProcessing(sessionCipher, nonce)

			// BYE message
			case messages.ConsExBye.String():
				ecw.byeMessageProcessing(sessionCipher, nonce)

			default:
				englogging.WarnLog("Message type with unknown format. Fomat received: "+
					ecw.extConnMessageContent[messages.ConsExMessageType].(string), nil)
				sendErrorMessage(ecw.extConnMessageSenderBytes, "unknown message type", ecw.encryptedComms,
					sessionCipher, nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512,
					ecw.engineAuthCodeHashBlake2b, ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign,
					ecw.engineID, ecw.zmqRouter)
			}
			// not right credentials
		} else {
			englogging.WarnLog("Invalid credentials: Password is not right", nil)
			sendErrorMessage(ecw.extConnMessageSenderBytes, "Ah ah ah, you didn't say the magic word! (Invalid credentials)",
				ecw.encryptedComms, sessionCipher, nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512,
				ecw.engineAuthCodeHashBlake2b, ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
		}
	} else {
		englogging.WarnLog("Invalid credentials: Empty message received", nil)
		sendErrorMessage(ecw.extConnMessageSenderBytes, "Empty message?", ecw.encryptedComms, sessionCipher, nonce,
			ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
			ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
	}

	// update the counter when the worker execution is ended by means of sending a message to Ext Connector Manager
	channelMsgActivity := messages.ChannelMessage{
		Sender:  messages.ConsExtConnWorkerThread,
		Type:    messages.ConsExtConnWorkerDecreaseWorkerCounter,
		Content: nil,
	}
	ecw.toExtConnMngr <- channelMsgActivity
}

// ==========================================================================================
// PREPARE ENDING FUNCTION
// ==========================================================================================
// method to notify all external connectors to end their operations
func (ecw *ExternalConnectorWorker) PrepareEngineEnding(msg messages.ChannelMessage, connections []*opvariables.Connection, waitingEndingTime int) {

	for _, extconnectorSession := range connections {
		if extconnectorSession != nil && extconnectorSession.Active {
			// Order the external connectors to end
			sendMessage(extconnectorSession.ExtConnIDBytes, messages.ConsExOrder, ConsOrdShutdown.String(), ecw.encryptedComms,
				extconnectorSession.SessionCipher, extconnectorSession.Nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512,
				ecw.engineAuthCodeHashBlake2b, ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
		}
	}
	englogging.InfoLog("Waiting '"+strconv.Itoa(waitingEndingTime)+"' seconds for giving time to end gracefully...", nil)
	time.Sleep(time.Duration(waitingEndingTime) * time.Second)
	englogging.InfoLog("Time is up! Ending engine execution...", nil)

	// Send activiy for informing about engine end as an activity
	activity := opvariables.ExtActivity{
		ExtConnMessageSender: "ENGINE",
		EndEngine:            true,
		AlertAll:             true,
	}
	activity.FillRawActivityField(ecw.activitySignatureEnable, ecw.ecdsaPrivateKey)
	ecw.sendActivity2AlertingAndDataServices(activity)

	// Sending the end message to all of the engine services
	msg.Sender = messages.ConsExtConnWorkerThread
	msg.Content = messages.ConsStopOrder
	ecw.toExtConnMngr <- msg
	ecw.toDataService <- msg
	ecw.toAlertingService <- msg
	ecw.toEngineCockpit <- msg
}
