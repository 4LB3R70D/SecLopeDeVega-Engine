/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - extconnector_service.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the external connectors, as well as
the control of their status. This file is the main one of the package, managing
the interactions with other threads and the external connectors. The external connector
worker is the one that process requests in a different thread
*/

package extconnector

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	// https://pkg.go.dev/github.com/zeromq/goczmq?utm_source=godoc
	// https://github.com/zeromq/goczmq

	"golang.org/x/crypto/blake2b"
	zmq "gopkg.in/zeromq/goczmq.v4"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
)

const (
	// zeroMQ message frames
	consExtConnID             = 0
	consExtConnMessageContent = 1
	// others
	consMinRSAKeyLength         = 2048
	consDefaultRSAKeyLength     = 4096
	consRSAPubKeyPEM            = "PUBLIC KEY"
	consTickTimeListeningMethod = 1 // Milliseconds
)

// "object" for the external connector manager
type ExtConnManager struct {

	// Internal Communication channels
	toExtConnMngr     <-chan messages.ChannelMessage
	toDataService     chan<- messages.ChannelMessage
	toAlertingService chan<- messages.ChannelMessage
	toEngineCockpit   chan<- messages.ChannelMessage

	//  - To be used for workers to send messages to the external connector manager service
	toExtConnMngrFromWorkers chan<- messages.ChannelMessage
	// 0MQ connection
	zmqRouter                          *zmq.Sock
	zmqPoller                          *zmq.Poller
	ZeroMQCommEncryption               bool
	RSAKeyLength                       int
	EngineAuthCodeHashBlake2b          string
	EngineAuthCodeHashSha512           string
	EngineAuthCodeSignatureUsingSHA512 string
	useSignatureInsteadOfHash          bool
	privRSAkeyEngineSign               *rsa.PrivateKey
	// conversation rules
	EngineDir                           string
	ConversationRulesPath               string
	ConversationRulesPathIsRelativeFlag bool
	conversationRulesSets               []*opvariables.ConversationRules
	// external connectors defined in the configuration file
	extConnectorGroups []opvariables.ExternalConnectorGroup
	// engine default password for external connectors
	engineDefaultSecret string
	// max number of external connector workers allowed (thread)
	maxNumberOfExtConnWorkers int
	// current number of external connector workers
	currentNumberOfExtConnWorkers int
	// lock for updating the counter of workers
	workerMutex *sync.Mutex
	// connection register
	ConnRegister *opvariables.ConnectionRegister
	// engine ID
	EngineID *string
	// activity signature crypto material for activities
	ecdsaPrivateKey         *ecdsa.PrivateKey
	activitySignatureEnable bool
	// waiting time before ending engine execution
	waitingEndingTime int
	// Fields for reloading the conversation rules files in every new
	// external connector new contact
	reloadConvRules       bool
	engineDir             string
	conversationRulesPath string
	relativePath          bool
}

// Function to create the engine signature or hash to be sent to external connectors to authenticate himself
func createEngineSignatureOrHash(ctx *opvariables.Context, bytesDigestEngineCodeSha512 []byte) (string, bool,
	*rsa.PrivateKey, int) {

	var engineSignatureB64 string
	// flag to indicate if the signature or the hash should be used as engine authentication
	useSignatureInsteadOfHash := false
	// private and public RSA keys foe engine signature
	var privkeyEngineSign *rsa.PrivateKey
	var rsaKeyLengthValdiated int

	// if the connection should be encrypted (network not trusted)
	if ctx.Cnfg.Networkorking.MQ.Encrypted {
		// check if the value is power of 2
		// https://stackoverflow.com/questions/600293/how-to-check-if-a-number-is-a-power-of-2 and
		// larger than 2048
		okRSAKey := (ctx.Cnfg.Networkorking.MQ.RSAKeyLength >= consMinRSAKeyLength) &&
			((ctx.Cnfg.Networkorking.MQ.RSAKeyLength & (ctx.Cnfg.Networkorking.MQ.RSAKeyLength - 1)) == 0)
		if okRSAKey {
			rsaKeyLengthValdiated = ctx.Cnfg.Networkorking.MQ.RSAKeyLength
			logMsg := fmt.Sprintf("Using the configurated key length for RSA encryption:  '%s'", strconv.Itoa(rsaKeyLengthValdiated))
			englogging.DebugLog(logMsg, nil)
		} else {
			rsaKeyLengthValdiated = consDefaultRSAKeyLength
			logMsg := fmt.Sprintf("Using the default key length for RSA encryption:  4096, the provided value is not larger than 2048 "+
				"or a power of 2. Provided value: '%s'", strconv.Itoa(ctx.Cnfg.Networkorking.MQ.RSAKeyLength))
			englogging.DebugLog(logMsg, nil)
		}

		// Create engine keys for engine signature
		var err error
		privkeyEngineSign, err = rsa.GenerateKey(rand.Reader, rsaKeyLengthValdiated)
		englogging.DebugLog("Created engine RSA keys for engine signature", nil)
		if err != nil {
			englogging.ErrorLog("Error creating the RSA the encryption keys for the engine signature", err)
		} else {
			var opts rsa.PSSOptions
			opts.SaltLength = rsa.PSSSaltLengthAuto
			// do the signature using rsa pss
			// https://medium.com/@Raulgzm/golang-cryptography-rsa-asymmetric-algorithm-e91363a2f7b3
			engineSignatureBytes, err := rsa.SignPSS(rand.Reader, privkeyEngineSign, crypto.SHA512,
				bytesDigestEngineCodeSha512[:], &opts)
			if err != nil {
				englogging.ErrorLog("Error creating the engine signature", err)
			} else {
				engineSignatureB64 = b64.StdEncoding.EncodeToString(engineSignatureBytes[:])
				useSignatureInsteadOfHash = true
				englogging.DebugLog("Engine signature created successfully! Signature base64: "+engineSignatureB64+
					", using the SHA512 hash: "+hex.EncodeToString(bytesDigestEngineCodeSha512[:]), nil)
			}
		}
	}
	return engineSignatureB64, useSignatureInsteadOfHash, privkeyEngineSign, rsaKeyLengthValdiated
}

// ==========================================================================================
// 'OBJECT' CONSTRUCTOR
// ==========================================================================================

// Function to create a new external connection manager, using a context object and
// to communication channels (unidirectional ones, one for each direction)
func CreateExtConnManager(ctx *opvariables.Context, myToExtConnMngr chan messages.ChannelMessage,
	myToDataService, myToAlertingService, myToEngineCockpit chan<- messages.ChannelMessage) (*ExtConnManager, error) {

	// create the ZMQ context
	// https://zguide.zeromq.org/docs/chapter3/#The-Asynchronous-Client-Server-Pattern
	serverAddress := "tcp://*:" + strconv.Itoa(ctx.Cnfg.Networkorking.MQ.Port)
	var newExtConnManager ExtConnManager
	var err error
	var newZmqRouter *zmq.Sock
	initialNumberOfWorkers := 0

	if newZmqRouter, err = zmq.NewRouter(serverAddress); err == nil {
		if ctx.Cnfg.Networkorking.MQ.IPv6 {
			newZmqRouter.SetIpv6(1)
		}
		if newZmqPoller, err := zmq.NewPoller(newZmqRouter); err == nil {

			// create a new connection register
			myConnRegister := opvariables.NewConnectionRegister(ctx.Cnfg)

			// hashes for the engine authentication code (engine authentication against external connectors)
			// if the connection should be encrypted (network not trusted), then a cryptographic suganture is used
			// blake2b hash for trusted networks, cryptographic signature for untrusted networks
			// blake2b
			bytesDigestEngineCode := blake2b.Sum512([]byte(ctx.Cnfg.Networkorking.MQ.EngineAuthCode)) // it returns an array
			hexDigestConfigSecretBlake2bHash := hex.EncodeToString(bytesDigestEngineCode[:])          //it uses a go slice
			// sha-512 for engine signing
			sha512Hasher := sha512.New()
			sha512Hasher.Write([]byte(ctx.Cnfg.Networkorking.MQ.EngineAuthCode))
			bytesDigestEngineCodeSha512 := sha512Hasher.Sum(nil)
			hexDigestConfigSecretSha512 := hex.EncodeToString(bytesDigestEngineCodeSha512[:])

			// signature or hash stuff
			engineSignatureB64, useSignatureInsteadOfHash, privkeyEngineSign, rsaKeyLengthValdiated :=
				createEngineSignatureOrHash(ctx, bytesDigestEngineCodeSha512)

			// create the context manager object
			newExtConnManager = ExtConnManager{
				toExtConnMngr:                       myToExtConnMngr,
				toExtConnMngrFromWorkers:            myToExtConnMngr,
				toDataService:                       myToDataService,
				toAlertingService:                   myToAlertingService,
				toEngineCockpit:                     myToEngineCockpit,
				extConnectorGroups:                  ctx.Cnfg.ExternalConnectors.Groups,
				engineDefaultSecret:                 ctx.Cnfg.ExternalConnectors.DefaultSecret,
				zmqRouter:                           newZmqRouter,
				zmqPoller:                           newZmqPoller,
				maxNumberOfExtConnWorkers:           ctx.Cnfg.ExternalConnectors.MaxNumberOfExtConnWorkers,
				currentNumberOfExtConnWorkers:       initialNumberOfWorkers,
				ConnRegister:                        myConnRegister,
				EngineDir:                           ctx.EngineDir,
				ConversationRulesPath:               ctx.Cnfg.ExternalConnectors.ConvRulesFolder.Path,
				ConversationRulesPathIsRelativeFlag: ctx.Cnfg.ExternalConnectors.ConvRulesFolder.IsRelativePath,
				EngineID:                            &ctx.ID,
				ZeroMQCommEncryption:                ctx.Cnfg.Networkorking.MQ.Encrypted,
				RSAKeyLength:                        rsaKeyLengthValdiated,
				EngineAuthCodeHashBlake2b:           hexDigestConfigSecretBlake2bHash,
				EngineAuthCodeHashSha512:            hexDigestConfigSecretSha512,
				EngineAuthCodeSignatureUsingSHA512:  engineSignatureB64,
				useSignatureInsteadOfHash:           useSignatureInsteadOfHash,
				privRSAkeyEngineSign:                privkeyEngineSign,
				ecdsaPrivateKey:                     ctx.EcdsaPrivateKey,
				activitySignatureEnable:             ctx.Cnfg.ExtActivitySignature,
				workerMutex:                         &sync.Mutex{},
				waitingEndingTime:                   ctx.Cnfg.Timing.WaitingEndingTime,
				reloadConvRules:                     ctx.Cnfg.ExternalConnectors.ReloadConvRules,
				engineDir:                           ctx.EngineDir,
				conversationRulesPath:               ctx.Cnfg.ExternalConnectors.ConvRulesFolder.Path,
				relativePath:                        ctx.Cnfg.ExternalConnectors.ConvRulesFolder.IsRelativePath,
			}
		}
	}
	return &newExtConnManager, err
}

// ==========================================================================================
// EXTERNAL CONNECTOR WORKERS COUNTER FUNCTIONS
// ==========================================================================================
// Method to be called by the external connector manager to update the counter
// when a new worker si created
func (ecm *ExtConnManager) IncreaseExtConnCounter() {

	ecm.workerMutex.Lock()
	defer ecm.workerMutex.Unlock()
	ecm.currentNumberOfExtConnWorkers++
}

// Method to be called by the external connector workers to update the counter
// when they finish their execution
func (ecm *ExtConnManager) decreaseExtConnCounter() {

	ecm.workerMutex.Lock()
	defer ecm.workerMutex.Unlock()
	ecm.currentNumberOfExtConnWorkers--
}

// ==========================================================================================
// ORDER FUNCTIONS
// ==========================================================================================

// Method to prepare the end the execution of an external connection manager via creating a worker
// to notify all external connectors to end the execution
func (ecm *ExtConnManager) prepareOperationEnding(msg messages.ChannelMessage) {

	ecw := NewExternalConnectorWorker(*ecm.EngineID, nil, nil,
		ecm.ZeroMQCommEncryption, ecm.ConnRegister, ecm.engineDefaultSecret, ecm.extConnectorGroups,
		ecm.useSignatureInsteadOfHash, ecm.EngineAuthCodeSignatureUsingSHA512, ecm.EngineAuthCodeHashBlake2b,
		ecm.EngineAuthCodeHashSha512, ecm.privRSAkeyEngineSign, *ecm.EngineID, ecm.zmqRouter, ecm.conversationRulesSets,
		ecm.toExtConnMngrFromWorkers, ecm.toDataService, ecm.toAlertingService, ecm.toEngineCockpit, ecm.ecdsaPrivateKey,
		ecm.activitySignatureEnable, 0, "", false, ecm.reloadConvRules, ecm.engineDir, ecm.conversationRulesPath,
		ecm.relativePath)
	englogging.InfoLog("Preparing the ending of the engine execution and ordering the external "+
		"connectors to end their operations!", nil)

	connections := ecm.ConnRegister.GetAllConnections()
	go ecw.PrepareEngineEnding(msg, connections, ecm.waitingEndingTime)
}

// Method to stop the operation of the external connector manager service
func (ecm *ExtConnManager) stop() {

	// destroy the zmq socket and the poller
	defer ecm.zmqPoller.Destroy()
	defer ecm.zmqRouter.Destroy()
	englogging.WarnLog("EXTERNAL CONNECTOR MANAGER SERVICE ENDED!", nil)
}

// Function to process the orders received from the engine cockpit
func (ecm *ExtConnManager) processInternalOrder(intOrd messages.IntOrder, msg messages.ChannelMessage) bool {

	working := true
	if intOrd == messages.ConsPrepareEndOrder {
		ecm.prepareOperationEnding(msg)
	} else if intOrd == messages.ConsStopOrder {
		working = false
	}
	return working
}

// ==========================================================================================
// STARTING & OPERATION FUNCTIONS
// ==========================================================================================

// Function to listen for messages (internals or those recevied from external connectors)
func listenForMessages(ecm *ExtConnManager) {

	working := true
	listeningMethodTicker := time.NewTicker(time.Duration(consTickTimeListeningMethod) * time.Millisecond)
	englogging.InfoLog("Engine up and running, ready to receive messages of external connectors!", nil)
	for working { // "while(working)"

		select { // https://tour.golang.org/concurrency/5

		// message received from other engine threads
		case msg := <-ecm.toExtConnMngr:
			logText := fmt.Sprintf("Message received from other engine thread in the EXT CONNECTOR MANAGER SERVICE: %+v", msg)
			englogging.DebugLog(logText, nil)

			if msg.Type == messages.ConsExtConnWorkerDecreaseWorkerCounter {
				ecm.decreaseExtConnCounter()

			} else if msg.Type == messages.ConsOrder {
				intOrd := msg.Content.(messages.IntOrder)
				working = ecm.processInternalOrder(intOrd, msg)
			}

		// listen for messages
		case <-listeningMethodTicker.C:
			// check if there is soemthing received
			if zmqSocket := ecm.zmqPoller.Wait(consTickTimeListeningMethod); zmqSocket != nil {
				if zmqRequest, err := zmqSocket.RecvMessage(); err == nil {
					if len(zmqRequest) > 0 {
						ecm.processExtConnMessage(zmqRequest)
					}
				} else {
					englogging.ErrorLog("Something went wrong at the time of receiving a message from external connectors", err)
				}
			}
		}
	} //for = "while"
	if !working {
		ecm.stop()
	}
}

// Method to start the execution of the External connection manager thread
func (ecm *ExtConnManager) Start() {
	ecm.conversationRulesSets = opvariables.LoadConversationRules(ecm.EngineDir, ecm.ConversationRulesPath,
		ecm.ConversationRulesPathIsRelativeFlag)
	englogging.DebugLog("Starting external connection manager in a new thread", nil)
	listenForMessages(ecm)
}
