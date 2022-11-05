/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - worker_toolbox.go
================================================================
Author: Alberto Dominguez

This package manages the interaction with the external connectors, as well as the control of their status.
This file is where the messages of the external connectors are processed (tools to do so)
*/
package extconnector

import (
	"crypto/cipher"
	"strings"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
)

// ==========================================================================================
// AUXILIARY FUNCTIONS FUNCTIONS
// ==========================================================================================
// Function to send activities to alerting and data services
func (ecw *ExternalConnectorWorker) sendActivity2AlertingAndDataServices(activity opvariables.ExtActivity) {

	// create a message to send the activity to the corresponding services
	channelMsgActivity := messages.ChannelMessage{
		Sender:  messages.ConsExtConnWorkerThread,
		Type:    messages.ConsActivity,
		Content: activity,
	}

	// send the messages
	// https://stackoverflow.com/questions/25657207/how-to-know-a-buffered-channel-is-full
	activitySent2DataService := false
	activitySent2AlertingService := false
	for !activitySent2AlertingService && !activitySent2DataService {
		// if the activity has not ben sent yet
		if !activitySent2DataService {
			// Channel full?
			if len(ecw.toDataService) < cap(ecw.toDataService) {
				ecw.toDataService <- channelMsgActivity
				activitySent2DataService = true
			}
		}
		// if the activity has not ben sent yet
		if !activitySent2AlertingService {
			// Channel full?
			if len(ecw.toDataService) < cap(ecw.toDataService) {
				ecw.toAlertingService <- channelMsgActivity
				activitySent2AlertingService = true
			}
		}
	}
}

// ==========================================================================================
// MESSAGE PROCESSING FUNCTIONS
// ==========================================================================================

// method for processing a HELLO message from an external connector and do
// the onboarding to the engine
func (ecw *ExternalConnectorWorker) helloMessageProcessing(applicableGroups bool, group string) {

	// function internal variables
	var sessionEncrypted bool
	var success bool
	var sessionCipher *cipher.AEAD
	var connectionID int
	var nonce []byte
	var sessionKey []byte
	var successDecryption bool

	// check if the communication should be encrypted or not (BODY message empty or not)
	if strings.EqualFold(
		ecw.extConnMessageContent[messages.ConsExMessageBody].(string),
		messages.ConsExMessageEmptyContent) {
		success, sessionCipher, connectionID = ecw.connRegister.OnboardConnection(ecw.extConnMessageSenderBytes,
			applicableGroups, sessionEncrypted, nil, nil, group)

	} else {
		sessionEncrypted = true
		//get the sessionKey and nounce provided by the external connector
		successDecryption, sessionKey, nonce = ecw.extractSessionKeyAndNonce()

		if successDecryption {
			success, sessionCipher, connectionID = ecw.connRegister.OnboardConnection(ecw.extConnMessageSenderBytes,
				applicableGroups, sessionEncrypted, sessionKey, nonce, group)
		}
	}
	// if the operation has been successfully, send the conversation rules, if not, send an error message
	if success {
		activity := opvariables.ExtActivity{
			ExtConnMessageSender:     string(ecw.extConnMessageSenderBytes),
			ExtConnBelongGroupFlag:   applicableGroups,
			ExtConnGroup:             group,
			NewExtConnSession:        true,
			ExternalConnectorSession: connectionID,
			AlertAll:                 true,
		}
		activity.FillRawActivityField(ecw.activitySignatureEnable, ecw.ecdsaPrivateKey)
		ecw.sendActivity2AlertingAndDataServices(activity)

		var convRulesToUse []*opvariables.ConversationRules
		if ecw.reloadConvRules{
			convRulesToUse = opvariables.LoadConversationRules(ecw.engineDir, ecw.conversationRulesPath, ecw.relativePath) 
		}else{
			convRulesToUse = ecw.conversationRulesSets
		}

		// get the conversation rules given an external connector group
		convRulesString, _, err := getConversationRules(applicableGroups, group, convRulesToUse, true)

		if err != nil {
			sendErrorMessage(ecw.extConnMessageSenderBytes, "Error getting the conversation rules",
				ecw.encryptedComms, sessionCipher, nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512,
				ecw.engineAuthCodeHashBlake2b, ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
			englogging.ErrorLog("Error getting the conversation rules to be sent", err)

		} else {
			sendMessage(ecw.extConnMessageSenderBytes, messages.ConsExHello, convRulesString, ecw.encryptedComms, sessionCipher,
				nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
				ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
			englogging.InfoLog("Conversation Rules for the group: "+group+" sent to the external connector", nil)
		}
	} else {
		sendErrorMessage(ecw.extConnMessageSenderBytes, "Error loading the session cryptography", false,
			nil, nil, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
			ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
		englogging.WarnLog("Error message sent to the external connector telling it the session cryptography could not be loaded", nil)
	}
}

// method for processing a INFO message received from an external connector
func (ecw *ExternalConnectorWorker) infoMessageProcessing(sessionCipher *cipher.AEAD, nonce []byte) {

	sendMessage(ecw.extConnMessageSenderBytes, messages.ConsExACK, messages.ConsExACK.String(), ecw.encryptedComms,
		sessionCipher, nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
		ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)
	englogging.InfoLog("After receiving activities information, OK message sent as acknowledgment", nil)

	// Get each activity of the list and send it to the data service and the alerting service for processing
	// Activity info: ecw.extConnMessageContent["BODY"].(data)[X].(data), where X is the index in the slice of the activity
	acitivitiesInfo := ecw.extConnMessageContent[messages.ConsExMessageBody].([]interface{})
	for _, rawActivity := range acitivitiesInfo {
		rawActivityTypeChanged, ok := rawActivity.(map[string]interface{})
		if ok {
			// get the conversation rules given an external connection group
			_, convRulesStruct, err := getConversationRules(ecw.applicableGroups, ecw.convRulesGroup, ecw.conversationRulesSets, false)

			activity := opvariables.ProcessActivity(rawActivityTypeChanged, string(ecw.extConnMessageSenderBytes),
				ecw.ecdsaPrivateKey, ecw.activitySignatureEnable, ecw.connectionID, ecw.convRulesGroup, convRulesStruct, err)

			ecw.sendActivity2AlertingAndDataServices(activity)

		} else {
			englogging.ErrorLog("Error casting the external activity received", nil)
		}
	}
}

// method for processing a BYE message received from an external connector
// and "disconnect" it form the engine
func (ecw *ExternalConnectorWorker) byeMessageProcessing(sessionCipher *cipher.AEAD, nonce []byte) {

	sendMessage(ecw.extConnMessageSenderBytes, messages.ConsExACK, messages.ConsExACK.String(), ecw.encryptedComms,
		sessionCipher, nonce, ecw.useSignatureInsteadOfHash, ecw.engineAuthCodeSignatureUsingSHA512, ecw.engineAuthCodeHashBlake2b,
		ecw.engineAuthCodeHashSha512, ecw.privRSAkeyEngineSign, ecw.engineID, ecw.zmqRouter)

	// create new activity to inform about the desconnection of the external connector
	activity := opvariables.ExtActivity{
		ExtConnMessageSender:     string(ecw.extConnMessageSenderBytes),
		EndExtConnSession:        true,
		ExternalConnectorSession: ecw.connectionID,
		AlertAll:                 true,
	}
	activity.FillRawActivityField(ecw.activitySignatureEnable, ecw.ecdsaPrivateKey)
	ecw.sendActivity2AlertingAndDataServices(activity)
	englogging.InfoLog("OK message sent", nil)
}
