/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - ext_conn_messages.go
=================================================
Author: Alberto Dominguez

This package contains the main message logic used in the engine.
This file contains logic about the messages send between external
connectors and the engine
*/

package messages

import (
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	_ "golang.org/x/crypto/chacha20poly1305"

	"sec-lope-de-vega/internal/englogging"
)

//--------------------------------
// External connector messages ENUM
//--------------------------------
type ExMessageType int

const (
	ConsExHello ExMessageType = iota
	ConsExPing
	ConsExPong
	ConsExOrder
	ConsExACK
	ConsExInfo
	ConsExBye
	ConsExError
	ConsExBusy
)

// method to provide text to each enum option
func (xmt ExMessageType) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"HELLO", "PING", "PONG", "ORDER", "ACK", "INFO",
		"BYE", "ERROR", "BUSY"}[xmt]
}

const (
	// Constants of message fields
	ConsExMessageType               = "TYPE"
	ConsExMessageID                 = "ID"
	ConsExMessageEngineHash         = "ENGINE_CODE"
	ConsExMessageTime               = "TIME"
	ConsExMessageBody               = "BODY"
	ConsExMessageSecret             = "SECRET"
	ConsExMessageEncrypted          = "ENCRYPTED"
	ConsExMessageEnginePubKey       = "PUBKEY"
	ConsExMessageEngineUseSignature = "USE_SIGNATURE"
	ConsExMessageNotEncryptedFlag   = false

	// Constants of secret "structure" to send the session key to the engine
	ConsSessionKeyField = "session_key"
	ConsNonceField      = "nonce"

	// Options of the field "USE_SIGNATURE"
	ConsExMessageYesSignature = "YES"
	ConsExMessageNoSignature  = "NO"

	// Other Constants
	ConsExMessageEmptyContent = "None"
)

// function to build messages to be sent to the external connector
func ExtMessageBuilder(engineID, engineAuthCode, engineAuthCodeHashSha512 string, emt ExMessageType, 
	info string, pubKeyB64 string, useSignatureInsteadOfHash bool, encrypted bool,
	sessionCipher *cipher.AEAD, nonce []byte) (string, error) {

	// variable to return
	var message_string string

	message := make(map[string]string)

	// message construction
	message[ConsExMessageID] = engineID
	message[ConsExMessageEngineHash] = engineAuthCode
	message[ConsExMessageType] = emt.String()
	message[ConsExMessageBody] = info
	message[ConsExMessageEnginePubKey] = pubKeyB64

	if useSignatureInsteadOfHash {
		message[ConsExMessageEngineUseSignature] = ConsExMessageYesSignature
	} else {
		message[ConsExMessageEngineUseSignature] = ConsExMessageNoSignature
	}

	// map ==> []bytes
	messageByte, err := json.Marshal(message)

	// PONG messages are not encrypted (key exchanged has not taken place yet)
	if encrypted && (emt != ConsExPong) {
		var msgContentEncrypted, messageEncyptedByte []byte
		// encrypt the message
		chacha20Cipher := *sessionCipher
		chacha20AADBytes := []byte(engineAuthCodeHashSha512)
		msgContentEncrypted = chacha20Cipher.Seal(nil, nonce, messageByte, chacha20AADBytes)
		messageEncrypted := make(map[string]string)
		msgContentEncryptedHex := hex.EncodeToString(msgContentEncrypted)
		messageEncrypted[ConsExMessageEncrypted] = msgContentEncryptedHex

		// map ==> []bytes
		messageEncyptedByte, err = json.Marshal(messageEncrypted)
		// []bytes ==> string
		message_string = string(messageEncyptedByte)

	} else {
		// []bytes ==> string
		message_string = string(messageByte)
	}
	return message_string, err
}

// function to process a message obtained from an external connector
func ExtMessageProcessor(rawMsg string) (map[string]interface{}, bool, error) {

	// message to return
	msg_processed := make(map[string]interface{})

	// parsing raw message
	err := json.Unmarshal([]byte(rawMsg), &msg_processed)
	// flag to return
	isMessageEncrypted := false

	if err == nil {
		//check if message is encrypted
		_, isPresentEncryptedField := msg_processed[ConsExMessageEncrypted]
		var isPresentSecretField bool
		msg_type := fmt.Sprintf("%v", msg_processed[ConsExMessageType])
		if strings.EqualFold(msg_type, ConsExPing.String()) {
			// for PING messages, this field is not necessary
			isPresentSecretField = true
		} else {
			_, isPresentSecretField = msg_processed[ConsExMessageSecret]
		}

		if isPresentEncryptedField {
			// message expected in this case: "Encrypted": "[message encrypted]". This function should be
			// called again to deserialize the rest of the contet
			englogging.DebugLog("Message is encrypted, only returning the raw message encrypted", nil)
			isMessageEncrypted = true
		} else {
			englogging.DebugLog("Message deserialized correctly", nil)
			_, isPresentIDField := msg_processed[ConsExMessageID]
			_, isPresentTypeField := msg_processed[ConsExMessageType]
			_, isPresentBodyField := msg_processed[ConsExMessageBody]

			correctMessageFormat := isPresentIDField && isPresentTypeField && isPresentBodyField &&
				isPresentSecretField

			if !correctMessageFormat {
				//raise a new error
				errorMsg := fmt.Sprintf(`Bad message format after correct deserialization. 
					Results: 'isPresentIDField'= %s, 'isPresentTypeField'= %s, 'isPresentBodyField'= %s,
					'isPresentSecretField'= %s`,
					strconv.FormatBool(isPresentIDField),
					strconv.FormatBool(isPresentTypeField),
					strconv.FormatBool(isPresentBodyField),
					strconv.FormatBool(isPresentSecretField))

				err = errors.New(errorMsg)
			}
		}
	}

	return msg_processed, isMessageEncrypted, err
}
