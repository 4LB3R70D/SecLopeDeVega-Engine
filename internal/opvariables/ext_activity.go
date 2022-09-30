/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - ext_activity.go
=================================================
Author: Alberto Dominguez

This package contains the operation variables used in the system.
This file contains logic about activities received from external connectors
*/

package opvariables

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sec-lope-de-vega/internal/englogging"
)

const (
	consActivityID              = "ACTIVITY_ID"
	consTime                    = "TIME"
	consConnectionID            = "CONNECTION_ID"
	consNewConnFlag             = "NEW_CONN_FLAG"
	consAsyncActivityFlag       = "ASYNC_ACTIVITY_FLAG"
	consTcpConnReadyFlag        = "TCP_CONN_READY_FLAG"
	consIP                      = "IP"
	consPort                    = "PORT"
	consExtInput                = "EXT_INPUT"
	consGreetingsRule           = "GREETINGS_RULE"
	consDefaultRule             = "DEFAULT_RULE"
	consEmptyRule               = "EMPTY_RULE"
	consExecutedSyncRules       = "EXECUTED_SYNC_RULES"
	consExecutedAsyncRules      = "EXECUTED_ASYNC_RULES"
	consCapturedData            = "CAPTURED_DATA"
	consDetectedAsyncRules      = "DETECTED_ASYNC_RULES"
	consEndConnection           = "END_CONNECTION"
	consListConnectionsTimedOut = "LIST_CONNECTIONS_TIMED_OUT"
	consConnBroken              = "CONN_BROKEN"
	consRuleID                  = "RULE_ID"
	consCaptures                = "CAPTURES"
	consProtocol                = "PROTOCOL"
	consEncoding                = "ENCODING"
	consMultiExtConnMem         = "MULTI_EXT_CONN_MEM"
	consGlobalMem               = "GLOBAL_MEM"
	consConnMem                 = "CONN_MEM"
	consHashConvRules           = "HASH_CONV_RULES"

	consBoolTrueString = "true"
	ConsDateTimeFormat = "2006-01-02 15:04:05"

	ConsIntType    = "int"
	ConsFloatType  = "float"
	ConsBoolType   = "bool"
	ConsStringType = "string"
)

type CapturedData struct {
	RuleID   int
	Captures map[string]string
}

type MemVariableReported struct {
	Name         string
	Type         string
	StringValue  string
	IntValue     int
	FloatValue   float64
	BooleanValue bool
}

type ExtActivity struct {

	// External Connector Fields
	ExtConnMessageSender   string
	ExtConnBelongGroupFlag bool
	ExtConnGroup           string

	// External Connector Session Fields
	ExternalConnectorSession int // == Connection ID for the engine, but not for the external connector
	NewExtConnSession        bool
	ECSTimedOut              bool
	EndExtConnSession        bool

	// Digital signature fields
	PubKeyActivitySignature  string
	Hash                     string
	Signature                string
	SuccessActivitySignature bool

	// Activity Fields
	ID                          int
	Time                        string
	ConnectionID                int
	IP                          string
	Port                        int
	NewConnFlag                 bool
	AsyncFlag                   bool
	TcpConnFlag                 bool
	ExtInputB64                 string
	GreetingsRule               bool
	DefaultRule                 bool
	EmptyRule                   bool
	ExecutedConvRules           []int
	ExecutedAsyncRules          []int
	CapturedDataB64             []CapturedData
	MultiExtConnMemoryVariables []MemVariableReported
	GlobalMemoryVariables       []MemVariableReported
	ConnMemoryVariables         []MemVariableReported
	DetectedAsyncRules          []int
	EndConnection               bool
	ListConnectionsTimedOut     []int
	ConBrokenFlag               bool
	Protocol                    string
	Encoding                    string
	HashConvRules               string
	AlertAll                    bool
	AlertEmail                  bool
	AlertHttp                   bool
	AlertKafka                  bool
	AlertSyslog                 bool
	EndEngine                   bool

	// Raw activity received
	rawActivity string

	// INFORMATION FOR SAVING MEMORY VARIABLES INFORMATION IN THE DATABASE
	// Flag to indicate if the activity has to report memory variables
	ReportMemory bool
	// Declaration of memory variables information
	MultiMemVars, GlobalMemVars, ConnMemVars []MemVariable
}

// Method to fill the raw activity field for engine generated activities
func (activity *ExtActivity) FillRawActivityField(activitySignatureEnable bool, ecdsaPrivateKey *ecdsa.PrivateKey) {

	var signature string
	var pubKeyActivitySignature string
	var hash string
	var successSignature bool

	if bytesJson, err := json.Marshal(activity); err != nil {
		englogging.ErrorLog("Error creating the raw activity part of the new activity in a json format", err)
		if activitySignatureEnable {
			if successSignature, pubKeyActivitySignature, signature, hash = signExtActivity(
				bytesJson, ecdsaPrivateKey); successSignature {
				activity.Hash = hash
				activity.PubKeyActivitySignature = pubKeyActivitySignature
				activity.Signature = signature
			}
		}
	} else {
		activity.rawActivity = string(bytesJson)
	}

}

// Method to get the contend of a raw activity
func (activity *ExtActivity) GetActivityContent() string {

	var activityContent string
	if len(activity.rawActivity) > 0 {
		activityContent = activity.rawActivity
	}
	return activityContent
}

// --------------------------------------------------------------------------------------------------------------------
// PARSING FUNCTIONS
// --------------------------------------------------------------------------------------------------------------------

// Function to sign criptographically an external activity
func signExtActivity(jsonRawActivityBytes []byte, ecdsaPrivateKey *ecdsa.PrivateKey) (bool, string, string, string) {

	var signature string
	var pubKeyActivitySignature string
	var hash string
	var successSignature bool

	activityHashBytes := sha256.Sum256(jsonRawActivityBytes)
	activitySignatureBytes, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivateKey, activityHashBytes[:])
	if err != nil {
		englogging.ErrorLog("Error geting the digital signature of the external activity", err)
	} else {
		signature = hex.EncodeToString(activitySignatureBytes)
		hash = hex.EncodeToString(activityHashBytes[:])
		// https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
		x509EncodedPub, err := x509.MarshalPKIXPublicKey(&ecdsaPrivateKey.PublicKey)
		if err != nil {
			englogging.ErrorLog("Error marshaling the public key in the x509 format for activity signature", err)
		} else {
			pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
			pubKeyActivitySignature = string(pemEncodedPub)
			successSignature = true
			englogging.DebugLog("External activity signed, obtained signature: "+pubKeyActivitySignature, nil)
			/*
				// how to verify the signature
				blockPub, _ := pem.Decode([]byte(pemEncodedPub))
				x509EncodedPubTest := blockPub.Bytes
				genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPubTest)
				publicKey := genericPublicKey.(*ecdsa.PublicKey)
				activityHashTestBytes, _ := hex.DecodeString(activityHash)
				activitySignatureTestBytes, _ := hex.DecodeString(activitySignature)
				valid := ecdsa.VerifyASN1(publicKey, activityHashTestBytes, activitySignatureTestBytes)
				if valid {
					fmt.Printf("valid signature!")
				}*/
		}
	}
	return successSignature, pubKeyActivitySignature, signature, hash
}

// Function to parse the int fields of a raw activity
func parseIntFieldOfActivity(rawActivity map[string]interface{}, fieldName string) (bool, int) {
	success := false
	intValue := 0
	var float64Value float64

	if content, ok := rawActivity[fieldName]; ok {
		if float64Value, ok = content.(float64); ok {
			intValue = int(float64Value)
			success = true
		}
	}
	return success, intValue
}

// Function to parse the string fields of a raw activity
func parseStringFieldOfActivity(rawActivity map[string]interface{}, fieldName string) (bool, string) {
	success := false
	stringValue := ""

	if content, ok := rawActivity[fieldName]; ok {
		if stringValue, ok = content.(string); ok {
			success = true
		}
	}
	return success, stringValue
}

// Function to parse the bool fields of a raw activity
func parseBoolFieldOfActivity(rawActivity map[string]interface{}, fieldName string) (bool, bool) {
	success := false
	var stringBoolValue string
	var boolValue bool

	if content, ok := rawActivity[fieldName]; ok {
		if stringBoolValue, ok = content.(string); ok {
			success = true
			boolValue = stringBoolValue == consBoolTrueString
		}
	}
	return success, boolValue
}

// Function to parse an array of ints of a raw activity
func parseIntArrayOfActivity(rawActivity map[string]interface{}, fieldName string) (bool, []int) {
	success := false
	var intSlice []int

	if content, ok := rawActivity[fieldName]; ok {
		if interfaceSlice, ok := content.([]interface{}); ok {

			intSlice = make([]int, len(interfaceSlice))
			success = true

			for _, element := range interfaceSlice {
				if float64Value, ok := element.(float64); ok {
					intValue := int(float64Value)
					intSlice = append(intSlice, intValue)
					success = success && true
				}
			}
		}
	}
	return success, intSlice
}

// Function to parse the captured data information, returning an struct
func parseCaptureInfoOfActivity(rawActivity map[string]interface{}, fieldName string) (bool, []CapturedData) {
	success := false
	var rawCaptureDataList []interface{}
	var capturedData []CapturedData

	if content, ok := rawActivity[fieldName]; ok {
		if rawCaptureDataList, ok = content.([]interface{}); ok {
			for _, rawCaptData := range rawCaptureDataList {
				var captData CapturedData
				if rawCaptDataProc := rawCaptData.(map[string]interface{}); ok {
					if idFloat, ok := rawCaptDataProc[consRuleID].(float64); ok {
						captData.RuleID = int(idFloat)
						success = true
					}
					if capturesRaw, ok := rawCaptDataProc[consCaptures].(map[string]interface{}); ok {
						captData.Captures = make(map[string]string)
						for memVarName, capture := range capturesRaw {
							strMemVarName := fmt.Sprintf("%v", memVarName)
							strCapture := fmt.Sprintf("%v", capture)
							captData.Captures[strMemVarName] = strCapture
						}
						success = success && true
					}
					if success {
						capturedData = append(capturedData, captData)
					}
				}
			}
		}
	}
	return success, capturedData
}

// function to find and get the type of a memory variable of the conversation rules
func findMemoryVariableInConversationRules(convRules *ConversationRules, variableName string,
	memType string) (bool, string) {
	found := false
	var variableType string

	if memType == consMultiExtConnMem {
		// check multi external connector memory variables
		for _, memVar := range convRules.MemoryVariables.MultiExtConnLevel {
			if memVar.Name == variableName {
				variableType = memVar.Type
				found = true
				break
			}
		}
	} else if memType == consGlobalMem {
		// check global memory variables
		for _, memVar := range convRules.MemoryVariables.GlobalLevel {
			if memVar.Name == variableName {
				variableType = memVar.Type
				found = true
				break
			}
		}
	} else {
		// check connection memory variables
		for _, memVar := range convRules.MemoryVariables.ConnectionLevel {
			if memVar.Name == variableName {
				variableType = memVar.Type
				found = true
				break
			}
		}
	}
	return found, variableType
}

// Function to parse the reported memory variables
func parseMemVariablesOfActivity(rawActivity map[string]interface{}, fieldName string,
	convRules *ConversationRules, memType string) (bool, []MemVariableReported) {
	success := true
	var rawMemVariables map[string]interface{}
	var memVariables []MemVariableReported

	if content, ok := rawActivity[fieldName]; ok {
		if rawMemVariables, ok = content.(map[string]interface{}); ok {

			// itereate the list of memory variables reported (connection or global ones)
			for variableName, value := range rawMemVariables {
				var currentMemVariable MemVariableReported
				currentMemVariable.Name = variableName
				success_iteration := false
				found, variableType := findMemoryVariableInConversationRules(convRules, variableName, memType)

				if found {

					if convRules.ExtOperation.EncodeB64MemoryReported {
						currentMemVariable.Type = ConsStringType
					} else {
						currentMemVariable.Type = strings.ToLower(variableType)
					}

					if currentMemVariable.Type == ConsIntType {
						// float type
						if castedValueInt, ok := value.(int); ok {
							currentMemVariable.IntValue = castedValueInt
							success_iteration = true
						} else if float2IntValue, ok := value.(float64); ok {
							currentMemVariable.IntValue = int(float2IntValue)
							success_iteration = true
						} else if string2IntValue, ok := value.(string); ok {
							if parsedValueInt, err := strconv.Atoi(string2IntValue); err == nil {
								currentMemVariable.IntValue = parsedValueInt
								success_iteration = true
							}
						}

					} else if currentMemVariable.Type == ConsFloatType {
						// float type
						if castedValueFloat, ok := value.(float64); ok {
							currentMemVariable.FloatValue = castedValueFloat
							success_iteration = true
						} else if int2FloatValue, ok := value.(int); ok {
							currentMemVariable.FloatValue = float64(int2FloatValue)
							success_iteration = true
						} else if string2FloatValue, ok := value.(string); ok {
							if parsedValueFloat, err := strconv.ParseFloat(string2FloatValue, 64); err == nil {
								currentMemVariable.FloatValue = parsedValueFloat
								success_iteration = true
							}
						}

					} else if currentMemVariable.Type == ConsBoolType {
						// bool type
						if castedValueBool, ok := value.(bool); ok {
							currentMemVariable.BooleanValue = castedValueBool
							success_iteration = true
						} else if parsedValueBool, err := strconv.ParseBool(value.(string)); err == nil {
							currentMemVariable.BooleanValue = parsedValueBool
							success_iteration = true
						}

					} else {
						// string type
						if castedStringValue, ok := value.(string); ok {
							currentMemVariable.StringValue = castedStringValue
							success_iteration = true
						}
					}
				}
				success = success && success_iteration
				if success_iteration {
					memVariables = append(memVariables, currentMemVariable)
				} else {
					englogging.WarnLog("Memory variable '"+variableName+"' not possible to parse", nil)
				}
			}
		}
	}
	return success, memVariables
}

// Function to add the reported memory
func addReportedMemory(procActivity ExtActivity, convRules *ConversationRules,
	errorGettingConvRulesForGroup error, rawActivity map[string]interface{}) ExtActivity {

	var memVariables []MemVariableReported
	var success bool
	var stringValue string

	if convRules.ExtOperation.ReportMemory && errorGettingConvRulesForGroup == nil {
		procActivity.ReportMemory = convRules.ExtOperation.ReportMemory

		// Multi External Connector Memory
		if convRules.ExtOperation.MemVarMultiExtConnEnable {
			procActivity.MultiMemVars = convRules.MemoryVariables.MultiExtConnLevel
			success, memVariables = parseMemVariablesOfActivity(rawActivity, consMultiExtConnMem,
				convRules, consMultiExtConnMem)
			if success {
				procActivity.MultiExtConnMemoryVariables = memVariables
			} else {
				englogging.DebugLog("Not possible to parse the field 'Multi External Connector Memory' of the activity", nil)
			}
		}

		// Global Memory
		procActivity.GlobalMemVars = convRules.MemoryVariables.GlobalLevel
		success, memVariables = parseMemVariablesOfActivity(rawActivity, consGlobalMem, convRules, consGlobalMem)
		if success {
			procActivity.GlobalMemoryVariables = memVariables
		} else {
			englogging.DebugLog("Not possible to parse the field 'Global Memory' of the activity", nil)
		}

		// Conn Memory
		procActivity.ConnMemVars = convRules.MemoryVariables.ConnectionLevel
		success, memVariables = parseMemVariablesOfActivity(rawActivity, consConnMem, convRules, consConnMem)
		if success {
			procActivity.ConnMemoryVariables = memVariables
		} else {
			englogging.DebugLog("Not possible to parse the field 'Conn Memory' of the activity", nil)
		}

		// Hash conversation rules
		success, stringValue = parseStringFieldOfActivity(rawActivity, consHashConvRules)
		if success {
			procActivity.HashConvRules = stringValue
		} else {
			englogging.DebugLog("Not possible to parse the field 'hash of conversation rules' of the activity", nil)
		}
	}
	return procActivity
}

// Function to check a specific rule for alertin
func checkSpecificRuleForAlerting(executedRuleID int, rule Rule) (bool, bool, bool, bool, bool, bool) {

	var alertAll, alertEmail, alertHttp, alertKafka, alertSyslog, found bool
	if executedRuleID == rule.Id {
		alertAll = alertAll || rule.Alert.All
		alertEmail = alertEmail || rule.Alert.Email
		alertHttp = alertHttp || rule.Alert.Http
		alertKafka = alertKafka || rule.Alert.Kafka
		alertSyslog = alertSyslog || rule.Alert.Syslog
		found = true
	}
	return found, alertAll, alertEmail, alertHttp, alertKafka, alertSyslog

}

// Function to check if a list of executed conversation rules should be marked to be reported or not
func checkRulesForAlerting(executedConvRules []int, convRules *ConversationRules) (bool, bool, bool, bool, bool) {

	var alertAll, alertEmail, alertHttp, alertKafka, alertSyslog bool
	for _, executedRuleID := range executedConvRules {
		found := false

		// find the rule declaration
		for _, rule := range convRules.Conversation.CustomRules.Rules {
			found, alertAll, alertEmail, alertHttp, alertKafka, alertSyslog = checkSpecificRuleForAlerting(
				executedRuleID, rule)
			if found {
				break
			}
		}

		if !found {
			for _, group := range convRules.Conversation.CustomRules.Groups {
				for _, rule := range group.Rules {
					found, alertAll, alertEmail, alertHttp, alertKafka, alertSyslog = checkSpecificRuleForAlerting(
						executedRuleID, rule)
					if found {
						break
					}
				}
			}
		}
	}
	return alertAll, alertEmail, alertHttp, alertKafka, alertSyslog
}

// Function to review if the activity should be marked to use for alerts, or not
func reviewForAlerting(greetingsRule, defaultRule, emptyRule, conBrokenFlag, endConnection bool,
	listConnectionsTimedOut []int, executedConvRules []int, executedAsyncRules []int,
	convRules *ConversationRules) (bool, bool, bool, bool, bool) {

	var alertEmail, alertHttp, alertKafka, alertSyslog bool
	alertAll := convRules.ExtOperation.AlertAllFlag

	if !alertAll {
		alertAllSync, alertEmailSync, alertHttpSync, alertKafkaSync, alertSyslogSync := checkRulesForAlerting(
			executedConvRules, convRules)

		alertAllAsync, alertEmailAsync, alertHttpAsync, alertKafkaAsync, alertSyslogAsync := checkRulesForAlerting(
			executedAsyncRules, convRules)

		alertEmail = (greetingsRule && convRules.Conversation.Greetings.Alert.Email) ||
			(defaultRule && convRules.Conversation.Default.Alert.Email) ||
			(emptyRule && convRules.Conversation.Empty.Alert.Email) ||
			((conBrokenFlag || endConnection) && convRules.Conversation.Ending.Alert.Email) ||
			(len(listConnectionsTimedOut) > 0 && convRules.Conversation.Timeout.Alert.Email) ||
			alertEmailSync || alertEmailAsync

		alertHttp = (greetingsRule && convRules.Conversation.Greetings.Alert.Http) ||
			(defaultRule && convRules.Conversation.Default.Alert.Http) ||
			(emptyRule && convRules.Conversation.Empty.Alert.Http) ||
			((conBrokenFlag || endConnection) && convRules.Conversation.Ending.Alert.Http) ||
			(len(listConnectionsTimedOut) > 0 && convRules.Conversation.Timeout.Alert.Http) ||
			alertHttpSync || alertHttpAsync

		alertKafka = (greetingsRule && convRules.Conversation.Greetings.Alert.Kafka) ||
			(defaultRule && convRules.Conversation.Default.Alert.Kafka) ||
			(emptyRule && convRules.Conversation.Empty.Alert.Kafka) ||
			((conBrokenFlag || endConnection) && convRules.Conversation.Ending.Alert.Kafka) ||
			(len(listConnectionsTimedOut) > 0 && convRules.Conversation.Timeout.Alert.Kafka) ||
			alertKafkaSync || alertKafkaAsync

		alertSyslog = (greetingsRule && convRules.Conversation.Greetings.Alert.Syslog) ||
			(defaultRule && convRules.Conversation.Default.Alert.Syslog) ||
			(emptyRule && convRules.Conversation.Empty.Alert.Syslog) ||
			((conBrokenFlag || endConnection) && convRules.Conversation.Ending.Alert.Syslog) ||
			(len(listConnectionsTimedOut) > 0 && convRules.Conversation.Timeout.Alert.Syslog) ||
			alertSyslogSync || alertSyslogAsync

		alertAll = alertAll || alertAllSync || alertAllAsync

		// if all alerts are False, the alertAll will be enable. Default => alert via all channels
		// this happens when this level of detail is not provided
		if !alertAll && !alertEmail && !alertHttp && !alertKafka && !alertSyslog {
			alertAll = true
		}
	}
	return alertAll, alertEmail, alertHttp, alertKafka, alertSyslog
}

// --------------------------------------------------------------------------------------------------------------------
// 'BUILDER' FUNCTION
// --------------------------------------------------------------------------------------------------------------------

// Function to process a raw activity received from an external connector
// and convert it into an 'object'
func ProcessActivity(rawActivity map[string]interface{}, myExtConnMessageSender string,
	ecdsaPrivateKey *ecdsa.PrivateKey, activitySignatureEnable bool, myExternalConnectorSession int, group string,
	convRules *ConversationRules, errorGettingConvRulesForGroup error) ExtActivity {

	// initialise function internal variables
	var success bool
	var intValue int
	var stringValue string
	var boolValue bool
	var intArrayValue []int
	var capturedData []CapturedData
	var jsonRawActivity string
	var signature string
	var pubKeyActivitySignature string
	var hash string

	jsonRawActivityBytes, err := json.Marshal(rawActivity)
	successSignature := false

	if err != nil {
		englogging.ErrorLog("Not possible to parse the raw activity received from a external connector, "+
			"not possible to convert to json string", err)
	} else {
		// https://pkg.go.dev/crypto/ecdsa
		jsonRawActivity = string(jsonRawActivityBytes)
		if activitySignatureEnable {
			successSignature, pubKeyActivitySignature, signature, hash = signExtActivity(
				jsonRawActivityBytes, ecdsaPrivateKey)
		}
	}

	// create an new activity
	procActivity := ExtActivity{
		ExtConnMessageSender:     myExtConnMessageSender,
		ExternalConnectorSession: myExternalConnectorSession,
		rawActivity:              jsonRawActivity,
		Signature:                signature,
		Hash:                     hash,
		PubKeyActivitySignature:  pubKeyActivitySignature,
		SuccessActivitySignature: successSignature,
		ExtConnGroup:             group,
	}

	// Add the corresponding content (if present)
	// Activity ID
	success, intValue = parseIntFieldOfActivity(rawActivity, consActivityID)
	if success {
		procActivity.ID = intValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'ID' of the activity", nil)
	}
	// Time
	success, stringValue = parseStringFieldOfActivity(rawActivity, consTime)
	var errTime error
	var parsedTime time.Time
	if success {
		parsedTime, errTime = time.Parse(ConsDateTimeFormat, stringValue)
		if err == nil {
			procActivity.Time = parsedTime.Format(ConsDateTimeFormat)
		} else {
			success = false
		}
	}
	if !success {
		englogging.DebugLog("Not possible to parse the field 'Time' of the activity", errTime)
	}
	// Connection ID
	success, intValue = parseIntFieldOfActivity(rawActivity, consConnectionID)
	if success {
		procActivity.ConnectionID = intValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Connection ID' of the activity", nil)
	}
	// IP
	success, stringValue = parseStringFieldOfActivity(rawActivity, consIP)
	if success {
		procActivity.IP = stringValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'ip' of the activity", nil)
	}
	// Port
	success, intValue = parseIntFieldOfActivity(rawActivity, consPort)
	if success {
		procActivity.Port = intValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'port' of the activity", nil)
	}
	// New Connection Flag
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consNewConnFlag)
	if success {
		procActivity.NewConnFlag = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'New Conn Flag' of the activity", nil)
	}
	// Async Flag
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consAsyncActivityFlag)
	if success {
		procActivity.AsyncFlag = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Async Flag' of the activity", nil)
	}
	// Tcp Connection Ready Flag
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consTcpConnReadyFlag)
	if success {
		procActivity.TcpConnFlag = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Tcp Conn Ready flag' of the activity", nil)
	}
	// External Input encoded base 64
	success, stringValue = parseStringFieldOfActivity(rawActivity, consExtInput)
	if success {
		procActivity.ExtInputB64 = stringValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'External Input' of the activity", nil)
	}
	// Greetings Rule
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consGreetingsRule)
	if success {
		procActivity.GreetingsRule = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Greetings Rule Flag' of the activity", nil)
	}
	// Default Rule
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consDefaultRule)
	if success {
		procActivity.DefaultRule = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Default Rule Flag' of the activity", nil)
	}
	// Empty Rule
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consEmptyRule)
	if success {
		procActivity.EmptyRule = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Empty Rule Flag' of the activity", nil)
	}
	// Executed Synchronous Conversation Rules
	success, intArrayValue = parseIntArrayOfActivity(rawActivity, consExecutedSyncRules)
	if success {
		procActivity.ExecutedConvRules = intArrayValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'executed synchronous conversation rules' of the activity", nil)
	}
	// Executed Asynchronous Conversation Rules
	success, intArrayValue = parseIntArrayOfActivity(rawActivity, consExecutedAsyncRules)
	if success {
		procActivity.ExecutedAsyncRules = intArrayValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'executed asynchronous conversation rules' of the activity", nil)
	}
	// Captured Data
	success, capturedData = parseCaptureInfoOfActivity(rawActivity, consCapturedData)
	if success {
		procActivity.CapturedDataB64 = capturedData
	} else {
		englogging.DebugLog("Not possible to parse the field 'captured data' of the activity", nil)
	}
	// Detected Asynchronous Conversation Rules
	success, intArrayValue = parseIntArrayOfActivity(rawActivity, consDetectedAsyncRules)
	if success {
		procActivity.DetectedAsyncRules = intArrayValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'detected ashyncrhonous conversation rules' of the activity", nil)
	}
	// End Connection
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consEndConnection)
	if success {
		procActivity.EndConnection = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'End Connection Flag' of the activity", nil)
	}
	// List of Connections Timed Out
	success, intArrayValue = parseIntArrayOfActivity(rawActivity, consListConnectionsTimedOut)
	if success {
		procActivity.ListConnectionsTimedOut = intArrayValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'list of timed out connections' of the activity", nil)
	}
	// Broken Connection
	success, boolValue = parseBoolFieldOfActivity(rawActivity, consConnBroken)
	if success {
		procActivity.ConBrokenFlag = boolValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Broken Connection Flag' of the activity", nil)
	}
	// Protocol
	success, stringValue = parseStringFieldOfActivity(rawActivity, consProtocol)
	if success {
		procActivity.Protocol = stringValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'Protocol' of the activity", nil)
	}
	// Encoding
	success, stringValue = parseStringFieldOfActivity(rawActivity, consEncoding)
	if success {
		procActivity.Encoding = stringValue
	} else {
		englogging.DebugLog("Not possible to parse the field 'encoding' of the activity", nil)
	}

	procActivity = addReportedMemory(procActivity, convRules, errorGettingConvRulesForGroup, rawActivity)

	alertAll, alertEmail, alertHttp, alertKafka, alertSyslog := reviewForAlerting(procActivity.GreetingsRule,
		procActivity.DefaultRule, procActivity.EmptyRule, procActivity.ConBrokenFlag, procActivity.EndConnection,
		procActivity.ListConnectionsTimedOut, procActivity.ExecutedConvRules, procActivity.ExecutedAsyncRules, convRules)

	procActivity.AlertAll = alertAll
	procActivity.AlertEmail = alertEmail
	procActivity.AlertHttp = alertHttp
	procActivity.AlertKafka = alertKafka
	procActivity.AlertSyslog = alertSyslog

	if errorGettingConvRulesForGroup != nil {
		englogging.WarnLog("Error getting the conversation rules for the group of the external connector"+
			myExtConnMessageSender+"for saving the memory variables of the reported activity", err)
	}
	return procActivity
}
