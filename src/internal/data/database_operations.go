/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - database_operations.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the data service, which is the one that
interact with the persistance elements. This file has all the logic related with the database operations
*/
package data

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
)

const (
	consMaxGetCacheValueAttempts          = 3
	consWaitTimeBetweenCacheValueAttempts = 750 // ms
)

// ------------------------------------------------------------------
// External Connector Session
// ------------------------------------------------------------------
// Function to save a new external connector session in the database
func (daser *DataService) saveNewExternalConnectorSession(activity opvariables.ExtActivity, extConnPk int) {

	extConnSessionPk := 0
	currentTime := getTimeAndDate()
	result, err := daser.sqlDB.Exec("INSERT INTO external_connector_session (session_id, engine_execution_pk, "+
		"external_connector_pk, `group`, starting_time, last_time_connected) VALUES (?,?,?,?,?,?);",
		activity.ExternalConnectorSession, daser.engineExecutionPK, extConnPk, activity.ExtConnGroup,
		currentTime, currentTime)
	if err != nil {
		englogging.ErrorLog("Error inserting an external connector session in the database", err)
	} else {
		pk64, _ := result.LastInsertId()
		extConnSessionPk = int(pk64)
		daser.saveExternalConnectorSessionPKinCache(activity.ExternalConnectorSession, extConnSessionPk)
	}
}

// Function to save a new external connector (if it is not already in the database) and its corresponding session
func (daser *DataService) saveNewExternalConnectorAndSession(activity opvariables.ExtActivity) {

	var extConnPk int
	daser.sqlDB.QueryRow("SELECT external_connector_pk FROM external_connector WHERE id_name=?",
		activity.ExtConnMessageSender).Scan(&extConnPk)

	if extConnPk == 0 {
		result, err := daser.sqlDB.Exec("INSERT INTO external_connector (id_name) VALUES (?)",
			activity.ExtConnMessageSender)
		if err != nil {
			englogging.ErrorLog("Error inserting an external connector in the database", err)
		} else {
			pk64, _ := result.LastInsertId()
			extConnPk = int(pk64)
		}
	}
	if extConnPk != 0 {
		daser.saveExternalConnectorPKinCache(activity.ExtConnMessageSender, extConnPk)
		daser.saveNewExternalConnectorSession(activity, extConnPk)
		englogging.DebugLog("New external connector session saved in the database form the external connector:"+
			activity.ExtConnMessageSender, nil)
	} else {
		englogging.WarnLog("Not possible to save a new session in the database, "+
			"the related external connector pk is 0!", nil)
	}
}

// Function to end an external connection session
func (daser *DataService) saveEndingExternalConnectorSession(activity opvariables.ExtActivity) {

	time := getTimeAndDate()
	extConnectorSessionPK := daser.getExternalConnectorSessionPKinCache(activity.ExternalConnectorSession)
	daser.endConnectionsOfAnEndingExternalConnectorSession(activity, extConnectorSessionPK)

	_, err := daser.sqlDB.Exec("UPDATE external_connector_session SET last_time_connected=?,active=?,timed_out=? WHERE external_connector_session_pk=?",
		time, false, activity.ECSTimedOut, extConnectorSessionPK)
	if err != nil {
		englogging.ErrorLog("Error updating the 'last time connected' field of the table 'external connection session'", err)
	} else {
		englogging.DebugLog("'Last time connected' field of the table 'external connection session' updated successfully", nil)
	}
}

// Function to update the 'last_time_connected' field of the table 'external_connector_session'
func (daser *DataService) updateLastTimeConnectedForExternalConnectorSessions(activity opvariables.ExtActivity) {

	time := getTimeAndDate()
	extConnectorSessionPK := daser.getExternalConnectorSessionPKinCache(activity.ExternalConnectorSession)

	_, err := daser.sqlDB.Exec("UPDATE external_connector_session SET last_time_connected=? WHERE external_connector_session_pk=?",
		time, extConnectorSessionPK)
	if err != nil {
		englogging.ErrorLog("Error updating the 'last time connected' field of the table 'external connection session'", err)
	} else {
		englogging.DebugLog("'Last time connected' field of the table 'external connection session' updated successfully", nil)
	}
}

// ------------------------------------------------------------------
// External Connection
// ------------------------------------------------------------------

// Function to get the external connections that do not have an 'ending time'
func (daser *DataService) getExtConnectionsWithoutEndingDate(extConnectorSessionPK int,
	activity opvariables.ExtActivity) []int {

	var err error
	var err2 error
	var extConnPkList []int
	sqlRows, err1 := daser.sqlDB.Query("SELECT external_connector_session_pk FROM external_connection "+
		"WHERE external_connector_session_pk=? AND ending_time IS NULL", extConnectorSessionPK)

	if err1 == nil {
		defer sqlRows.Close()
		for sqlRows.Next() {
			var externalConnectorSessionPk int
			err2 = sqlRows.Scan(&externalConnectorSessionPk)

			if externalConnectorSessionPk != 0 {
				connID := daser.getConnIDFromExternalConnectorSessionPk(externalConnectorSessionPk)
				extConnPkList = append(extConnPkList, connID)
			} else {
				err2 = errors.New("connection ID is 0")
			}
		}

	}
	if err1 != nil || err2 != nil {
		if err1 != nil {
			err = err1
		} else if err2 != nil {
			err = err2
		}
		englogging.ErrorLog("Error getting the external connections from the ending external connector: '"+
			activity.ExtConnMessageSender+"'", err)
	}
	return extConnPkList
}

// Function to mark a external connection as ended (timed out, broken or normal close)
func (daser *DataService) saveEndConnInfo(activity opvariables.ExtActivity, connID int, timeOut, broken, incomplete bool) {

	newCacheExtConnSessionConnectionMapKey := cacheExtConnSessionConnectionMapKey{
		ExternalConnectorSessionID: activity.ExternalConnectorSession,
		ConnectionID:               connID,
	}
	time := getTimeAndDate()
	if extConnectionPK, ok := daser.getExternalConnectionPKinCache(newCacheExtConnSessionConnectionMapKey); ok {
		_, err := daser.sqlDB.Exec("UPDATE external_connection SET ending_time=?,timed_out=?,broken=?,incomplete=? WHERE external_connection_pk=?",
			time, timeOut, broken, incomplete, extConnectionPK)

		if err != nil {
			englogging.ErrorLog("Not possible to mark the connection: '"+strconv.Itoa(connID)+"' as ended", err)
		} else {
			englogging.DebugLog("Connection: '"+strconv.Itoa(connID)+"' marked as ended in the database", nil)
		}
	} else {
		englogging.WarnLog("The PK of the external connection: '"+strconv.Itoa(connID)+"' of the external connection session: '"+
			strconv.Itoa(activity.ExternalConnectorSession)+"' not saved previously for marking the connection as ended", nil)
	}
}

// Function to end the connections of an ending external connection session
func (daser *DataService) endConnectionsOfAnEndingExternalConnectorSession(activity opvariables.ExtActivity,
	extConnectorSessionPK int) {

	extConnPkList := daser.getExtConnectionsWithoutEndingDate(extConnectorSessionPK, activity)
	for _, connID := range extConnPkList {
		daser.saveEndConnInfo(activity, connID, false, false, true)
	}
}

// Function to mark a list of connections as timed out connections (and end them)
func (daser *DataService) saveListConnTimedOut(activity opvariables.ExtActivity, extActivityPK int) {

	if activity.ListConnectionsTimedOut != nil {
		for _, connID := range activity.ListConnectionsTimedOut {
			daser.saveEndConnInfo(activity, connID, true, false, false)
		}
	}
}

// Function to save a new external connection
func (daser *DataService) saveNewExternalConnection(activity opvariables.ExtActivity) {

	result, err := daser.sqlDB.Exec("INSERT INTO external_connection (external_connector_session_pk,"+
		"external_connection_id,starting_time,ip,port,protocol,encoding,hash_conv_rules_used) VALUES (?,?,?,?,?,?,?,?);",
		daser.getExternalConnectorSessionPKinCache(activity.ExternalConnectorSession), activity.ExternalConnectorSession,
		activity.Time, activity.IP, activity.Port, activity.Protocol, activity.Encoding, activity.HashConvRules)
	if err != nil {
		englogging.ErrorLog("Error inserting a new external connection", err)
	} else {
		pk64, _ := result.LastInsertId()
		extConnectionPK := int(pk64)
		newCacheExtConnSessionConnectionMapKey := cacheExtConnSessionConnectionMapKey{
			ExternalConnectorSessionID: activity.ExternalConnectorSession,
			ConnectionID:               activity.ConnectionID,
		}
		daser.saveExternalConnectionPKinCache(newCacheExtConnSessionConnectionMapKey, extConnectionPK)

		// Add the information about the memory variables (if it is not already done)
		daser.addNewMemoryVars(activity, utils.ConsMultiExternalConnectorMemoryVariable)
		daser.addNewMemoryVars(activity, utils.ConsGlobalMemoryVariable)
		daser.addNewMemoryVars(activity, utils.ConsConnectionMemoryVariable)

		englogging.DebugLog("Added a new external connection in the database. Connection ID: "+
			strconv.Itoa(activity.ConnectionID), nil)
	}
}

// ------------------------------------------------------------------
// Memory
// ------------------------------------------------------------------
// Auxiliary function to prepare the query for inserting memory variables
func (daser *DataService) prepareQueryDataForMemVarInsertion(activity opvariables.ExtActivity,
	memoryVariableType utils.MemVarType) (string, string, int, []opvariables.MemVariable) {

	var tableName string
	var foreignKeyName string
	var fk int
	var listOfMemVars []opvariables.MemVariable

	if memoryVariableType == utils.ConsMultiExternalConnectorMemoryVariable {
		tableName = "multi_ext_connector_memory_variable"
		foreignKeyName = "engine_execution_pk"
		fk = daser.engineExecutionPK
		listOfMemVars = activity.MultiMemVars

	} else if memoryVariableType == utils.ConsGlobalMemoryVariable {
		tableName = "global_memory_variable"
		foreignKeyName = "external_connector_session_pk"
		fk = daser.getExternalConnectorSessionPKinCache(activity.ExternalConnectorSession)
		listOfMemVars = activity.GlobalMemVars

	} else {
		tableName = "connection_memory_variable"
		foreignKeyName = "external_connection_pk"
		newCacheExtConnSessionConnectionMapKey := cacheExtConnSessionConnectionMapKey{
			ExternalConnectorSessionID: activity.ExternalConnectorSession,
			ConnectionID:               activity.ConnectionID,
		}
		fk, _ = daser.getExternalConnectionPKinCache(newCacheExtConnSessionConnectionMapKey)
		listOfMemVars = activity.ConnMemVars
	}

	return tableName, foreignKeyName, fk, listOfMemVars
}

// Function to check if a memory variable is the cache of the service, therefore, it has been saved previously
func (daser *DataService) checkIfMemVarHasBeenSavedPreviously(memVarName string, connID int) bool {

	cacheConnMemVarMapKey := cacheConnMemVarMapKey{
		ConnectionID: connID,
		VarName:      memVarName,
	}
	_, multiMemVarAlreadySavedPreviously := daser.getMemoryVariablePKinCache(memVarName,
		cacheConnMemVarMapKey, utils.ConsMultiExternalConnectorMemoryVariable)
	_, globalMemVarAlreadySavedPreviously := daser.getMemoryVariablePKinCache(memVarName,
		cacheConnMemVarMapKey, utils.ConsGlobalMemoryVariable)
	_, connMemVarAlreadySavedPreviously := daser.getMemoryVariablePKinCache(memVarName,
		cacheConnMemVarMapKey, utils.ConsConnectionMemoryVariable)

	memVarNotSavedPreviously := multiMemVarAlreadySavedPreviously || globalMemVarAlreadySavedPreviously ||
		connMemVarAlreadySavedPreviously

	return memVarNotSavedPreviously
}

// Function to save the declaration of memory variables for multi external connector, global or connection level ones
func (daser *DataService) addNewMemoryVars(activity opvariables.ExtActivity, memoryVariableType utils.MemVarType) {

	tableName, foreignKeyName, fk, listOfMemVars := daser.prepareQueryDataForMemVarInsertion(activity, memoryVariableType)

	for _, memVar := range listOfMemVars {
		memVarNotSavedPreviously := daser.checkIfMemVarHasBeenSavedPreviously(memVar.Name, activity.ConnectionID)

		if !memVarNotSavedPreviously {
			result, err := daser.sqlDB.Exec("INSERT INTO "+tableName+" ("+foreignKeyName+", name) VALUES (?,?);",
				fk, memVar.Name)

			if err != nil {
				englogging.ErrorLog("Error inserting the memory variable: '"+memVar.Name+"', in the table: '"+
					tableName+"'", err)

			} else {
				pk64, _ := result.LastInsertId()
				memVarPk := int(pk64)
				newCacheConnMemVarMapKey := cacheConnMemVarMapKey{
					ConnectionID: activity.ConnectionID,
					VarName:      memVar.Name,
				}

				// save the corresponding PK
				if memoryVariableType == utils.ConsMultiExternalConnectorMemoryVariable {
					daser.saveMemoryVariablePKinCache(memVar.Name, newCacheConnMemVarMapKey, memVarPk, utils.ConsMultiExternalConnectorMemoryVariable)
				} else if memoryVariableType == utils.ConsGlobalMemoryVariable {
					daser.saveMemoryVariablePKinCache(memVar.Name, newCacheConnMemVarMapKey, memVarPk, utils.ConsGlobalMemoryVariable)
				} else {
					daser.saveMemoryVariablePKinCache(memVar.Name, newCacheConnMemVarMapKey, memVarPk, utils.ConsConnectionMemoryVariable)
				}
				logText := fmt.Sprintf("Added a new memory variable in the DB: '%v' in the table: '%v' with the ID:'%d'",
					memVar.Name, tableName, memVarPk)
				englogging.DebugLog(logText, nil)
			}
		}
	}
}

// Function to convert any memory variable value into string
func (daser *DataService) convertMemVarValueIntoString(memVar opvariables.MemVariableReported) string {

	var memVarValue string
	if memVar.Type == opvariables.ConsBoolType {
		// bool type
		memVarValue = strconv.FormatBool(memVar.BooleanValue)
	} else if memVar.Type == opvariables.ConsIntType {
		//int type
		memVarValue = strconv.Itoa(memVar.IntValue)
	} else if memVar.Type == opvariables.ConsFloatType {
		// float type
		memVarValue = fmt.Sprintf("%g", memVar.FloatValue)
	} else {
		//string type
		memVarValue = memVar.StringValue
	}
	return memVarValue
}

// Function to save the snapshots of memory variables
func (daser *DataService) saveMemVarSnapshots(tableName, memVarValue, fkName, memVarName string, extActivityPK, pkMemVar int) {

	result, err := daser.sqlDB.Exec("INSERT INTO "+tableName+" (external_activity_pk,"+fkName+",value) VALUES (?,?,?);",
		extActivityPK, pkMemVar, memVarValue)

	if err != nil {
		englogging.ErrorLog("Error inserting the memory variable snapshot: '"+memVarName+"', in the table: '"+
			tableName+"'", err)
	} else {
		pk64, _ := result.LastInsertId()
		memVarSnapPk := int(pk64)
		logText := fmt.Sprintf("Added a new memory variable snapshot in the DB: '%v' in the table: '%v' with the ID:'%d'",
			memVarName, tableName, memVarSnapPk)
		englogging.DebugLog(logText, nil)
	}
}

// Function to manage if a memory variable value should be saved or not
func (daser *DataService) saveOrNotMemVarValue(ok bool, memVar opvariables.MemVariableReported, tableName,
	fkNameMemVar string, extActivityPK, pkMemVar int) {

	if ok {
		memVarValue := daser.convertMemVarValueIntoString(memVar)
		daser.saveMemVarSnapshots(tableName, memVarValue, fkNameMemVar, memVar.Name, extActivityPK, pkMemVar)
	} else {
		msgLog := fmt.Sprintf("Memory variable PK for the memory variable: '%s' "+
			"is not available, its value will not be saved", memVar.Name)
		englogging.WarnLog(msgLog, nil)
	}
}

// Function to save information about multi external connector variables
func (daser *DataService) saveMultiMemVarSnapshots(activity opvariables.ExtActivity, extActivityPK int) {

	tableName := "multi_ext_conn_memory_snapshot"
	fkNameMemVar := "multi_ext_connector_memory_variable_pk"
	var ok bool
	var pkMemVar int
	attempts := 0

	for _, memVar := range activity.MultiExtConnMemoryVariables {
		for !ok && attempts < consMaxGetCacheValueAttempts {
			pkMemVar, ok = daser.getMemoryVariablePKinCache(memVar.Name, cacheConnMemVarMapKey{},
				utils.ConsMultiExternalConnectorMemoryVariable)

			if !ok {
				msgLog := fmt.Sprintf("Memory variable PK for the multi external connector memory variable: '%s' "+
					" is not available, waiting before trying to get it again...", memVar.Name)
				englogging.DebugLog(msgLog, nil)

				time.Sleep(consWaitTimeBetweenCacheValueAttempts * time.Millisecond)
				attempts++
			}
			daser.saveOrNotMemVarValue(ok, memVar, tableName, fkNameMemVar, extActivityPK, pkMemVar)
		}

	}
}

// Function to save information about global variables
func (daser *DataService) saveGlobalMemVarSnapshots(activity opvariables.ExtActivity, extActivityPK int) {

	tableName := "global_memory_snapshot"
	fkNameMemVar := "global_memory_variable_pk"
	var ok bool
	var pkMemVar int
	attempts := 0

	for _, memVar := range activity.GlobalMemoryVariables {
		for !ok && attempts < consMaxGetCacheValueAttempts {
			pkMemVar, ok = daser.getMemoryVariablePKinCache(memVar.Name, cacheConnMemVarMapKey{},
				utils.ConsGlobalMemoryVariable)

			if !ok {
				msgLog := fmt.Sprintf("Memory variable PK for the global memory variable: '%s' "+
					"is not available, waiting before trying to get it again...", memVar.Name)
				englogging.DebugLog(msgLog, nil)

				time.Sleep(consWaitTimeBetweenCacheValueAttempts * time.Millisecond)
				attempts++
			}
		}
		daser.saveOrNotMemVarValue(ok, memVar, tableName, fkNameMemVar, extActivityPK, pkMemVar)
	}
}

// Function to save information about connection variables
func (daser *DataService) saveConnMemVarSnapshots(activity opvariables.ExtActivity, extActivityPK int) {

	tableName := "connection_memory_snapshot"
	fkNameMemVar := "connection_memory_variable_pk"
	var ok bool
	var pkMemVar int
	attempts := 0

	for _, memVar := range activity.ConnMemoryVariables {

		newCacheConnMemVarMapKey := cacheConnMemVarMapKey{
			ConnectionID: activity.ConnectionID,
			VarName:      memVar.Name,
		}

		for !ok && attempts < consMaxGetCacheValueAttempts {

			pkMemVar, ok = daser.getMemoryVariablePKinCache(memVar.Name, newCacheConnMemVarMapKey,
				utils.ConsConnectionMemoryVariable)

			if !ok {
				msgLog := fmt.Sprintf("Memory variable PK for the connection memory variable: '%s' "+
					"is not available, waiting before trying to get it again...", memVar.Name)
				englogging.DebugLog(msgLog, nil)

				time.Sleep(consWaitTimeBetweenCacheValueAttempts * time.Millisecond)
				attempts++
			}
		}
		daser.saveOrNotMemVarValue(ok, memVar, tableName, fkNameMemVar, extActivityPK, pkMemVar)
	}
}

// ------------------------------------------------------------------
// Custom Rules & Capturing Data
// ------------------------------------------------------------------

// function to manage the result of the operation of inserting a custom rule
func (daser *DataService) manageRuleDbInsertionResults(ruleID int, result sql.Result, err error, activityID int) {

	ruleIDStringFormat := strconv.Itoa(ruleID)
	activityIDStringFormat := strconv.Itoa(activityID)
	if err != nil {
		englogging.ErrorLog("Error inserting the rule: '"+ruleIDStringFormat+"' in the database for the activity: '"+
			activityIDStringFormat+"'", err)
	} else {
		pk64, _ := result.LastInsertId()
		ruleActivityPK := int(pk64)
		newRuleActivityMapKey := cacheRuleActivityMapKey{
			ActivityID: activityID,
			RuleID:     ruleID,
		}
		daser.saveRuleActivityPKinCache(newRuleActivityMapKey, ruleActivityPK)
		englogging.DebugLog("Added the rule: '"+ruleIDStringFormat+"' in the database for the activity: '"+
			activityIDStringFormat+"'", nil)
	}
}

// Auxiliary function to insert a set of captured data
func (daser *DataService) insertCapturedData(customRulePK, memVarPk int, data, memVarName, tableName, memVarPkName string) {

	_, err := daser.sqlDB.Exec("INSERT INTO "+tableName+" (custom_rule_pk, "+memVarPkName+", captured_value)"+
		" VALUES (?,?,?);", customRulePK, memVarPk, data)
	if err != nil {
		englogging.ErrorLog("Error insterting the captured data for the memory variable: '"+memVarName+"'", err)
	} else {
		englogging.DebugLog("The captured information saved in the ('"+memVarName+"') saved data was correctly saved in the database", nil)
	}
}

// Function to save captured data information
func (daser *DataService) saveCapturedData(activityID, connectionID int, capturedDataList []opvariables.CapturedData) {

	for _, captData := range capturedDataList {
		ruleActivityMapKey := cacheRuleActivityMapKey{
			ActivityID: activityID,
			RuleID:     captData.RuleID,
		}

		if customRulePK, ok := daser.getRuleActivityPKinCache(ruleActivityMapKey); ok {
			for memVarName, data := range captData.Captures {

				connMemVarMapKey := cacheConnMemVarMapKey{
					ConnectionID: connectionID,
					VarName:      memVarName,
				}

				attempts := 0
				var memoryFound bool

				for !memoryFound && attempts < consMaxGetCacheValueAttempts {

					if multiMemVarPk, ok := daser.getMemoryVariablePKinCache(memVarName, connMemVarMapKey,
						utils.ConsMultiExternalConnectorMemoryVariable); ok {
						tableName := "multi_ext_connector_captured_data"
						memVarPkName := "multi_ext_connector_memory_variable_pk"
						daser.insertCapturedData(customRulePK, multiMemVarPk, data, memVarName, tableName, memVarPkName)
						memoryFound = true

					} else if globalMemVarPk, ok := daser.getMemoryVariablePKinCache(memVarName, connMemVarMapKey,
						utils.ConsGlobalMemoryVariable); ok {
						tableName := "global_captured_data"
						memVarPkName := "global_memory_variable_pk"
						daser.insertCapturedData(customRulePK, globalMemVarPk, data, memVarName, tableName, memVarPkName)
						memoryFound = true

					} else if connMemVarPk, ok := daser.getMemoryVariablePKinCache(memVarName, connMemVarMapKey,
						utils.ConsConnectionMemoryVariable); ok {
						tableName := "connection_captured_data"
						memVarPkName := "connection_memory_variable_pk"
						daser.insertCapturedData(customRulePK, connMemVarPk, data, memVarName, tableName, memVarPkName)
						memoryFound = true

					} else {
						englogging.DebugLog("Memory variable '"+memVarName+"', not saved previously in the DB at "+
							"the time of saving captured information, wait and try again...", nil)
						// wait a bit before trying again
						time.Sleep(consWaitTimeBetweenCacheValueAttempts * time.Millisecond)
						attempts++
					}
				}
				if !memoryFound {
					englogging.WarnLog("Memory variable '"+memVarName+"', not saved previously in the DB at "+
						"the time of saving captured information (This can be caused because this memory variable "+
						"is not marked as to be reported). Therefore, this information will not be saved in the database", nil)
				}
			}
		} else {
			englogging.WarnLog("Rule: '"+strconv.Itoa(captData.RuleID)+"' not found in the DB at the time of saving "+
				"capture information", nil)
		}
	}
}

// Function to save any information pertaining the conversation rules (execution or detection)
func (daser *DataService) saveRulesInformation(activity opvariables.ExtActivity, extActivityPK int) {

	if len(activity.ExecutedConvRules) > 0 {
		for _, ruleID := range activity.ExecutedConvRules {
			result, err := daser.sqlDB.Exec("INSERT INTO custom_rule (external_activity_pk, rule_number, executed)"+
				" VALUES (?,?,?);", extActivityPK, ruleID, true)
			daser.manageRuleDbInsertionResults(ruleID, result, err, activity.ID)
		}
	}
	if len(activity.ExecutedAsyncRules) > 0 {
		for _, ruleID := range activity.ExecutedAsyncRules {
			result, err := daser.sqlDB.Exec("INSERT INTO custom_rule (external_activity_pk, rule_number, executed, async)"+
				" VALUES (?,?,?,?);", extActivityPK, ruleID, true, true)
			daser.manageRuleDbInsertionResults(ruleID, result, err, activity.ID)
		}
	}
	if len(activity.DetectedAsyncRules) > 0 {
		for _, ruleID := range activity.DetectedAsyncRules {
			result, err := daser.sqlDB.Exec("INSERT INTO custom_rule (external_activity_pk, rule_number, async, detected)"+
				" VALUES (?,?,?,?);", extActivityPK, ruleID, true, true)
			daser.manageRuleDbInsertionResults(ruleID, result, err, activity.ID)
		}
	}
	if len(activity.CapturedDataB64) > 0 {
		daser.saveCapturedData(activity.ID, activity.ConnectionID, activity.CapturedDataB64)
	}
}

// ------------------------------------------------------------------
// Activity
// ------------------------------------------------------------------

// Function to save the information reported in a external activity
func (daser *DataService) saveNewActivity(activity opvariables.ExtActivity) {

	newCacheExtConnSessionConnectionMapKey := cacheExtConnSessionConnectionMapKey{
		ExternalConnectorSessionID: activity.ExternalConnectorSession,
		ConnectionID:               activity.ConnectionID,
	}
	var ok bool
	var externalConnectionPk int
	attempts := 0

	for !ok && attempts < consMaxGetCacheValueAttempts {

		externalConnectionPk, ok = daser.getExternalConnectionPKinCache(newCacheExtConnSessionConnectionMapKey)

		if !ok {
			msgLog := fmt.Sprintf("External Connection PK for the connection: '%s' of the external connector session: '%s'"+
				"is not available, waiting before trying to get it again...", strconv.Itoa(activity.ConnectionID),
				strconv.Itoa(activity.ExternalConnectorSession))
			englogging.DebugLog(msgLog, nil)

			time.Sleep(consWaitTimeBetweenCacheValueAttempts * time.Millisecond)
			attempts++
		}
	}
	if ok {
		result, err := daser.sqlDB.Exec("INSERT INTO external_activity  (id, external_connection_pk,`time`,external_input,"+
			"new_conn,tcp_conn_ready,greetings_rule,default_rule,empty_rule,raw_activity,hash,signature,pub_key_signature) "+
			"VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);", activity.ID, externalConnectionPk,
			activity.Time, activity.ExtInputB64, activity.NewConnFlag, activity.TcpConnFlag, activity.GreetingsRule,
			activity.DefaultRule, activity.EmptyRule, activity.GetActivityContent(), activity.Hash, activity.Signature,
			activity.PubKeyActivitySignature)

		if err != nil {
			englogging.ErrorLog("Error inserting a new activity", err)

		} else {
			pk64, _ := result.LastInsertId()
			extActivityPK := int(pk64)
			englogging.DebugLog("Added a new external activity in the database. Activity ID: "+
				strconv.Itoa(activity.ID)+", for the Connection: "+strconv.Itoa(activity.ConnectionID), nil)

			// memory reporting
			if activity.ReportMemory {
				if len(activity.MultiExtConnMemoryVariables) > 0 {
					daser.saveMultiMemVarSnapshots(activity, extActivityPK)
				}
				if len(activity.GlobalMemoryVariables) > 0 {
					daser.saveGlobalMemVarSnapshots(activity, extActivityPK)
				}
				if len(activity.ConnMemoryVariables) > 0 {
					daser.saveConnMemVarSnapshots(activity, extActivityPK)
				}
			}
			// rules reported
			daser.saveRulesInformation(activity, extActivityPK)

			// connections timed out reported
			if len(activity.ListConnectionsTimedOut) > 0 {
				daser.saveListConnTimedOut(activity, extActivityPK)
			}
			// ended connection (external connections, not external connectors)
			if activity.ConBrokenFlag {
				daser.saveEndConnInfo(activity, activity.ConnectionID, false, true, false)

			} else if activity.EndConnection {
				daser.saveEndConnInfo(activity, activity.ConnectionID, false, false, false)
			}
		}
	} else {
		msgLog := fmt.Sprintf("External Connection PK for the connection: '%s' of the external connector session: "+
			"'%s' is not available. Activity: '%s' not saved in the database",
			strconv.Itoa(activity.ConnectionID), strconv.Itoa(activity.ExternalConnectorSession), strconv.Itoa(activity.ID))
		englogging.WarnLog(msgLog, nil)
	}
}

// Function to organize how activities should be saved in the database
func (daser *DataService) saveActivityInDatabase(activity opvariables.ExtActivity) {
	// https://stackoverflow.com/questions/58197442/secure-insert-queries-with-go-sql-driver-and-mysql

	if activity.NewExtConnSession {
		daser.saveNewExternalConnectorAndSession(activity)
	} else if activity.NewConnFlag {
		daser.saveNewExternalConnection(activity)
		daser.saveNewActivity(activity)
	} else if activity.EndExtConnSession {
		daser.saveEndingExternalConnectorSession(activity)
	} else if activity.EndEngine {
		daser.markEndingEngineExecution()
	} else {
		daser.updateLastTimeConnectedForExternalConnectorSessions(activity)
		daser.saveNewActivity(activity)
	}
}
