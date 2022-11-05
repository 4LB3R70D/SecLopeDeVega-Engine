/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - data_service.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the data service, which is the one that
interact with the persistance elements. this file has the logic about the global
operation of the data service & the file storage
*/
package data

import (
	"crypto/tls"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"

	"github.com/go-sql-driver/mysql"
)

const (
	// Simple file storage
	consDataFilePrefix             = "engine_"
	consDataFileExt                = ".slvdata"
	consDefaultNumberOfDataWorkers = 200
	consSafeEndingTime             = 3 // seconds
)

// struct to be used as key for the cache of custom rules
type cacheExtConnSessionConnectionMapKey struct {
	ExternalConnectorSessionID int
	ConnectionID               int
}

// struct to be used as key for the cache of connection memory variables
type cacheConnMemVarMapKey struct {
	ConnectionID int
	VarName      string
}

// struct to be used as key for the cache of custom rules
type cacheRuleActivityMapKey struct {
	ActivityID int
	RuleID     int
}

//  "object" for the data service
type DataService struct {

	// flag to mark if the service should be running or not
	working bool

	// concurrency material
	dataMutex     *sync.Mutex
	fileMutex     *sync.Mutex
	numberWorkers int
	maxWorkers    int

	// communication channels
	toDataService   <-chan messages.ChannelMessage
	toEngineCockpit chan<- messages.ChannelMessage

	// Simple file storage
	enableFileStorage bool
	storageFilePath   string
	encodebase64      bool

	// SQL database
	enableSqlDB       bool
	sqlDB             *sql.DB
	dbKeyProtected    bool
	dbPrivKeyLocation string

	// Cache of DB PKs
	engineExecutionPK             int
	_externalConnectorsPKs        map[string]int
	_externalConnectorSessionsPKs map[int]int
	_externalConnectionPKs        map[cacheExtConnSessionConnectionMapKey]int
	_multiMemVarsPKs              map[string]int
	_globalMemVarsPKs             map[string]int
	_connMemVarsPKs               map[cacheConnMemVarMapKey]int
	_ruleActivityPKs              map[cacheRuleActivityMapKey]int
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 'Private' functions: database related ones
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// ------------------------------------------------------------------
// Initialisation + Utils
// ------------------------------------------------------------------
// Function to initialise the database
func initialiseSimpleFileStorage(dataService DataService, ctx *opvariables.Context) DataService {

	fileName := consDataFilePrefix + ctx.ID + consDataFileExt
	storageFile, err := utils.CreateNewFile(ctx.EngineDir, ctx.Cnfg.DataService.SimpleFileStorage.Path, fileName,
		ctx.Cnfg.DataService.SimpleFileStorage.IsRelativePath)
	dataService.encodebase64 = ctx.Cnfg.DataService.SimpleFileStorage.EncodeB64

	if err != nil {
		englogging.ErrorLog("Creation of the simple storage file not possible, it will not be used in this execution", err)
	} else {
		dataService.storageFilePath = filepath.Join(
			utils.RelativeToAbasolutePathIfRelative(
				ctx.EngineDir,
				ctx.Cnfg.DataService.SimpleFileStorage.Path,
				ctx.Cnfg.DataService.SimpleFileStorage.IsRelativePath),
			fileName)
		defer storageFile.Close()
		dataService.enableFileStorage = true
		englogging.DebugLog("Storage file creted successfully ", nil)
	}
	return dataService
}

// Function to initialise the database
func initialiseDB(dataService DataService, ctx *opvariables.Context) DataService {

	var err error
	var mySqlDb *sql.DB
	var success bool
	var tlsConfig *tls.Config
	var privKeyLocation string

	if ctx.Cnfg.DataService.Database.TLS.Enable {
		if success, tlsConfig, privKeyLocation, err = utils.GetTlsConfig(ctx.EngineDir, ctx.Cnfg.DataService.Database.TLS.CaCert,
			ctx.Cnfg.DataService.Database.TLS.RelativePathForCertificates, ctx.Cnfg.DataService.Database.TLS.EngineClientKey,
			ctx.Cnfg.DataService.Database.TLS.EngineClientKeyProtected, ctx.Cnfg.DataService.Database.TLS.EngineClientKeyProtectedPassword,
			ctx.Cnfg.DataService.Database.TLS.EngineClientCert, ctx.Cnfg.DataService.Database.TLS.SkipCertificateVerification,
			ctx.Cnfg.DataService.Database.TLS.ServerName); success {
			if err = mysql.RegisterTLSConfig("custom", tlsConfig); err != nil {
				englogging.ErrorLog("Not possible to apply the TLS config to the connection with the database", err)
			}
		} else {
			englogging.ErrorLog("Error preparing the TLS configuration fopr the connection with the database", err)
		}
	}
	// https://github.com/go-sql-driver/mysql
	mySqlDb, err = sql.Open("mysql", ctx.Cnfg.DataService.Database.SQLUser+":"+ctx.Cnfg.DataService.Database.SQLPassword+
		"@tcp("+ctx.Cnfg.DataService.Database.SQLIP+":"+strconv.Itoa(ctx.Cnfg.DataService.Database.SQLPort)+
		")/"+ctx.Cnfg.DataService.Database.SQLSchema)

	// check connection with database
	var version string
	mySqlDb.QueryRow("SELECT VERSION()").Scan(&version)

	// if there was an error in the connection with database and the test query does not provide any information
	// the database is not working, then, execution must end
	if (err != nil) || (len(version) == 0) || (mySqlDb == nil) {
		dataService.enableSqlDB = false
		englogging.ErrorLog("Connection with the database not possible, database will not be used in this execution", err)

	} else {
		// In case the private key is protected, then a temporary file is created
		// for saving the protected key unencrypted, and it should be removed
		//after being used

		dataService.sqlDB = mySqlDb
		dataService._externalConnectorsPKs = make(map[string]int)
		dataService._externalConnectorSessionsPKs = make(map[int]int)
		dataService._externalConnectionPKs = make(map[cacheExtConnSessionConnectionMapKey]int)
		dataService._multiMemVarsPKs = make(map[string]int)
		dataService._globalMemVarsPKs = make(map[string]int)
		dataService._connMemVarsPKs = make(map[cacheConnMemVarMapKey]int)
		dataService._ruleActivityPKs = make(map[cacheRuleActivityMapKey]int)
		dataService.dbKeyProtected = ctx.Cnfg.DataService.Database.TLS.Enable &&
			ctx.Cnfg.DataService.Database.TLS.EngineClientKeyProtected
		dataService.dbPrivKeyLocation = privKeyLocation

		// Add information in the database about the engine execution
		dt_formatted := getTimeAndDate()
		result, err := mySqlDb.Exec("INSERT INTO engine_execution (execution_id,starting_time) VALUES (?,?);", ctx.ID, dt_formatted)

		if err != nil {
			englogging.ErrorLog("Error inserting the entry for this engine execution, database will not be used then.", err)
		} else {
			engineExecutionPK, _ := result.LastInsertId()
			dataService.engineExecutionPK = int(engineExecutionPK)
			dataService.sqlDB = mySqlDb
			dataService.enableSqlDB = true
			englogging.DebugLog("Database connected: "+version, nil)
		}
	}
	return dataService
}

// function to get a time stamp for inserting data in the database
func getTimeAndDate() string {

	currentTime := time.Now()
	dateTimeFormatted := currentTime.Format(opvariables.ConsDateTimeFormat)
	return dateTimeFormatted
}

// Method to mark the ending of the engine executioninitialiseSimpleFileStorage
func (daser *DataService) markEndingEngineExecution() {

	time := getTimeAndDate()
	_, err := daser.sqlDB.Exec("UPDATE engine_execution SET ending_time=? WHERE engine_execution_pk=?",
		time, daser.engineExecutionPK)
	if err != nil {
		englogging.ErrorLog("Error at the time of marking the execution end'", err)
	} else {
		englogging.DebugLog("Engine execution ended in the database", nil)
	}
}

// ------------------------------------------------------------------
// Database PK Caches
// ------------------------------------------------------------------
// Function to save the PK of an external connector session
func (daser *DataService) saveExternalConnectorSessionPKinCache(externalConnectorSession, extConnSessionPk int) {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser._externalConnectorSessionsPKs[externalConnectorSession] = extConnSessionPk
}

// Function to get the PK of an external connector session
func (daser *DataService) getExternalConnectorSessionPKinCache(externalConnectorSession int) int {

	var extConnSessionPK int
	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()

	extConnSessionPK = daser._externalConnectorSessionsPKs[externalConnectorSession]

	return extConnSessionPK
}

// Function to get the connectio ID (session ID) of an external connector session using the PK
func (daser *DataService) getConnIDFromExternalConnectorSessionPk(externalConnectorSessionPk int) int {

	externalConnectorConnID := 0
	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()

	for externalConnectorSessionID, extConnSessionPk := range daser._externalConnectorSessionsPKs {
		if extConnSessionPk == externalConnectorSessionPk {
			externalConnectorConnID = externalConnectorSessionID
			break
		}
	}
	return externalConnectorConnID
}

// Function to save the PK of an external connector
func (daser *DataService) saveExternalConnectorPKinCache(extConnMessageSender string, extConnPk int) {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser._externalConnectorsPKs[extConnMessageSender] = extConnPk
}

// Function to save the PK of an external connection
func (daser *DataService) saveExternalConnectionPKinCache(
	cacheExtConnSessionConnectionMapKey cacheExtConnSessionConnectionMapKey,
	extConnectionPK int) {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser._externalConnectionPKs[cacheExtConnSessionConnectionMapKey] = extConnectionPK
}

// Function to get the PK of an external connection
func (daser *DataService) getExternalConnectionPKinCache(
	cacheExtConnSessionConnectionMapKey cacheExtConnSessionConnectionMapKey) (int, bool) {

	var ok bool
	var extConnectionPK int
	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()

	extConnectionPK, ok = daser._externalConnectionPKs[cacheExtConnSessionConnectionMapKey]

	return extConnectionPK, ok
}

// Function to save the PK of an memory variable
func (daser *DataService) saveMemoryVariablePKinCache(memVarName string, cacheConnMemVarMapKey cacheConnMemVarMapKey,
	memVarPK int, memVarType utils.MemVarType) {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()

	if memVarType == utils.ConsMultiExternalConnectorMemoryVariable {
		daser._multiMemVarsPKs[memVarName] = memVarPK

	} else if memVarType == utils.ConsGlobalMemoryVariable {
		daser._globalMemVarsPKs[memVarName] = memVarPK

	} else if memVarType == utils.ConsConnectionMemoryVariable {
		daser._connMemVarsPKs[cacheConnMemVarMapKey] = memVarPK
	}
}

// Function to get the PK of an memory variable
func (daser *DataService) getMemoryVariablePKinCache(memVarName string, connMemVarMapKey cacheConnMemVarMapKey,
	memVarType utils.MemVarType) (int, bool) {

	var memVarPK int
	var ok bool

	daser.dataMutex.Lock()
	if memVarType == utils.ConsMultiExternalConnectorMemoryVariable {
		memVarPK, ok = daser._multiMemVarsPKs[memVarName]

	} else if memVarType == utils.ConsGlobalMemoryVariable {
		memVarPK, ok = daser._globalMemVarsPKs[memVarName]

	} else if memVarType == utils.ConsConnectionMemoryVariable {
		memVarPK, ok = daser._connMemVarsPKs[connMemVarMapKey]
	}
	daser.dataMutex.Unlock()

	return memVarPK, ok
}

// Function to save the PK of executed conversation rule in one activity
func (daser *DataService) saveRuleActivityPKinCache(ruleActivityMapKey cacheRuleActivityMapKey, ruleActivityPK int) {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser._ruleActivityPKs[ruleActivityMapKey] = ruleActivityPK
}

// Function to save the PK of executed conversation rule in one activity
func (daser *DataService) getRuleActivityPKinCache(ruleActivityMapKey cacheRuleActivityMapKey) (int, bool) {

	var ruleActivityPK int
	var ok bool
	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()

	ruleActivityPK, ok = daser._ruleActivityPKs[ruleActivityMapKey]

	return ruleActivityPK, ok
}

// ------------------------------------------------------------------
// Activity
// ------------------------------------------------------------------

// Function to save an activity in the simpel file storage
func (daser *DataService) saveActivityInSimpleFileStorage(activity opvariables.ExtActivity) {
	daser.fileMutex.Lock()
	defer daser.fileMutex.Unlock()
	// http://networkbit.ch/golang-write-text-file/
	storageFile, err := os.OpenFile(daser.storageFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE,
		utils.ConsSimpleStorageFilePermits)
	if err != nil {
		englogging.ErrorLog("Error opening the storage file, the activity will not be saved", err)

	} else {
		defer storageFile.Close()
		activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash,
			activity.Signature, activity.PubKeyActivitySignature,
			activity.HashConvRules, daser.encodebase64)
		storageFile.WriteString(activityContent)
	}
}

// Function to save data about an activity in the different persistance capabilities
func (daser *DataService) saveActivity(activity opvariables.ExtActivity) {

	defer daser.decreaseNumberOfDataWorkers()
	if len(activity.GetActivityContent()) > 0 {
		if daser.enableFileStorage {
			daser.saveActivityInSimpleFileStorage(activity)
		}
		if daser.enableSqlDB {
			daser.saveActivityInDatabase(activity)
		}
	} else {
		englogging.WarnLog("Empty Activity received, not possible to save it: Nothing to save!", nil)
	}
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 'Private' functions: internal service related ones
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Method to end the execution of a data service
func (daser *DataService) stop() {

	daser.working = false

	if daser.enableSqlDB {
		defer daser.sqlDB.Close()
		// final time before ending to ensure the rest of the threads ends correctly
		time.Sleep(time.Duration(consSafeEndingTime) * time.Second)
		if daser.dbKeyProtected {
			if err := os.Remove(daser.dbPrivKeyLocation); err != nil {
				englogging.ErrorLog("Deleting the temporary file when the key is encrypted was not possible for database TLSe", err)
			}
		}
	}
	englogging.WarnLog("DATA SERVICE ENDED!", nil)
}

// Method to increase the number of data workers in use
func (daser *DataService) increaseNumberOfDataWorkers() {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser.numberWorkers++
}

// Method to decrease the number of data workers in use
func (daser *DataService) decreaseNumberOfDataWorkers() {

	daser.dataMutex.Lock()
	defer daser.dataMutex.Unlock()
	daser.numberWorkers--
}

// Function to process the orders received from the engine cockpit
func (daser *DataService) processInternalOrder(intOrd messages.IntOrder) {

	if intOrd == messages.ConsStopOrder {
		daser.stop()
	}
}

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 'Public' functions
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//function to create a new data service
func CreateDataService(ctx *opvariables.Context, myToDataService <-chan messages.ChannelMessage,
	myToEngineCockpit chan<- messages.ChannelMessage) *DataService {

	maxNumberOfDataWorkers := consDefaultNumberOfDataWorkers
	if ctx.Cnfg.DataService.MaxNumberOfDataWorkers > 0 {
		maxNumberOfDataWorkers = ctx.Cnfg.DataService.MaxNumberOfDataWorkers
	}

	dataService := DataService{
		toDataService:     myToDataService,
		toEngineCockpit:   myToEngineCockpit,
		enableSqlDB:       false,
		enableFileStorage: false,
		working:           true,
		dataMutex:         &sync.Mutex{},
		fileMutex:         &sync.Mutex{},
		numberWorkers:     0,
		maxWorkers:        maxNumberOfDataWorkers,
	}

	if ctx.Cnfg.DataService.SimpleFileStorage.Enable {
		dataService = initialiseSimpleFileStorage(dataService, ctx)
	}

	dataService.enableSqlDB = ctx.Cnfg.DataService.Database.EnableSQLDB
	if ctx.Cnfg.DataService.Database.EnableSQLDB {
		dataService = initialiseDB(dataService, ctx)
	}
	return &dataService
}

// Method to start the execution of a data service
func (daser *DataService) Start() {

	englogging.InfoLog("Starting data service in a new thread", nil)

	for daser.working {
		msg := <-daser.toDataService

		if msg.Type == messages.ConsActivity {
			activity := msg.Content.(opvariables.ExtActivity)

			waiting := true
			for waiting {
				// wait until the number of data workers decreases
				if daser.numberWorkers < daser.maxWorkers {
					// execute in a different thread
					daser.increaseNumberOfDataWorkers()
					go daser.saveActivity(activity)
					waiting = false
				}
			}

		} else if msg.Type == messages.ConsOrder {
			intOrd := msg.Content.(messages.IntOrder)
			daser.processInternalOrder(intOrd)
		}
	} //"while"
}
