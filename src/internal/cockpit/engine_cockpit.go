/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - engine_cockpit.go
=================================================
Author: Alberto Dominguez

This packages is the main element of the engine, which oversees the execution of the engine
and takes decisions about when to end the execution. This module contains the main logic of
the operation loop of the engine
*/

package cockpit

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"sec-lope-de-vega/internal/alerting"
	"sec-lope-de-vega/internal/data"
	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/extconnector"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/opvariables"
)

const (
	consEngineSleepingTimeMilliseconds = 500 // milliseconds
	consSafeEndingTime                 = 3   // seconds
)

// Function to prepare the end the operation of the engine
func prepareOperationEnding(ctx *opvariables.Context) {

	// Send the end message
	englogging.InfoLog("Notifying the external connector manager service to prepare the end of the operation", nil)
	prepareEndingMessage := messages.ChannelMessage{
		Sender:  messages.ConsCockpitThread,
		Type:    messages.ConsOrder,
		Content: messages.ConsPrepareEndOrder,
	}
	ctx.CockpitCommChannels.ToExtConnMngr <- prepareEndingMessage
}

// Function to end the operation of the engine
func endEngineOperation(ctx *opvariables.Context) {

	// final time before ending to ensure the rest of the threads ends correctly
	time.Sleep(time.Duration(consSafeEndingTime) * time.Second)
	englogging.WarnLog("\n\n+-+-+-+-+-+-+-+-+-+-+-ENGINE EXECUTION ENDED-+-+-+-+-+-+-+-+-+-+\n\n", nil)
}

// Function to process messages received in the engine cockpit
func processOrder(intOrd messages.IntOrder, ctx *opvariables.Context) bool {

	working := true
	if intOrd == messages.ConsStopOrder {
		working = false
	}
	return working
}

// This function is the main one that controls the operation of the engine
func engineOperation(ctx *opvariables.Context) {

	englogging.InfoLog("Starting engine operation", nil)

	// For detecting 'CTRL+C'
	osSignalChannel := make(chan os.Signal, 1)
	signal.Notify(osSignalChannel, os.Interrupt)

	// Working flag
	working := true

	// timeout - https://gobyexample.com/timeouts
	var timeout int
	if ctx.Cnfg.Timing.EngineTimeout > 0 {
		timeout = ctx.Cnfg.Timing.EngineTimeout
	} else {
		timeout = 0 // it means, not timeout
	}
	timeoutChannel := time.After(time.Duration(timeout) * time.Second)

	for working { // while
		select { // https://tour.golang.org/concurrency/5

		// message received
		case msg := <-ctx.CockpitCommChannels.ToEngineCockpit:
			logText := fmt.Sprintf("Message received from other engine thread in the ENGINE COCKPIT SERVICE: %+v", msg)
			englogging.DebugLog(logText, nil)

			if msg.Type == messages.ConsOrder {
				intOrd := msg.Content.(messages.IntOrder)
				working = processOrder(intOrd, ctx)
			}

		case <-osSignalChannel:
			englogging.WarnLog("OS signal received to end the execution of the engine", nil)
			prepareOperationEnding(ctx)

		case <-timeoutChannel:
			// It only ends the execution if the timeout is a value grater than 0
			if timeout > 0 {
				englogging.WarnLog("Engine timeout! The execution of the engine will end", nil)
				prepareOperationEnding(ctx)
			}
		default:
			time.Sleep(consEngineSleepingTimeMilliseconds * time.Millisecond)
		}
	}
}

//This function starts the engine and initialise the main logic components and the main operation loop
func StartEngine(ctx *opvariables.Context) {

	englogging.InfoLog("Starting Engine components...", nil)
	// ------------------------------------------------
	// create communication channels between threads
	// ------------------------------------------------
	// engine cockpit
	toEngineCockpit := make(chan messages.ChannelMessage, ctx.Cnfg.GoChannels.EngineCockpitBuffer)
	// external connection manager
	toExtConnMngr := make(chan messages.ChannelMessage, ctx.Cnfg.GoChannels.ExtConnMngrBuffer)
	// data service
	toDataService := make(chan messages.ChannelMessage, ctx.Cnfg.GoChannels.DataServiceBuffer)
	// alerting service
	toAlertingService := make(chan messages.ChannelMessage, ctx.Cnfg.GoChannels.AlertingServiceBuffer)

	// add communication channels to the context object to be used by the engine cockpit thread
	ctx.AddCommChannels(toEngineCockpit, toExtConnMngr, toDataService, toAlertingService)

	// ------------------------------------------------
	// create engine logic components
	// ------------------------------------------------
	// external connection manager
	if extConnManager, err := extconnector.CreateExtConnManager(ctx, toExtConnMngr, toDataService,
		toAlertingService, toEngineCockpit); extConnManager != nil && err == nil {
		englogging.DebugLog("External connector manager created succesfully, and ready to start", nil)
		// data service
		dataService := data.CreateDataService(ctx, toDataService, toEngineCockpit)
		englogging.DebugLog("Data service created succesfully, and ready to start", nil)
		// alerting service
		alertingService := alerting.CreateAlertingService(ctx, toEngineCockpit, toAlertingService)
		englogging.DebugLog("Alerting service created succesfully, and ready to start", nil)

		// ------------------------------------------------
		// start engine logic components in different threads
		// ------------------------------------------------
		go extConnManager.Start()
		go dataService.Start()
		go alertingService.Start()

		// start engine operation
		engineOperation(ctx)

		// end operation
		endEngineOperation(ctx)
	} else {
		englogging.ErrorLog("Initializing the external connector service manager was not possible",err)
	}
}
