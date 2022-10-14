/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - slack_alerts.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the slack interactions

tutorial/examples:
  - https://github.com/slack-go/slack/blob/master/examples/socketmode/socketmode.go
  - https://towardsdatascience.com/develop-a-slack-bot-using-golang-1025b3e606bc
*/
package alerting

import (
	"fmt"
	"sync"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
)

var (
	slackMutex = &sync.Mutex{}
)

// ----------------------------------------------
// Fake logger implementation
// ----------------------------------------------
type FakeLogerType struct {
	tag string
}

// Implementation of Writer interface to use in the slack alerting channel
func (fl FakeLogerType) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// Implementation of Writer interface to use in the slack alerting channel
func (fl FakeLogerType) Output(calldepth int, s string) error {
	// redirect the information to the engine logger
	englogging.DebugLog("["+fl.tag+"]"+s, nil)
	return nil
}

// ----------------------------------------------
// Slack Alerting Functions
// ----------------------------------------------
// Function to initialise the slack client alerting mechanism
func initSlackClient(ctx *opvariables.Context) (bool, *socketmode.Client) {

	enableSlack := false

	fakelLoggerApi := FakeLogerType{"API"}
	fakelLoggerSocketMode := FakeLogerType{"SOCKET_MODE"}

	api := slack.New(ctx.Cnfg.AlertingService.Slack.OAuthToken,
		slack.OptionDebug(ctx.Cnfg.AlertingService.Slack.Debug),
		slack.OptionAppLevelToken(ctx.Cnfg.AlertingService.Slack.AppLevelToken),
		slack.OptionAPIURL(ctx.Cnfg.AlertingService.Slack.Url),
		slack.OptionLog(fakelLoggerApi),
	)

	client := socketmode.New(
		api,
		socketmode.OptionDebug(true),
		socketmode.OptionLog(fakelLoggerSocketMode),
	)

	initialText := fmt.Sprintf("%s%s","Lope engine connected! EngineID: ",ctx.ID)
	enableSlack = deliverSlackMessage("", initialText, ctx.Cnfg.AlertingService.Slack.TextColor,
		ctx.Cnfg.AlertingService.Slack.ChannelID, client)

	return enableSlack, client
}

// Auxiliary function to send a slack message
func deliverSlackMessage(pretext, text, color, channelID string, client *socketmode.Client) bool {

	var success bool

	// block the use of the slack client
	slackMutex.Lock()
	defer slackMutex.Unlock()

	attachment := slack.Attachment{
		Text:    text,
		Color: color,
		Fields: []slack.AttachmentField{
			{
				Title: "Date",
				Value: time.Now().String(),
			},
		},
	}
	if len(pretext) > 0{
		attachment.Pretext = pretext
	}

	// PostMessage will send the message away.
	// First parameter is just the channelID, makes no sense to accept it
	if _, _, err := client.PostMessage(
		channelID,
		// uncomment the item below to add a extra Header to the message, try it out :)
		//slack.MsgOptionText("New message from bot", false),
		slack.MsgOptionAttachments(attachment),
	); err == nil {
		success = true
		englogging.DebugLog("Slack message deliverd successfully!", nil)
	} else {
		englogging.ErrorLog("Slack message could not be sent!", err)
	}

	return success
}

// Function to send an alert via slack
func (aleser *AlertingService) sendSlackAlert(activity opvariables.ExtActivity) {

	// preapare activity to be sent
	activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash,
		activity.Signature, activity.PubKeyActivitySignature, activity.HashConvRules, aleser.encodeB64Slack)

	slackContent := fmt.Sprintf("%s%s%s",
		aleser.bodyIntroSlack,
		activityContent,
		aleser.bodyEndSlack)

	deliverSlackMessage(aleser.pretext, slackContent, aleser.textColor, aleser.channelID, aleser.slackClient)
}
