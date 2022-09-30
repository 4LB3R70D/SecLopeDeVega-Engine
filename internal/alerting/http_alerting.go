/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - http_alerts.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the http client
mechanism to send alerts
*/
package alerting

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
)

const (
	consGetHttpMethod  = "GET"
	consPutHttpMethod  = "PUT"
	consPostHttpMethod = "POST"

	consActivityQueryParameter = "{{ACTIVITY}}"
)

// https://www.practical-go-lessons.com/chap-35-build-an-http-client#a-basic-http-client

// Function to initialise the http client alerting mechanism
func initHttpClient(ctx *opvariables.Context) (bool, *http.Client, string, string) {

	var enableHttpClient bool
	var httpPrivKeyLocation string
	var tlsConfig *tls.Config
	var err error

	if ctx.Cnfg.AlertingService.Http.TLS.Enable {
		if enableHttpClient, tlsConfig, httpPrivKeyLocation, err = utils.GetTlsConfig(ctx.EngineDir,
			ctx.Cnfg.AlertingService.Http.TLS.CaCert, ctx.Cnfg.AlertingService.Http.TLS.RelativePathForCertificates,
			ctx.Cnfg.AlertingService.Http.TLS.EngineClientKey, ctx.Cnfg.AlertingService.Http.TLS.EngineClientKeyProtected,
			ctx.Cnfg.AlertingService.Http.TLS.EngineClientKeyProtectedPassword,
			ctx.Cnfg.AlertingService.Http.TLS.EngineClientCert, ctx.Cnfg.AlertingService.Http.TLS.SkipCertificateVerification,
			ctx.Cnfg.AlertingService.Http.TLS.ServerName); err != nil {
			englogging.ErrorLog("Error loading the TLS config for Http", err)
		}
	} else {
		enableHttpClient = true
	}
	httpClient := &http.Client{
		Timeout: time.Duration(ctx.Cnfg.AlertingService.Http.TimeOut) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// HTTP Method
	methodConfig := strings.ToUpper(ctx.Cnfg.AlertingService.Http.Method)
	httpMethod := consPostHttpMethod
	if methodConfig == consGetHttpMethod {
		httpMethod = consGetHttpMethod
	} else if methodConfig == consPutHttpMethod {
		httpMethod = consPutHttpMethod
	}
	return enableHttpClient, httpClient, httpMethod, httpPrivKeyLocation
}

// Function to send an alert via http
func (aleser *AlertingService) sendHttpAlert(activity opvariables.ExtActivity) {

	// preapare activity to be sent
	activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash,
		activity.Signature, activity.PubKeyActivitySignature, activity.HashConvRules, aleser.encodeB64Http)

	// Prepare the body to be sent
	var reqBody *bytes.Buffer
	if aleser.useHttpBody {
		httpBodyContent := fmt.Sprintf("%s%s%s",
			aleser.bodyIntroHttp,
			activityContent,
			aleser.bodyEndHttp)

		reqBody = bytes.NewBuffer(
			[]byte(httpBodyContent))
	}

	if req, err := http.NewRequest(aleser.httpMethod, aleser.httpUrl, reqBody); err == nil {

		// Adding headers
		for headerName, headerValue := range aleser.headers {
			req.Header.Add(headerName, headerValue)
		}

		// Adding parameters
		queryString := req.URL.Query()
		for parName, parValue := range aleser.urlParameters {
			if strings.ToUpper(parValue) == consActivityQueryParameter {
				queryString.Add(parName, activity.GetActivityContent())
			} else {
				queryString.Add(parName, parValue)
			}
		}
		req.URL.RawQuery = queryString.Encode()

		// Sending the Activity
		aleser.httpMutex.Lock()
		defer aleser.httpMutex.Unlock()
		if resp, err := aleser.httpClient.Do(req); err == nil {
			defer resp.Body.Close()
			if respBody, err := ioutil.ReadAll(resp.Body); err == nil {
				logMsg := fmt.Sprintf("Response received after sending the HTTP: '%s'", string(respBody[:]))
				englogging.DebugLog(logMsg, nil)
			} else {
				englogging.ErrorLog("Error reading the response after sending an activity via HTTP", err)
			}
		} else {
			englogging.ErrorLog("Error receiving the response after sending an activity via HTTP", err)
		}
	} else {
		englogging.ErrorLog("Error preparing the activity to be sent via HTTP", err)
	}
}
