/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - kafka_alerts.go
=================================================
Author: Alberto Dominguez

This package manages the interaction with the alerting systems for sending alerts
according to the events registered. This file contains the logic of the kafka interactions
*/
package alerting

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/opvariables"
	"sec-lope-de-vega/internal/utils"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// https://github.com/segmentio/kafka-go
const (
	consBalancerModeLeastBytes      = "LEAST_BYTES"
	consBalancerModeCrc32Balancer   = "CRC32BALANCER"
	consBalancerModeMurmur2Balancer = "MURMUR2BALANCER"
	consBalancerModeHash            = "HASH"
	consAuthScram                   = "SCRAM"
	consAuthScramSha256             = "SHA256"
	consAuthPlain                   = "PLAIN"
	consTimeBetweenRetries          = 500
)

// log wrapper for kafka client
func kafkaLogWrapper(msg string, a ...interface{}) {
	logText := fmt.Sprintf(msg, a...)
	englogging.InfoLog(logText, nil)
}

// error log wrapper for kafka client
func kafkaErrorLogWrapper(msg string, a ...interface{}) {
	logText := fmt.Sprintf(msg, a...)
	englogging.ErrorLog(logText, nil)
}

// Auxiliary finction to get the balancer
func getKafkaBalancer(configSelection string) kafka.Balancer {

	var balancerMode kafka.Balancer

	balancerConfigMode := strings.ToUpper(configSelection)
	if balancerConfigMode == consBalancerModeCrc32Balancer {
		balancerMode = &kafka.CRC32Balancer{}

	} else if balancerConfigMode == consBalancerModeMurmur2Balancer {
		balancerMode = &kafka.Murmur2Balancer{}

	} else if balancerConfigMode == consBalancerModeHash {
		balancerMode = &kafka.Hash{}

	} else {
		balancerMode = &kafka.LeastBytes{}
	}
	return balancerMode
}

// Auxiliary function to get the authentication mechanism
func getAuthMechanism(ctx *opvariables.Context) (sasl.Mechanism, error) {

	var err error
	var mechanism sasl.Mechanism
	authConfig := strings.ToUpper(ctx.Cnfg.AlertingService.KafKa.AuthN)

	if authConfig == consAuthPlain {
		mechanism = plain.Mechanism{
			Username: ctx.Cnfg.AlertingService.KafKa.User,
			Password: ctx.Cnfg.AlertingService.KafKa.Password,
		}
	} else if authConfig == consAuthScram {
		var algo scram.Algorithm
		if strings.ToUpper(ctx.Cnfg.AlertingService.KafKa.ScramHash) == consAuthScramSha256 {
			algo = scram.SHA256
		} else {
			algo = scram.SHA512
		}
		mechanism, err = scram.Mechanism(algo,
			ctx.Cnfg.AlertingService.KafKa.User,
			ctx.Cnfg.AlertingService.KafKa.Password)
	}
	return mechanism, err
}

// Function to initialise the kafka alerting mechanism
func initKafka(ctx *opvariables.Context) (bool, *kafka.Writer, string) {

	var tlsConfig *tls.Config
	var privKeyLocation string
	var kafkaWriter *kafka.Writer
	enableKafka := false

	addr := kafka.TCP(ctx.Cnfg.AlertingService.KafKa.IP + ":" + strconv.Itoa(ctx.Cnfg.AlertingService.KafKa.Port))
	selectedBalancer := getKafkaBalancer(ctx.Cnfg.AlertingService.KafKa.Balancer)
	authMechanism, err := getAuthMechanism(ctx)

	if err == nil {
		if ctx.Cnfg.AlertingService.KafKa.TLS.Enable {
			if enableKafka, tlsConfig, privKeyLocation, err = utils.GetTlsConfig(ctx.EngineDir,
				ctx.Cnfg.AlertingService.KafKa.TLS.CaCert, ctx.Cnfg.AlertingService.KafKa.TLS.RelativePathForCertificates,
				ctx.Cnfg.AlertingService.KafKa.TLS.EngineClientKey, ctx.Cnfg.AlertingService.KafKa.TLS.EngineClientKeyProtected,
				ctx.Cnfg.AlertingService.KafKa.TLS.EngineClientKeyProtectedPassword,
				ctx.Cnfg.AlertingService.KafKa.TLS.EngineClientCert, ctx.Cnfg.AlertingService.KafKa.TLS.SkipCertificateVerification,
				ctx.Cnfg.AlertingService.KafKa.TLS.ServerName); err != nil {
				englogging.ErrorLog("Error loading the TLS config for Kafka", err)
			}
		}
		kafkaWriter = &kafka.Writer{
			Addr:                   addr,
			Topic:                  ctx.Cnfg.AlertingService.KafKa.Topic,
			Balancer:               selectedBalancer,
			AllowAutoTopicCreation: ctx.Cnfg.AlertingService.KafKa.CreateTopicIfNotExist,
			Logger:                 kafka.LoggerFunc(kafkaLogWrapper),
			ErrorLogger:            kafka.LoggerFunc(kafkaErrorLogWrapper),
			Transport: &kafka.Transport{
				SASL: authMechanism,
				TLS:  tlsConfig,
			}}
		if err == nil {
			enableKafka = true
		}
	} else {
		englogging.ErrorLog("Not possible to get the Authentication Mechanism for Kafka", err)
	}
	return enableKafka, kafkaWriter, privKeyLocation
}

// function to send a kafka message
func (aleser *AlertingService) sendKafkaAlert(activity opvariables.ExtActivity) {

	var err error
	const retries = 3
	activityContent := utils.PrepareActivityToBeExported(activity.GetActivityContent(), activity.Hash,
		activity.Signature, activity.PubKeyActivitySignature,
		activity.HashConvRules, aleser.encodeB64Kafka)

	messages := []kafka.Message{
		{
			Key:   []byte(aleser.kafkaEventKey),
			Value: []byte(activityContent),
		},
	}

	aleser.kafkaMutex.Lock()
	defer aleser.kafkaMutex.Unlock()

	for i := 0; i < retries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), aleser.kafkaTimeout)
		defer cancel()

		// attempt to create topic prior to publishing the message
		err = aleser.kafkaWriter.WriteMessages(ctx, messages...)

		if errors.Is(err, kafka.LeaderNotAvailable) || errors.Is(err, context.DeadlineExceeded) {
			time.Sleep(consTimeBetweenRetries * time.Millisecond)
			continue
		}
		if err != nil {
			englogging.ErrorLog("An expected error happens sending the kafka alert", err)
		} else {
			// success delivery
			englogging.DebugLog("Kafka message sent successfully", nil)
			break
		}
	}
}
