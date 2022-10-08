/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================Sec Lope De Vega engine - operation_variables.go
=================================================
Author: Alberto Dominguez

This package contains the operation variables used in the system.
This file contains logic about global variables such as configuration
and context
*/

package opvariables

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strconv"

	"sec-lope-de-vega/internal/englogging"
	"sec-lope-de-vega/internal/messages"
	"sec-lope-de-vega/internal/utils"
)

// ====================================================
// CONFIG
// ====================================================
const consTokenLengthForEngineExecutionID = 6

// external connection struct, mainly used to load the configuration,
// but also used in the control of connections with them
type ExternalConnector struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

// external connection group struct, mainly used to load the configuration
type ExternalConnectorGroup struct {
	ID   string              `yaml:"id"`
	List []ExternalConnector `yaml:"list"`
}

// external connection group struct, mainly used to load the configuration
type TLSConfig struct {
	Enable                           bool   `yaml:"enable"`
	UseStartTLS                      bool   `yaml:"use_start_tls"`
	CaCert                           string `yaml:"ca_cert"`
	EngineClientCert                 string `yaml:"engine_client_cert"`
	EngineClientKey                  string `yaml:"engine_client_key"`
	EngineClientKeyProtected         bool   `yaml:"engine_client_key_protected"`
	EngineClientKeyProtectedPassword string `yaml:"engine_client_key_protected_password"`
	SkipCertificateVerification      bool   `yaml:"skip_certificate_verification"`
	RelativePathForCertificates      bool   `yaml:"relative_path_for_certificates"`
	ServerName                       string `yaml:"server_name"`
}

// Config structure for loading data from config file with the tags to map
// the values for the config file
type Config struct {
	ExtActivitySignature bool `yaml:"external_activity_signature"`
	ExternalConnectors   struct {
		ConvRulesFolder struct {
			Path           string `yaml:"path"`
			IsRelativePath bool   `yaml:"is_relative_path"`
		} `yaml:"conv_rules_folder"`
		ReloadConvRules               bool                     `yaml:"reload_conv_rules_in_new_contact"`
		MaxNumberOfExtConnWorkers     int                      `yaml:"max_number_of_workers"`
		MaxNumberOfExternalConnectors int                      `yaml:"max_number_of_external_connectors_connected"`
		DefaultSecret                 string                   `yaml:"default_secret"`
		Groups                        []ExternalConnectorGroup `yaml:"groups"`
	} `yaml:"external_connectors"`

	Networkorking struct {
		MQ struct {
			Port           int    `yaml:"port"`
			IPv6           bool   `yaml:"ipv6"`
			Encrypted      bool   `yaml:"connection_encrypted"`
			RSAKeyLength   int    `yaml:"rsa_key_lengt"`
			EngineAuthCode string `yaml:"engine_auth_code"`
		} `yaml:"mq"`
	} `yaml:"networking"`

	DataService struct {
		MaxNumberOfDataWorkers int `yaml:"max_number_data_workers"`

		SimpleFileStorage struct {
			Enable         bool   `yaml:"enable"`
			Path           string `yaml:"folder_path"`
			IsRelativePath bool   `yaml:"is_relative_path"`
			EncodeB64      bool   `yaml:"encode_b64"`
		} `yaml:"simple_file_storage"`

		Database struct {
			EnableSQLDB bool      `yaml:"enable_sql_db"`
			SQLUser     string    `yaml:"user"`
			SQLPassword string    `yaml:"password"`
			SQLIP       string    `yaml:"ip"`
			SQLPort     int       `yaml:"port"`
			SQLSchema   string    `yaml:"schema"`
			TLS         TLSConfig `yaml:"tls_config"`
		} `yaml:"database"`
	} `yaml:"data_service"`

	AlertingService struct {
		MaxNumberOfAlertWorkers int `yaml:"max_number_alert_workers"`

		SysLog struct {
			Enable               bool      `yaml:"enable"`
			Remote               bool      `yaml:"remote_flag"`
			RemoteSyslogProtocol string    `yaml:"remote_syslog_protocol"`
			RemoteSyslogServerIP string    `yaml:"remote_syslog_server_ip"`
			RemoteSyslogPort     int       `yaml:"remote_syslog_server_port"`
			SyslogTag            string    `yaml:"tag"`
			EncodeB64            bool      `yaml:"encode_activity_base64"`
			TLS                  TLSConfig `yaml:"tls_config"`
		} `yaml:"syslog"`

		Http struct {
			Enable        bool              `yaml:"enable"`
			Url           string            `yaml:"url"`
			Method        string            `yaml:"method"`
			UseBody       bool              `yaml:"use_body_flag"`
			EncodeB64     bool              `yaml:"encode_activity_base64"`
			TimeOut       int               `yaml:"timeout"`
			Headers       map[string]string `yaml:"headers"`
			UrlParameters map[string]string `yaml:"url_parameters"`
			BodyIntro     string            `yaml:"body_intro"`
			BodyEnd       string            `yaml:"body_end"`
			TLS           TLSConfig         `yaml:"tls_config"`
		} `yaml:"http"`

		KafKa struct {
			Enable                bool      `yaml:"enable"`
			IP                    string    `yaml:"server_ip"`
			Port                  int       `yaml:"server_port"`
			TLS                   TLSConfig `yaml:"tls_config"`
			EncodeB64             bool      `yaml:"encode_activity_base64"`
			Topic                 string    `yaml:"topic"`
			CreateTopicIfNotExist bool      `yaml:"create_topic_if_not_exist"`
			Balancer              string    `yaml:"distribution"`
			EventKey              string    `yaml:"event_key"`
			AuthN                 string    `yaml:"authentication_mechanism"`
			ScramHash             string    `yaml:"auth_scram_hash"`
			TimeOut               int       `yaml:"timeout"`
			User                  string    `yaml:"user"`
			Password              string    `yaml:"password"`
		} `yaml:"kafka"`

		Email struct {
			Enable                bool      `yaml:"enable"`
			SmtpIp                string    `yaml:"smtp_ip"`
			SmtpPort              int       `yaml:"smtp_port"`
			AuthN                 string    `yaml:"authentication_mechanism"`
			SmtpPlainAuthIdentity string    `yaml:"smtp_plain_auth_identity"`
			SmtpAuthUser          string    `yaml:"smtp_auth_user"`
			SmtpAuthPassword      string    `yaml:"smtp_auth_password"`
			SmtpPlainAuthHost     string    `yaml:"smtp_plain_auth_host"`
			TLS                   TLSConfig `yaml:"tls_config"`
			EncodeB64             bool      `yaml:"encode_activity_base64"`
			From                  string    `yaml:"from"`
			ReplyTo               []string  `yaml:"reply_to"`
			To                    []string  `yaml:"to"`
			CC                    []string  `yaml:"cc"`
			BCC                   []string  `yaml:"bcc"`
			Subject               string    `yaml:"subject"`
			BodyIntro             string    `yaml:"body_intro"`
			BodyEnd               string    `yaml:"body_end"`
		} `yaml:"email"`
	} `yaml:"alert_service"`

	Logging struct {
		Level                string `yaml:"level"`
		Mode                 string `yaml:"mode"`
		ShowCaller           bool   `yaml:"show_logger_caller"`
		ConsoleHumanFriendly bool   `yaml:"console_human_friendly"`
		AsyncLogs            bool   `yaml:"async_logs"`
		LogFolder            struct {
			Path           string `yaml:"path"`
			IsRelativePath bool   `yaml:"is_relative_path"`
		} `yaml:"log_folder"`
		LogPrefix                string `yaml:"log_prefix"`
		LogExtension             string `yaml:"log_extension"`
		LogRotationMaxSize       int    `yaml:"log_rotation_max_size"`
		LogRotationNumberFiles   int    `yaml:"log_rotation_number_files"`
		LogRotationMaxNumberDays int    `yaml:"log_rotation_max_number_days"`
		LogRotationCompress      bool   `yaml:"log_rotation_compress"`
	} `yaml:"logging"`

	GoChannels struct {
		EngineCockpitBuffer     int `yaml:"engine_cockpit_buffer"`
		ExtConnMngrWorkerBuffer int `yaml:"ext_conn_manager_worker_channel_buffer"`
		ExtConnMngrBuffer       int `yaml:"ext_conn_manager_buffer"`
		DataServiceBuffer       int `yaml:"data_service_buffer"`
		AlertingServiceBuffer   int `yaml:"alerting_service_buffer"`
	} `yaml:"go_channels"`

	Timing struct {
		EngineTimeout     int `yaml:"engine_timeout"`
		WaitingEndingTime int `yaml:"engine_ending_waiting_time"`
	} `yaml:"timing"`
}

// ====================================================
// CONTEXT
// ====================================================

// Context structure for the operation variables
type Context struct {
	ID        string  // id of the current instance
	Cnfg      *Config // config struct
	EngineDir string  // engine directory

	// communication channels in use for the cockpit thread
	CockpitCommChannels struct {
		ToEngineCockpit   <-chan messages.ChannelMessage
		ToExtConnMngr     chan<- messages.ChannelMessage
		ToDataService     chan<- messages.ChannelMessage
		ToAlertingService chan<- messages.ChannelMessage
	}

	// External Activity Signature Supporting Material
	EcdsaPrivateKey *ecdsa.PrivateKey
}

// function to create a new context
func NewContext(myCnfg *Config, myEngineDir string) *Context {

	engineID := strconv.Itoa(os.Getpid())
	token, err := utils.TokenGenerator(consTokenLengthForEngineExecutionID)
	if err != nil {
		englogging.ErrorLog("Error geting a token for the engine execution ID, using only the PID as ID", err)
	} else {
		engineID = engineID + token
	}

	// External Activity Digital Signature Crypto Material
	var newEcdsaPrivateKey *ecdsa.PrivateKey
	if myCnfg.ExtActivitySignature {
		newEcdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			englogging.ErrorLog("Error creating the private keys of ECDSA for external activity signature", err)
		}
	}

	// variable to return
	ctx := Context{
		ID:              engineID,
		Cnfg:            myCnfg,
		EngineDir:       myEngineDir,
		EcdsaPrivateKey: newEcdsaPrivateKey,
	}
	englogging.DebugLog("Engine context object created", nil)
	return &ctx
}

func (ctx *Context) AddCommChannels(myToEngineCockpit <-chan messages.ChannelMessage,
	myToExtConnMngr, myToDataService, myToAlertingService chan<- messages.ChannelMessage) {

	ctx.CockpitCommChannels.ToEngineCockpit = myToEngineCockpit
	ctx.CockpitCommChannels.ToExtConnMngr = myToExtConnMngr
	ctx.CockpitCommChannels.ToDataService = myToDataService
	ctx.CockpitCommChannels.ToAlertingService = myToAlertingService
}
