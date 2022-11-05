/*
Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.

=================================================
Sec Lope De Vega engine - utils.go
=================================================
Author: Alberto Dominguez

This package and file contains some auxiliary functions used in different parts of the software
*/

package utils

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	//https://chmodcommand.com
	ConsSimpleStorageFilePermits = 0755
)

// Function to convert a relative path to a absolute path
func RelativeToAbasolutePathIfRelative(engineDir, path string, isRelativePathFlag bool) string {

	var finalPath string
	// crete the file, depending the path provided in the config file
	if isRelativePathFlag {
		//relative path
		finalPath = filepath.Join(engineDir, path)
	} else {
		//absolute path
		finalPath = path
	}
	return finalPath
}

// Function to load a cert key (protected by password or not). In case it is, it returns a temporary file where
// the key unencrypted is this temporary file should be removed after being used
func loadCertPrivKey(privKeyPath, engineDir string, privKeyPathIsRelative, privKeyIsProtected bool,
	privKeyPassword string) (string, error) {
	// https://github.com/golang/go/issues/10181

	var privKeyPathToUse string
	var err error
	var pemContent []byte
	var privKeyBytes []byte
	var tempFile *os.File
	var absPathOfTempFile string

	keyPath := RelativeToAbasolutePathIfRelative(
		engineDir,
		privKeyPath,
		privKeyPathIsRelative)

	if privKeyIsProtected {
		// load the key encrypted
		if pemContent, err = ioutil.ReadFile(keyPath); err == nil {
			privKeyPasswordBytes := []byte(privKeyPassword)
			pemBlock, _ := pem.Decode(pemContent)
			// decrypt the loaded key. This function is deprecated, but there is no alternative in place so far
			if privKeyBytes, err = x509.DecryptPEMBlock(pemBlock, privKeyPasswordBytes); err == nil {

				//create a new PEM block for being exported
				newPemBlock := &pem.Block{
					Type:  pemBlock.Type,
					Bytes: privKeyBytes,
				}
				// create a temporary file
				if tempFile, err = ioutil.TempFile(os.TempDir(), "tmpk_"); err == nil {
					if err = pem.Encode(tempFile, newPemBlock); err == nil {
						// get the absoltue path
						if absPathOfTempFile, err = filepath.Abs(tempFile.Name()); err == nil {
							privKeyPathToUse = filepath.FromSlash(absPathOfTempFile)
						}
					}
				}
			}
		}
	} else {
		privKeyPathToUse = keyPath
	}
	return privKeyPathToUse, err
}

// Function to lad the CAs for the TLS config
func loadEngineCACerts(engineDir, caCertPath string, isRelativePath bool) (*x509.CertPool, bool, error) {

	var err error
	var pem []byte
	var ok bool

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if len(caCertPath) > 0 {
		if pem, err = ioutil.ReadFile(
			RelativeToAbasolutePathIfRelative(
				engineDir,
				caCertPath,
				isRelativePath)); err == nil {
			ok = rootCAs.AppendCertsFromPEM(pem)
		}
	} else {
		ok = true
	}
	return rootCAs, ok, err
}

// Function to load engine client cert for TLS config
func loadEngineClientCert(engineDir string, isRelativePath bool, engineClientKeyPath string,
	engineClientKeyProtected bool, engineClientKeyProtectedPassword, engineClientCertPath string) ([]tls.Certificate, error) {

	var err error
	var clientCert []tls.Certificate
	var privKeyLocation string
	var engineCert tls.Certificate

	if len(engineClientKeyPath) > 0 {
		clientCert = make([]tls.Certificate, 0, 1)
		// load the cert private key
		if privKeyLocation, err = loadCertPrivKey(
			engineClientKeyPath,
			engineDir,
			isRelativePath,
			engineClientKeyProtected,
			engineClientKeyProtectedPassword); err == nil {
			// parse the raw key to have the 'pem' nature
			certPath := RelativeToAbasolutePathIfRelative(
				engineDir,
				engineClientCertPath,
				isRelativePath)
			if engineCert, err = tls.LoadX509KeyPair(
				certPath,
				privKeyLocation); err == nil {
				clientCert = append(clientCert, engineCert)
			}
		}
	}
	return clientCert, err
}

// Function to a TLS config
func GetTlsConfig(engineDir, caCertPath string, isRelativePath bool, engineClientKeyPath string,
	engineClientKeyProtected bool, engineClientKeyProtectedPassword, engineClientCertPath string,
	selfSignedCerts bool, serverName string) (bool, *tls.Config, string, error) {

	success := false
	var tlsConfig tls.Config
	var privKeyLocation string
	var err error
	var clientCert []tls.Certificate
	var rootCAs *x509.CertPool
	var ok bool

	// load the CAs to be used
	if rootCAs, ok, err = loadEngineCACerts(engineDir, caCertPath, isRelativePath); ok && err == nil {
		// Load the engine client certificated (if applies)
		if clientCert, err = loadEngineClientCert(engineDir, isRelativePath, engineClientKeyPath,
			engineClientKeyProtected, engineClientKeyProtectedPassword,
			engineClientCertPath); err == nil {
			// create the config 'object'
			tlsConfig = tls.Config{
				MinVersion:         tls.VersionTLS12,
				RootCAs:            rootCAs,
				Certificates:       clientCert,
				InsecureSkipVerify: selfSignedCerts,
				ServerName:         serverName,
			}
			success = true
		}
	}
	return success, &tlsConfig, privKeyLocation, err
}

// Function to create a file in the system, and the corresponding folder structure if needed
func CreateNewFile(engineDir, folderPathCandidate, fileName string, isRelativePathFlag bool) (*os.File, error) {

	// define variables to be used
	var newFile *os.File
	var err error

	// crete the file, depending the path provided in the config file
	folderPath := RelativeToAbasolutePathIfRelative(engineDir, folderPathCandidate, isRelativePathFlag)

	if err == nil {
		//check if the folder exists
		_, err = os.Stat(folderPath)
		// if not, create it
		if os.IsNotExist(err) {
			err = os.MkdirAll(folderPath, ConsSimpleStorageFilePermits)
		}

		if err == nil {
			// create the file
			filePath := filepath.Join(folderPath, fileName)
			newFile, err = os.Create(filePath)
		}
	}
	return newFile, err
}

// Function to get a random string token
func TokenGenerator(length int) (string, error) {
	tokenBytes := make([]byte, length)
	_, err := rand.Read(tokenBytes)
	finalToken := hex.EncodeToString(tokenBytes)[:length]
	return finalToken, err
}

// Auxiliary function to get the activity contento to be safe in the simple file storage,
// or to be sent via the alerting mechanism
func PrepareActivityToBeExported(rawActivity, activityHash, activitySignature, pubKeyActivitySignature,
	hashConvRules string, base64Flag bool) string {

	activityContent := fmt.Sprintf("{\"Activity\":\"%s\",\"Hash_Activity\":\"%s\",\"Signature\":"+
		"\"%s\",\"Public_Key\":\"%s\"\n,\"Hash_Conversation_Rules\":\"%s\"\n},",
		rawActivity, activityHash, activitySignature, pubKeyActivitySignature, hashConvRules)

	if base64Flag {
		activityContent = b64.StdEncoding.EncodeToString([]byte(activityContent))
	}

	return activityContent
}

//--------------------------------
// Memory Variables
//--------------------------------
type MemVarType int

const (
	ConsMultiExternalConnectorMemoryVariable MemVarType = iota
	ConsGlobalMemoryVariable
	ConsConnectionMemoryVariable
)

// method to provide text to each enum option
func (mvtp MemVarType) String() string {
	// https://programming.guide/go/three-dots-ellipsis.html#array-literals
	return [...]string{"MULTI", "GLOBAL", "CONN"}[mvtp]
}
