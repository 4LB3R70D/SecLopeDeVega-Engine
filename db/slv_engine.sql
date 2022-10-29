-- Copyright 2022 The Sec Lope De Vega Authors. All rights reserved.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this file,
-- You can obtain one at http://mozilla.org/MPL/2.0/.

-- =================================================

-- MySQL dump 10.19  Distrib 10.3.34-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: slv_engine
-- ------------------------------------------------------
-- Server version	10.3.34-MariaDB-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `connection_captured_data`
--

DROP TABLE IF EXISTS `connection_captured_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connection_captured_data` (
  `connection_captured_data_pk` int(11) NOT NULL AUTO_INCREMENT,
  `custom_rule_pk` int(11) NOT NULL,
  `connection_memory_variable_pk` int(11) NOT NULL,
  `captured_value` varchar(500) NOT NULL,
  PRIMARY KEY (`connection_captured_data_pk`),
  KEY `captured_data_FK` (`custom_rule_pk`),
  KEY `captured_data_FK_1` (`connection_memory_variable_pk`),
  CONSTRAINT `captured_data_FK` FOREIGN KEY (`custom_rule_pk`) REFERENCES `custom_rule` (`custom_rule_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `captured_data_FK_1` FOREIGN KEY (`connection_memory_variable_pk`) REFERENCES `connection_memory_variable` (`connection_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for saving data captured for some rules to be added in some memory variables';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `connection_memory_snapshot`
--

DROP TABLE IF EXISTS `connection_memory_snapshot`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connection_memory_snapshot` (
  `connection_memory_snapshot_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_activity_pk` int(11) NOT NULL,
  `connection_memory_variable_pk` int(11) NOT NULL,
  `value` varchar(1000) NOT NULL,
  PRIMARY KEY (`connection_memory_snapshot_pk`),
  KEY `memory_snapshot_FK` (`external_activity_pk`),
  KEY `memory_snapshot_FK_1` (`connection_memory_variable_pk`),
  CONSTRAINT `memory_snapshot_FK` FOREIGN KEY (`external_activity_pk`) REFERENCES `external_activity` (`external_activity_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `memory_snapshot_FK_1` FOREIGN KEY (`connection_memory_variable_pk`) REFERENCES `connection_memory_variable` (`connection_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='table for saving the values of the memory variables reported in a external activity of one connection';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `connection_memory_variable`
--

DROP TABLE IF EXISTS `connection_memory_variable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `connection_memory_variable` (
  `connection_memory_variable_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_connection_pk` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  PRIMARY KEY (`connection_memory_variable_pk`),
  KEY `memory_variable_FK` (`external_connection_pk`),
  CONSTRAINT `memory_variable_FK` FOREIGN KEY (`external_connection_pk`) REFERENCES `external_connection` (`external_connection_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for registering the memory variables used in a connection';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custom_rule`
--

DROP TABLE IF EXISTS `custom_rule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_rule` (
  `custom_rule_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_activity_pk` int(11) NOT NULL,
  `rule_number` int(11) NOT NULL,
  `detected` tinyint(1) NOT NULL DEFAULT 0,
  `executed` tinyint(1) NOT NULL DEFAULT 0,
  `async` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`custom_rule_pk`),
  KEY `external_activity_pk` (`external_activity_pk`),
  CONSTRAINT `external_activity_pk` FOREIGN KEY (`external_activity_pk`) REFERENCES `external_activity` (`external_activity_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for registering the custom rules detect and/or executed during the interaction';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `engine_execution`
--

DROP TABLE IF EXISTS `engine_execution`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `engine_execution` (
  `engine_execution_pk` int(11) NOT NULL AUTO_INCREMENT,
  `execution_id` varchar(50) NOT NULL,
  `starting_time` datetime NOT NULL,
  `ending_time` datetime DEFAULT NULL,
  PRIMARY KEY (`engine_execution_pk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table to register the engine executions';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_activity`
--

DROP TABLE IF EXISTS `external_activity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `external_activity` (
  `external_activity_pk` int(11) NOT NULL AUTO_INCREMENT,
  `id` int(11) NOT NULL,
  `external_connection_pk` int(11) NOT NULL,
  `time` datetime NOT NULL,
  `external_input` varchar(2000) DEFAULT NULL,
  `new_conn` tinyint(1) NOT NULL DEFAULT 0,
  `tcp_conn_ready` tinyint(1) NOT NULL DEFAULT 0,
  `greetings_rule` tinyint(1) NOT NULL DEFAULT 0,
  `default_rule` tinyint(1) NOT NULL DEFAULT 0,
  `empty_rule` tinyint(1) NOT NULL DEFAULT 0,
  `raw_activity` varchar(5000) DEFAULT NULL,
  `hash` varchar(500) DEFAULT NULL,
  `pub_key_signature` varchar(520) DEFAULT NULL,
  `signature` varchar(520) DEFAULT NULL,
  PRIMARY KEY (`external_activity_pk`),
  KEY `external_connection_pk` (`external_connection_pk`),
  CONSTRAINT `external_connection_pk` FOREIGN KEY (`external_connection_pk`) REFERENCES `external_connection` (`external_connection_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_connection`
--

DROP TABLE IF EXISTS `external_connection`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `external_connection` (
  `external_connection_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_connector_session_pk` int(11) NOT NULL,
  `starting_time` datetime NOT NULL,
  `ip` varchar(200) NOT NULL,
  `port` int(11) NOT NULL,
  `protocol` varchar(150) NOT NULL,
  `external_connection_id` int(11) NOT NULL,
  `ending_time` datetime DEFAULT NULL,
  `encoding` varchar(20) NOT NULL,
  `timed_out` tinyint(1) NOT NULL DEFAULT 0,
  `broken` tinyint(1) NOT NULL DEFAULT 0,
  `incomplete` tinyint(1) NOT NULL DEFAULT 0,
  `hash_conv_rules_used` varchar(180) DEFAULT NULL,
  PRIMARY KEY (`external_connection_pk`),
  KEY `external_connecion_session_pk` (`external_connector_session_pk`),
  CONSTRAINT `external_connecion_session_pk` FOREIGN KEY (`external_connector_session_pk`) REFERENCES `external_connector_session` (`external_connector_session_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for managing external connections in the context of a external connector session';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_connector`
--

DROP TABLE IF EXISTS `external_connector`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `external_connector` (
  `external_connector_pk` int(11) NOT NULL AUTO_INCREMENT,
  `id_name` varchar(100) NOT NULL,
  PRIMARY KEY (`external_connector_pk`),
  UNIQUE KEY `external_connector_UN` (`id_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for registering the external connectors identities';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_connector_session`
--

DROP TABLE IF EXISTS `external_connector_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `external_connector_session` (
  `external_connector_session_pk` int(11) NOT NULL AUTO_INCREMENT,
  `session_id` int(11) NOT NULL,
  `engine_execution_pk` int(11) NOT NULL,
  `external_connector_pk` int(11) NOT NULL,
  `group` varchar(100) DEFAULT NULL,
  `starting_time` datetime NOT NULL,
  `last_time_connected` datetime NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `timed_out` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`external_connector_session_pk`),
  KEY `engine_execution_pk` (`engine_execution_pk`),
  KEY `external_connector_pk` (`external_connector_pk`),
  CONSTRAINT `engine_execution_pk` FOREIGN KEY (`engine_execution_pk`) REFERENCES `engine_execution` (`engine_execution_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `external_connector_pk` FOREIGN KEY (`external_connector_pk`) REFERENCES `external_connector` (`external_connector_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for the external connector sessions within an engine execution';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `global_captured_data`
--

DROP TABLE IF EXISTS `global_captured_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `global_captured_data` (
  `global_captured_data_pk` int(11) NOT NULL AUTO_INCREMENT,
  `custom_rule_pk` int(11) NOT NULL,
  `global_memory_variable_pk` int(11) NOT NULL,
  `captured_value` varchar(500) NOT NULL,
  PRIMARY KEY (`global_captured_data_pk`),
  KEY `global_captured_data_FK` (`custom_rule_pk`),
  KEY `global_captured_data_FK_1` (`global_memory_variable_pk`),
  CONSTRAINT `global_captured_data_FK` FOREIGN KEY (`custom_rule_pk`) REFERENCES `custom_rule` (`custom_rule_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `global_captured_data_FK_1` FOREIGN KEY (`global_memory_variable_pk`) REFERENCES `global_memory_variable` (`global_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='table for saving the captures of data of some rules regarding global memory variables';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `global_memory_snapshot`
--

DROP TABLE IF EXISTS `global_memory_snapshot`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `global_memory_snapshot` (
  `global_memory_snapshot_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_activity_pk` int(11) NOT NULL,
  `global_memory_variable_pk` int(11) NOT NULL,
  `value` varchar(1000) NOT NULL,
  PRIMARY KEY (`global_memory_snapshot_pk`),
  KEY `global_memory_snapshot_FK` (`external_activity_pk`),
  KEY `global_memory_snapshot_FK_1` (`global_memory_variable_pk`),
  CONSTRAINT `global_memory_snapshot_FK` FOREIGN KEY (`external_activity_pk`) REFERENCES `external_activity` (`external_activity_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `global_memory_snapshot_FK_1` FOREIGN KEY (`global_memory_variable_pk`) REFERENCES `global_memory_variable` (`global_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='table for saving the values of the global memory variables reported in one external activity';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `global_memory_variable`
--

DROP TABLE IF EXISTS `global_memory_variable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `global_memory_variable` (
  `global_memory_variable_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_connector_session_pk` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  PRIMARY KEY (`global_memory_variable_pk`),
  KEY `global_memory_variable_FK` (`external_connector_session_pk`),
  CONSTRAINT `global_memory_variable_FK` FOREIGN KEY (`external_connector_session_pk`) REFERENCES `external_connector_session` (`external_connector_session_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for saving the global memory variables used in a external connector session';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `multi_ext_conn_memory_snapshot`
--

DROP TABLE IF EXISTS `multi_ext_conn_memory_snapshot`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `multi_ext_conn_memory_snapshot` (
  `multi_ext_conn_memory_snapshot_pk` int(11) NOT NULL AUTO_INCREMENT,
  `external_activity_pk` int(11) NOT NULL,
  `multi_ext_connector_memory_variable_pk` int(11) NOT NULL,
  `value` varchar(1000) NOT NULL,
  PRIMARY KEY (`multi_ext_conn_memory_snapshot_pk`),
  KEY `multi_ext_conn_memory_snapshot_FK` (`external_activity_pk`),
  KEY `multi_ext_conn_memory_snapshot_FK_1` (`multi_ext_connector_memory_variable_pk`),
  CONSTRAINT `multi_ext_conn_memory_snapshot_FK` FOREIGN KEY (`external_activity_pk`) REFERENCES `external_activity` (`external_activity_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `multi_ext_conn_memory_snapshot_FK_1` FOREIGN KEY (`multi_ext_connector_memory_variable_pk`) REFERENCES `multi_ext_connector_memory_variable` (`multi_ext_connector_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for saving the memory variables values that are shared among external connectors, reported in a single moment';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `multi_ext_connector_captured_data`
--

DROP TABLE IF EXISTS `multi_ext_connector_captured_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `multi_ext_connector_captured_data` (
  `multi_ext_connector_captured_data_pk` int(11) NOT NULL AUTO_INCREMENT,
  `custom_rule_pk` int(11) NOT NULL,
  `multi_ext_connector_memory_variable_pk` int(11) NOT NULL,
  `captured_value` varchar(500) NOT NULL,
  PRIMARY KEY (`multi_ext_connector_captured_data_pk`),
  KEY `multi_ext_connector_captured_data_FK` (`custom_rule_pk`),
  KEY `multi_ext_connector_captured_data_FK_1` (`multi_ext_connector_memory_variable_pk`),
  CONSTRAINT `multi_ext_connector_captured_data_FK` FOREIGN KEY (`custom_rule_pk`) REFERENCES `custom_rule` (`custom_rule_pk`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `multi_ext_connector_captured_data_FK_1` FOREIGN KEY (`multi_ext_connector_memory_variable_pk`) REFERENCES `multi_ext_connector_memory_variable` (`multi_ext_connector_memory_variable_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for saving the caputred data that have been saved in a multi external connector memory variable';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `multi_ext_connector_memory_variable`
--

DROP TABLE IF EXISTS `multi_ext_connector_memory_variable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `multi_ext_connector_memory_variable` (
  `multi_ext_connector_memory_variable_pk` int(11) NOT NULL AUTO_INCREMENT,
  `engine_execution_pk` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  PRIMARY KEY (`multi_ext_connector_memory_variable_pk`),
  KEY `multi_ext_connector_memory_variable_FK` (`engine_execution_pk`),
  CONSTRAINT `multi_ext_connector_memory_variable_FK` FOREIGN KEY (`engine_execution_pk`) REFERENCES `engine_execution` (`engine_execution_pk`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Table for saving the multi external connector memory variables used during an engine execution';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-04-15 11:36:46
