/*
 Navicat Premium Data Transfer

 Source Server         : 192.168.1.137
 Source Server Type    : MariaDB
 Source Server Version : 100138 (10.1.38-MariaDB)
 Source Host           : 192.168.1.137:3306
 Source Schema         : accesslog

 Target Server Type    : MariaDB
 Target Server Version : 100138 (10.1.38-MariaDB)
 File Encoding         : 65001

 Date: 12/04/2023 21:07:07
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for info
-- ----------------------------
DROP TABLE IF EXISTS `info`;
CREATE TABLE `info`  (
  `ip` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `time` int(200) NULL DEFAULT NULL,
  `count` int(20) NULL DEFAULT NULL,
  `protocol` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `port` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL
) ENGINE = InnoDB CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of info
-- ----------------------------
INSERT INTO `info` VALUES ('1.1.1.1', 1680493624, 0, 'icmp', NULL);

-- ----------------------------
-- Table structure for ip
-- ----------------------------
DROP TABLE IF EXISTS `ip`;
CREATE TABLE `ip`  (
  `ip` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `time` int(200) NOT NULL,
  `type` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `action` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL
) ENGINE = InnoDB CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of ip
-- ----------------------------
INSERT INTO `ip` VALUES ('1.1.1.1', 1680495030, 'ssh', 'pass');

-- ----------------------------
-- Table structure for scan
-- ----------------------------
DROP TABLE IF EXISTS `scan`;
CREATE TABLE `scan`  (
  `ip` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `port` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL
) ENGINE = InnoDB CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of scan
-- ----------------------------

SET FOREIGN_KEY_CHECKS = 1;
