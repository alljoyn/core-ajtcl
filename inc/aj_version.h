#ifndef _AJ_VERSION_H
#define _AJ_VERSION_H
/**
 * @file aj_version.h
 * @defgroup aj_version Current AllJoyn Thin Client Version
 * @{
 */
/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/

#define AJ_RELEASE_YEAR        15       /**< release year */
#define AJ_MAJOR_VERSION       AJ_RELEASE_YEAR /**< deprecated */
#define AJ_RELEASE_MONTH       4        /**< release month */
#define AJ_MINOR_VERSION       AJ_RELEASE_MONTH /**< deprecated */
#define AJ_FEATURE_VERSION     0        /**< feature version */
#define AJ_RELEASE_VERSION     AJ_FEATURE_VERSION /**< deprecated */
#define AJ_BUGFIX_VERSION      98       /**< bugfix version (0=first, 0x61==a, 0x62==b, etc.) */
#define AJ_RELEASE_YEAR_STR    15       /**< release year string (two digits) */
#define AJ_RELEASE_MONTH_STR   04       /**< release month string (two digits) */
#define AJ_FEATURE_VERSION_STR 00       /**< feature version string (00, 01, 02, ...) */
#define AJ_BUGFIX_VERSION_STR  b        /**< bugfix version string (blank, a, b, ...) */
#define AJ_RELEASE_TAG         "v15.04.00b"

#define AJ_VERSION (((AJ_RELEASE_YEAR) << 24) | ((AJ_RELEASE_MONTH) << 16) | ((AJ_FEATURE_VERSION) << 8) | (AJ_BUGFIX_VERSION))  /**< macro to generate the version from major, minor, release, bugfix */

/**
 * @}
 */
#endif