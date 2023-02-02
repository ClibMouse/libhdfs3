/*******************************************************************
 * Copyright (c) 2013 - 2014, Pivotal Inc.
 * All rights reserved.
 *
 * Author: Zhanwei Wang
 ********************************************************************/
/********************************************************************
 * 2014 -
 * open source under Apache License Version 2.0
 ********************************************************************/
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <algorithm>
#include <cctype>

#include "Exception.h"
#include "ExceptionInternal.h"
#include "SaslClient.h"
#include <string>
#include <sstream>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

#define SASL_SUCCESS 0

namespace Hdfs {
namespace Internal {

std::string calculateIV(std::string initIV, long counter) {
    std::string IV;
    IV.resize(initIV.length());
    int i = initIV.length();
    int j = 0;
    int sum = 0;
    unsigned c;
    while (i-- > 0) {
      // (sum >>> Byte.SIZE) is the carry for addition
      sum = (((unsigned char)initIV.c_str()[i]) & 0xff) + ((unsigned int)sum >> 8);
      if (j++ < 8) { // Big-endian, and long is 8 bytes length
        sum += (unsigned char) counter & 0xff;
        c = (unsigned long) counter;
        c >>= (unsigned)8;
        counter = c;
      }
      IV[i] = (unsigned char) sum;
    }
    return IV;
}

void printArray(std::string str, const char* text) {
    int i=0;
    printf("length %d: %s\n", (int)str.length(), text);
    for (i=0; i < (int)str.length(); i++) {
        printf("%02d ", (int)str[i]);
    }
    printf("\n");

}
bool AESClient::initialized = false;

AESClient::AESClient(std::string enckey, std::string enciv,
              std::string deckey, std::string deciv, int bufsize) :
              encrypt(NULL), decrypt(NULL), packetsSent(0), decoffset(0), bufsize(bufsize),
              enckey(enckey), enciv(enciv), deckey(deckey), deciv(deciv), initdeciv(deciv)
{
    if (!initialized) {
      ERR_load_crypto_strings();
      OpenSSL_add_all_algorithms();
      OPENSSL_config(NULL);
      initialized = true;
    }
    encrypt = NULL;
    decrypt = NULL;
    encrypt = EVP_CIPHER_CTX_new();
    if (!encrypt) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes encrypt context %s",
              err.c_str());
    }
    decrypt = EVP_CIPHER_CTX_new();
    if (!decrypt) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes decrypt context %s",
              err.c_str());
    }
    std::string iv = enciv;
    const EVP_CIPHER *cipher = NULL;
    if (enckey.length() == 32)
        cipher = EVP_aes_256_ctr();
    else if (enckey.length() == 16)
        cipher = EVP_aes_128_ctr();
    else
        cipher = EVP_aes_192_ctr();
    if (!EVP_CipherInit_ex(encrypt, cipher, NULL,
        (const unsigned char*)enckey.c_str(), (const unsigned char*)iv.c_str(), 1)) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes encrypt cipher %s",
              err.c_str());
    }
    iv = deciv;
    if (!EVP_CipherInit_ex(decrypt, cipher, NULL, (const unsigned char*)deckey.c_str(),
        (const unsigned char*)iv.c_str(), 0)) {
        std::string err = ERR_lib_error_string(ERR_get_error());
        THROW(HdfsIOException, "Cannot initialize aes decrypt cipher %s",
              err.c_str());
    }
    EVP_CIPHER_CTX_set_padding(encrypt, 0);
    EVP_CIPHER_CTX_set_padding(decrypt, 0);

}

AESClient::~AESClient() {
    if (encrypt)
        EVP_CIPHER_CTX_free(encrypt);
    if (decrypt)
        EVP_CIPHER_CTX_free(decrypt);
}

std::string AESClient::encode(const char *input, size_t input_len) {
    int len;
    std::string result;
    result.resize(input_len);
    int offset = 0;
    int remaining = input_len;

    while (remaining > bufsize) {
        if (!EVP_CipherUpdate (encrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, bufsize)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot encrypt AES data %s",
                  err.c_str());
        }
        offset += len;
        remaining -= len;
    }
    if (remaining) {

        if (!EVP_CipherUpdate (encrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, remaining)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot encrypt AES data %s",
                  err.c_str());
        }
    }
    return result;
}


std::string AESClient::decode(const char *input, size_t input_len) {
    int len;
    std::string result;
    result.resize(input_len);
    int offset = 0;
    int remaining = input_len;

    while (remaining > bufsize) {
        if (!EVP_CipherUpdate (decrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, bufsize)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot decrypt AES data %s",
                  err.c_str());
        }
        offset += len;
        remaining -= len;
    }
    if (remaining) {

        if (!EVP_CipherUpdate (decrypt, (unsigned char*)&result[offset], &len, (const unsigned char*)input+offset, remaining)) {
            std::string err = ERR_lib_error_string(ERR_get_error());
            THROW(HdfsIOException, "Cannot decrypt AES data %s",
                  err.c_str());
        }
    }
    decoffset += input_len;
    return result;

}




SaslClient::SaslClient(const RpcSaslProto_SaslAuth & auth, const Token & token,
                       const std::string & principal) :
    complete(false) {
    int rc;
    ctx = NULL;
    RpcAuth method = RpcAuth(RpcAuth::ParseMethod(auth.method()));
    rc = gsasl_init(&ctx);

    if (rc != GSASL_OK) {
        THROW(HdfsIOException, "cannot initialize libgsasl");
    }

    switch (method.getMethod()) {
    case AuthMethod::KERBEROS:
        initKerberos(auth, principal);
        break;

    case AuthMethod::TOKEN:
        initDigestMd5(auth, token);
        break;

    default:
        THROW(HdfsIOException, "unknown auth method.");
        break;
    }
}

SaslClient::~SaslClient() {
    if (aes)
        delete aes;

    if (session != NULL) {
        gsasl_finish(session);
    }

    if (ctx != NULL) {
        gsasl_done(ctx);
    }
}

void SaslClient::initKerberos(const RpcSaslProto_SaslAuth & auth,
                              const std::string & principal) {
    int rc;

    /* Create new authentication session. */
    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(HdfsIOException, "Cannot initialize client (%d): %s", rc,
              gsasl_strerror(rc));
    }

    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
    gsasl_property_set(session, GSASL_AUTHID, principal.c_str());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());
}

std::string Base64Encode(const std::string & in) {
    char * temp;
    size_t len;
    std::string retval;
    int rc = gsasl_base64_to(in.c_str(), in.size(), &temp, &len);

    if (rc != GSASL_OK) {
        if (rc == GSASL_BASE64_ERROR)
            THROW(HdfsIOException, "SaslClient: Failed to encode string to base64");
        throw std::bad_alloc();
    }

    if (temp) {
        retval = temp;
        free(temp);
    }

    if (!temp || retval.length() != len) {
        THROW(HdfsIOException, "SaslClient: Failed to encode string to base64");
    }

    return retval;
}

std::string Base64Decode(const std::string & in) {
    char * temp;
    size_t len;
    std::string retval;
    int rc = gsasl_base64_from(in.c_str(), in.size(), &temp, &len);

    if (rc != GSASL_OK) {
        if (rc == GSASL_BASE64_ERROR)
            THROW(HdfsIOException, "SaslClient: Failed to decode string to base64");
        throw std::bad_alloc();
    }

    if (temp) {
        retval.assign(temp, len);
        free(temp);
    }

    if (!temp || retval.length() != len) {
        THROW(HdfsIOException, "SaslClient: Failed to decode string to base64");
    }

    return retval;
}

void SaslClient::initDigestMd5(const RpcSaslProto_SaslAuth & auth,
                               const Token & token) {
    int rc;

    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(HdfsIOException, "Cannot initialize client (%d): %s", rc, gsasl_strerror(rc));
    }

    std::string password = Base64Encode(token.getPassword());
    std::string identifier;

    if (!encryptedData)
        identifier = Base64Encode(token.getIdentifier());
    else
        identifier = token.getIdentifier();
    gsasl_property_set(session, GSASL_PASSWORD, password.c_str());
    gsasl_property_set_raw(session, GSASL_AUTHID, identifier.c_str(), identifier.length());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());
    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
}

std::string SaslClient::evaluateChallenge(const std::string & challenge) {
    int rc;
    char * output = NULL;
    size_t outputSize;
    std::string retval;
    std::string copied_challenge = challenge;

    rc = gsasl_step(session, challenge.data(), challenge.size(), &output,
                    &outputSize);

    if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK) {
        retval.resize(outputSize);
        memcpy(retval.data(), output, outputSize);

        if (output) {
            free(output);
        }
    } else {
        if (output) {
            free(output);
        }

        THROW(AccessControlException, "Failed to evaluate challenge: %s", gsasl_strerror(rc));
    }

    if (rc == GSASL_OK) {
        complete = true;
    }

    return retval;
}

bool SaslClient::isComplete() {
    return complete;
}

}
}

