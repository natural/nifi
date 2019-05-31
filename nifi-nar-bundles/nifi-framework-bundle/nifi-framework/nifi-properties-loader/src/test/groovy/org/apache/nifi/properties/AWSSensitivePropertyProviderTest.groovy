/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.properties

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.DecoderException
import org.bouncycastle.util.encoders.Hex
import org.junit.*
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.Security

@RunWith(JUnit4.class)
class AWSSensitivePropertyProviderTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(AWSSensitivePropertyProviderTest.class)

    private static final Base64.Encoder encoder = Base64.encoder
    private static final Base64.Decoder decoder = Base64.decoder
    
    private SensitivePropertyProvider propProvider

    
    @BeforeClass
    static void setUpOnce() throws Exception {
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
        propProvider = null
    }

    @Test
    void testShouldProtectValue() throws Exception {
        // com.amazonaws.SdkClientException
        // com.amazonaws.services.kms.model.NotFoundException:
        // com.amazonaws.services.kms.model.InvalidCiphertextException

        def keyIds = [
            "arn:aws:kms:us-east-2:607563158743:key/bd05545c-da2c-4ac2-944e-947b989aa7ef",
            "alias/aws-at-troy-io-cmk-alias-000",
            "bd05545c-da2c-4ac2-944e-947b989aa7ef"
        ]

        String plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
        
        keyIds.each { k ->
            propProvider = new AWSSensitivePropertyProvider(k)
            assert propProvider != null
            assert plainText == propProvider.unprotect(propProvider.protect(plainText))
        }
    }

    @Test
    void testShouldHandleProtectEmptyValue() throws Exception {
    }

    @Test
    void testShouldUnprotectValue() throws Exception {
    }

    @Test
    void testShouldHandleUnprotectEmptyValue() throws Exception {
    }

    @Test
    void testShouldUnprotectValueWithWhitespace() throws Exception {
    }

    @Test
    void testShouldHandleUnprotectMalformedValue() throws Exception {
    }

    @Test
    void testShouldNotAllowEmptyKey() throws Exception {
    }

    @Test
    void testShouldNotAllowIncorrectlySizedKey() throws Exception {
    }

    @Test
    void testShouldNotAllowInvalidKey() throws Exception {
    }

    /**
     * This test is to ensure internal consistency and allow for encrypting value for various property files
     */
    @Test
    void testShouldEncryptArbitraryValues() {
        // Arrange
        def values = ["thisIsABadPassword", "thisIsABadSensitiveKeyPassword", "thisIsABadKeystorePassword", "thisIsABadKeyPassword", "thisIsABadTruststorePassword", "This is an encrypted banner message", "nififtw!"]

        String key = "2C576A9585DB862F5ECBEE5B4FFFCCA1" //getKeyOfSize(128)
        // key = "0" * 64

        // SensitivePropertyProvider spp = new AWSSensitivePropertyProvider(key)

        // // Act
        // def encryptedValues = values.collect { String v ->
        //     def encryptedValue = spp.protect(v)
        //     logger.info("${v} -> ${encryptedValue}")
        //     def (String iv, String cipherText) = encryptedValue.tokenize("||")
        //     logger.info("Normal Base64 encoding would be ${encoder.encodeToString(decoder.decode(iv))}||${encoder.encodeToString(decoder.decode(cipherText))}")
        //     encryptedValue
        // }

        // // Assert
        // assert values == encryptedValues.collect { spp.unprotect(it) }
    }

    /**
     * This test is to ensure external compatibility in case someone encodes the encrypted value with Base64 and does not remove the padding
     */
    @Test
    void testShouldDecryptPaddedValue() {
    }
}
