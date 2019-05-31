
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

import org.bouncycastle.util.encoders.Hex
import org.junit.*
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.SecureRandom


@RunWith(JUnit4.class)
class AWSSensitivePropertyProviderTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(AWSSensitivePropertyProviderTest.class)
    
    private static final Base64.Encoder encoder = Base64.encoder
    private static final Base64.Decoder decoder = Base64.decoder
    
    private final String[] knownGoodKeys = [
            "arn:aws:kms:us-east-2:607563158743:key/bd05545c-da2c-4ac2-944e-947b989aa7ef",
            "alias/aws-at-troy-io-cmk-alias-000",
            "bd05545c-da2c-4ac2-944e-947b989aa7ef"
    ]
    
    @BeforeClass
    static void setUpOnce() throws Exception {
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
    }

    @Test
    void testShouldThrowExceptionsWithBadKeys() throws Exception {
        SensitivePropertyProvider propProvider
        String msg
        
        msg = shouldFail(SensitivePropertyProtectionException) {
            propProvider = new AWSSensitivePropertyProvider("")
        }
        
        assert msg =~ "The key cannot be empty"
        assert propProvider == null

        def badKeyExceptions = [com.amazonaws.SdkClientException,
                                com.amazonaws.services.kms.model.NotFoundException]

        badKeyExceptions.each { exc -> 
            msg = shouldFail(exc) {
                propProvider = new AWSSensitivePropertyProvider("bad key")
                propProvider.protect("value")
            }
            assert propProvider != null
            assert msg =~ "Invalid keyId"
        }
    }
    
    @Test
    void testShouldProtectAndUnprotectValues() throws Exception {
        // com.amazonaws.services.kms.model.InvalidCiphertextException
        SensitivePropertyProvider propProvider
        String plainText;
        
        knownGoodKeys.each { k ->
            propProvider = new AWSSensitivePropertyProvider(k)
            assert propProvider != null

            byte[] randBytes = new byte[32]
            new SecureRandom().nextBytes(randBytes)
            plainText = Hex.toHexString(randBytes)
                
            assert plainText != null
            assert plainText != ""
            
            assert plainText == propProvider.unprotect(propProvider.protect(plainText))
        }
    }

    @Test
    void testShouldHandleProtectEmptyValue() throws Exception {
        SensitivePropertyProvider propProvider
        final List<String> EMPTY_PLAINTEXTS = ["", "    ", null]
        
        knownGoodKeys.each { k ->
            propProvider = new AWSSensitivePropertyProvider(k)
            assert propProvider != null

            EMPTY_PLAINTEXTS.each { String emptyPlaintext ->
                def msg = shouldFail(IllegalArgumentException) {
                    propProvider.protect(emptyPlaintext)
                }
                assert msg == "Cannot encrypt an empty value"
            }
        }
    }

    @Test
    void testShouldUnprotectValue() throws Exception {
        SensitivePropertyProvider propProvider
        final List<String> BAD_CIPHERTEXTS = ["any", "bad", "value"]
        
        knownGoodKeys.each { k ->
            propProvider = new AWSSensitivePropertyProvider(k)
            assert propProvider != null

            BAD_CIPHERTEXTS.each { String emptyPlaintext ->
                def msg = shouldFail(org.bouncycastle.util.encoders.DecoderException) {
                    propProvider.unprotect(emptyPlaintext)
                }
                assert msg != null
            }
        }
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
    void testShouldNotAllowInvalidKey() throws Exception {
    }

    /**
     * This test is to ensure internal consistency and allow for encrypting value for various property files
     */
    @Test
    void testShouldEncryptArbitraryValues() {
        // Arrange
        def values = ["thisIsABadPassword", "thisIsABadSensitiveKeyPassword", "thisIsABadKeystorePassword", "thisIsABadKeyPassword", "thisIsABadTruststorePassword", "This is an encrypted banner message", "nififtw!"]

        knownGoodKeys.each { k ->
            SensitivePropertyProvider propProvider = new AWSSensitivePropertyProvider(k)
            assert propProvider != null

            // Act
            def encryptedValues = values.collect { String v ->
                propProvider.protect(v)
            }
            assert values == encryptedValues.collect { propProvider.unprotect(it) }
        }
    }

    /**
     * This test is to ensure external compatibility in case someone encodes the encrypted value with Base64 and does not remove the padding
     */
    @Test
    void testShouldDecryptPaddedValue() {
    }
}
