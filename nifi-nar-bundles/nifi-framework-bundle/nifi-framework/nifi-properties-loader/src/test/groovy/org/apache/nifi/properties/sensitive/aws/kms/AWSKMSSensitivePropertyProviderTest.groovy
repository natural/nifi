
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
package org.apache.nifi.properties.sensitive.aws.kms

import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider
import org.bouncycastle.util.encoders.Hex
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory



@RunWith(JUnit4.class)
class AWSKMSSensitivePropertyProviderTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(AWSKMSSensitivePropertyProviderTest.class)
    
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

    /**
     * This test is to ensure internal consistency and allow for encrypting value for various property files
     */
    @Test
    void testShouldEncryptArbitraryValues() {
    }

    /**
     * This test is to ensure external compatibility in case someone encodes the encrypted value with Base64 and does not remove the padding
     */
    @Test
    void testShouldDecryptPaddedValue() {
    }
}
