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
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.junit.runners.JUnit4

import java.security.Security

@RunWith(JUnit4.class)
class StandardSensitivePropertyProviderTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(StandardSensitivePropertyProviderTest.class)

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        // setupTmpDir()
    }

    @AfterClass
    static void tearDownOnce() throws Exception {
        // File tmpDir = new File("target/tmp/")
        // tmpDir.delete()
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
        // TestAppender.reset()
    }

    @Test
    void testSomethingBasicWorksLikeYouLike() throws Exception {
        // StandardSensitivePropertyProvider sp = StandardSensitivePropertyProvider.fromAnyValue("any old value will do")
        // assert sp.getName() == "AES Sensitive Property Provider"

        assert 1 == 1

    }

}
