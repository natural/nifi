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

package org.apache.nifi.wali;

import org.junit.Before;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;


class AbstractSimpleCipherUtilTest {
    static SecureRandom random = new SecureRandom();
    final SecretKey[] cipherKeys = new SecretKey[4];

    byte[] secret;
    SecretKey cipherKey;

    @Before
    public void setupSecretAndKey() {
        secret = randomBytes(randomInt(1024*1024*10));
        cipherKey = new SecretKeySpec(randomBytes(32), "AES");

        cipherKeys[0] = null;
        cipherKeys[1] = new SecretKeySpec(randomBytes(32), "AES");
        cipherKeys[2] = new SecretKeySpec(randomBytes(16), "AES");
        cipherKeys[3] = null;
    }

    static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    static int randomInt(int size) {
        return random.nextInt(size);
    }
}
