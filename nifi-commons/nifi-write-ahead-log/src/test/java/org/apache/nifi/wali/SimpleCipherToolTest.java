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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


public class SimpleCipherToolTest {
    static final Logger logger = LoggerFactory.getLogger(SimpleCipherToolTest.class);
    private static SecureRandom random;

    @BeforeClass
    public static void setUpOnce() {
        random = new SecureRandom();
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }


    @Test
    public void testCipherTool() throws IOException {
        Set<Integer> sizes = new HashSet<>();
        sizes.add(16);
        sizes.add(32);
        sizes.forEach(size -> {
            try {
                // this shows we can use a hex-encoded string as a key
                SimpleCipherTool cipher = SimpleCipherTool.fromKey(randomHex(size));
                testEncryptDecrypt(cipher);

                // this shows we can use a base64-encoded string as a key
                cipher = SimpleCipherTool.fromKey(randomBase64(size));
                testEncryptDecrypt(cipher);

                // this shows we can use a byte array as a key:
                cipher = SimpleCipherTool.fromKey(randomBytes(size));
                testEncryptDecrypt(cipher);

                // this shows we can use some regular strings as keys:
                cipher = SimpleCipherTool.fromKey(randomString(size));
                testEncryptDecrypt(cipher);
            } catch (final IOException | InvalidCipherTextException e) {
                throw new AssertionError("Encryption Test Failure", e);
            }
        });
    }

    private void testEncryptDecrypt(SimpleCipherTool simpleCipherTool) throws IOException, InvalidCipherTextException {
        // this shows we can encrypt and decrypt data
        final byte[] plainText = randomBytes(randomInt(1024*1024));
        final byte[] cipherText = simpleCipherTool.encrypt(plainText);

        Assert.assertTrue(cipherText.length > 0);
        Assert.assertFalse(Arrays.equals(plainText, cipherText));
        Assert.assertArrayEquals(plainText, simpleCipherTool.decrypt(cipherText));
    }

    private String randomHex(int size) {
        return Hex.toHexString(randomBytes(size));
    }

    private String randomBase64(int size) {
        return Base64.toBase64String(randomBytes(size));
    }

    static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    static int randomInt(int size) {
        return random.nextInt(size);
    }

    private String randomString(int size) {
        final String base = "this is password";
        return base;
    }

}
