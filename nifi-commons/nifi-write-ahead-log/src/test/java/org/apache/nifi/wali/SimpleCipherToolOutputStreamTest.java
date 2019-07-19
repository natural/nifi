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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SimpleCipherToolOutputStreamTest {
    private static byte[] secret;
    private static SecretKey key;
    private static SecureRandom random;

    @BeforeClass
    public static void setUpClass() {
        random = new SecureRandom();
        secret = randomBytes(randomInt(1024*1024*10));
        key = new SecretKeySpec(randomBytes(32), "AES");
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testCipherOutputStream() throws IOException {
        ByteArrayOutputStream cipherByteOutputStream = new ByteArrayOutputStream();
        OutputStream stream = SimpleCipherOutputStream.wrapWithKey(cipherByteOutputStream, key);

        stream.write(secret);
        stream.close();

        byte[] cipherText = cipherByteOutputStream.toByteArray();
        ByteArrayInputStream cipherByteInputStream = new ByteArrayInputStream(cipherText);
        InputStream cipherInputStream = SimpleCipherInputStream.wrapWithKey(cipherByteInputStream, key);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        byte[] plainText = new byte[((SimpleCipherInputStream) cipherInputStream).cipher.getOutputSize(cipherText.length)];
        int len;
        while ((len = cipherInputStream.read(plainText, 0, plainText.length)) != -1) {
            buffer.write(plainText, 0, len);
        }

        Assert.assertArrayEquals(secret, buffer.toByteArray());
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