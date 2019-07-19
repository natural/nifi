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

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SimpleCipherInputStreamTest extends AbstractSimpleCipherTest {
    @Test
    public void testCipherInputStream() throws IOException {
        // This shows we can use a variety of keys (some null) with the stream wrapper
        // and the output will always be the same as the input.
        for (SecretKey cipherKey : cipherKeys) {
            ByteArrayOutputStream cipherByteOutputStream = new ByteArrayOutputStream();
            OutputStream stream = SimpleCipherOutputStream.wrapWithKey(cipherByteOutputStream, cipherKey);

            stream.write(secret);
            stream.close();

            byte[] cipherText = cipherByteOutputStream.toByteArray();
            ByteArrayInputStream cipherByteInputStream = new ByteArrayInputStream(cipherText);
            InputStream cipherInputStream = SimpleCipherInputStream.wrapWithKey(cipherByteInputStream, cipherKey);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            byte[] plainText = new byte[secret.length*2];
            int len;
            while ((len = cipherInputStream.read(plainText, 0, plainText.length)) != -1) {
                buffer.write(plainText, 0, len);
            }

            Assert.assertArrayEquals(secret, buffer.toByteArray());
        }
    }

    @Test
    public void testCipherInputStreamTampering() throws IOException {
        SecretKey key = cipherKeys[1];
        byte[] secret = randomBytes(4096); // smaller secret for this test

        ByteArrayOutputStream cipherByteOutputStream = new ByteArrayOutputStream();
        OutputStream stream = SimpleCipherOutputStream.wrapWithKey(cipherByteOutputStream, key);

        stream.write(secret);
        stream.close();

        byte[] cipherText = cipherByteOutputStream.toByteArray();
        int fails = 0;

        // This shows we can randomly tamper with (change) any single byte (except the first) and the result is that
        // the cipher will throw an exception during decryption:
        for (int i = 1; i < cipherText.length; i++) {
            byte[] cipherCopy = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, cipherCopy, 0, cipherText.length);

            // tamper with the byte:
            cipherCopy[i] += 1 + random.nextInt(253);

            ByteArrayInputStream cipherByteInputStream = new ByteArrayInputStream(cipherCopy);
            InputStream cipherInputStream = SimpleCipherInputStream.wrapWithKey(cipherByteInputStream, key);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            byte[] plainText = new byte[secret.length*2];
            int len;

            try {
                while ((len = cipherInputStream.read(plainText, 0, plainText.length)) != -1) {
                    buffer.write(plainText, 0, len);
                }
            } catch (final Exception ignored) {
                fails += 1;
            }
        }

        // This shows we failed on every iteration (and skipped the first byte):
        Assert.assertEquals(fails, cipherText.length-1);
    }
}
