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
package org.apache.nifi.security.util;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;


public class CipherUtils {
    final static SecureRandom random = new SecureRandom();
    public final static int IV_LENGTH = 12;

    /**
     * Generates a new random IV of 12 bytes using {@link java.security.SecureRandom}.
     *
     * @return the IV
     */
    public static byte[] generateIV() {
        byte[] bytes = new byte[IV_LENGTH];
        random.nextBytes(bytes);
        return bytes;
    }


    public static byte[] zeroIV() {
        byte[] bytes = new byte[IV_LENGTH];
        Arrays.fill(bytes, (byte) 0);
        return bytes;
    }


    public static Cipher blockCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        return Cipher.getInstance("AES/GCM/NoPadding", "BC");
    }

    public static String getRandomHex(int size) {
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return Hex.toHexString(bytes);
    }

    public static int getRandomInt(int lower, int upper) {
        int value = random.nextInt(upper);
        while (value < lower) {
            value = random.nextInt(upper);
        }
        return value;
    }
}
