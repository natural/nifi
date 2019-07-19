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
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.Security;


public class SimpleCipherTool {
    private static final int IV_BYTES = 12;
    private static final int MAC_BYTES = 8;
    private static final int AAD_BYTES = 20;

    private SecretKey key;
    private SecureRandom random = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SimpleCipherTool(SecretKey key) {
        this.key = key;
    }

    public static SimpleCipherTool fromKey(byte[] keyMaterial) {
        return new SimpleCipherTool(new SecretKeySpec(keyMaterial, "AES"));
    }

    public static SimpleCipherTool fromKey(String keyMaterial) {
        // hex first
        try {
            return SimpleCipherTool.fromKey(Hex.decode(keyMaterial));
        } catch (org.bouncycastle.util.encoders.DecoderException ignored) {
        }

        // base64 next
        try {
            return SimpleCipherTool.fromKey(Base64.decode(keyMaterial));
        } catch (org.bouncycastle.util.encoders.DecoderException ignored) {
        }

        // plain string (least likely) last
        return SimpleCipherTool.fromKey(keyMaterial.getBytes());
    }

    public byte[] encrypt(byte[] plainText) throws IOException {
        final byte[] iv = randomBytes(IV_BYTES);
        final byte[] aad = randomBytes(AAD_BYTES);
        final AEADBlockCipher cipher = initCipher(true, iv, aad);

        return concat(iv, aad, process(cipher, plainText));
    }

    public byte[] decrypt(byte[] cipherBytes) throws IOException {
        final byte[] iv = slice(cipherBytes, 0, IV_BYTES);
        final byte[] aad = slice(cipherBytes, IV_BYTES, IV_BYTES + AAD_BYTES);
        final byte[] cipherText = slice(cipherBytes, IV_BYTES + AAD_BYTES, cipherBytes.length);
        final AEADBlockCipher cipher = initCipher(false, iv, aad);

        return process(cipher, cipherText);
    }

    private byte[] process(AEADBlockCipher cipher, byte[] input) throws IOException {
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int processed = cipher.processBytes(input, 0, input.length, output, 0); // processBytes updates the mac

        try {
            processed += cipher.doFinal(output, processed); // doFinal writes/verifies the mac
        } catch (InvalidCipherTextException e) {
            throw new IOException("Cipher processing failure", e);
        }

        if (processed == output.length) {
            return output;
        }
        return slice(output, 0, processed);
    }

    public AEADBlockCipher initCipher(boolean encrypt, byte[] iv, byte[] aad) {
        final AEADBlockCipher cipher = new EAXBlockCipher(new AESEngine());
        final AEADParameters param = new AEADParameters(new KeyParameter(key.getEncoded()),MAC_BYTES *8, iv, aad);
        cipher.init(encrypt, param);
        return cipher;
    }



    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        int position = 0;

        for (byte[] a : arrays) {
            len += a.length;
        }

        byte[] output = new byte[len];

        for (byte[] a : arrays) {
            System.arraycopy(a, 0, output, position, a.length);
            position += a.length;
        }

        return output;
    }

    private static byte[] slice(byte[] bytes, int start, int finish) {
        byte[] slice = new byte[finish - start];
        System.arraycopy(bytes, start, slice, 0, finish - start);
        return slice;
    }

    byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }
}
