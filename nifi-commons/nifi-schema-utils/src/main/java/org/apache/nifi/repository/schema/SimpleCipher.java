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
package org.apache.nifi.repository.schema;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;

public class SimpleCipher {
    private static final String CIPHER_NAME = "AES/GCM/NoPadding";
    private static final String CIPHER_NAME_SHORT = "AES";
    private static final String CIPHER_PROVIDER = "BC";
    private static final int CIPHER_AUTH_TAG_LENGTH = 128;
    private SecretKey key;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SimpleCipher(SecretKey key) {
        this.key = key;
    }

    public static SimpleCipher fromKey(byte[] keyMaterial) throws IOException {
        return new SimpleCipher(new SecretKeySpec(keyMaterial, CIPHER_NAME_SHORT));
    }

    public static SimpleCipher fromKey(String keyMaterial) throws IOException {
        // hex first
        try {
            return SimpleCipher.fromKey(Hex.decode(keyMaterial));
        } catch (org.bouncycastle.util.encoders.DecoderException ignored) {
        }

        // base64 next
        try {
            return SimpleCipher.fromKey(Base64.decode(keyMaterial));
        } catch (org.bouncycastle.util.encoders.DecoderException ignored) {
        }

        // plain string (least likely) last
        return SimpleCipher.fromKey(keyMaterial.getBytes());
    }

    private GCMParameterSpec makeIV() {
        SecureRandom random = new SecureRandom();
        byte[] ivs = new byte[12];
        random.nextBytes(ivs);
        return new GCMParameterSpec(CIPHER_AUTH_TAG_LENGTH, ivs);
    }

    private Cipher makeCipher(int mode, GCMParameterSpec iv) throws IOException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER_NAME, CIPHER_PROVIDER);
            cipher.init(mode, key, iv);
            // if (associatedData != null) {
            //    cipher.updateAAD(associatedData);
            // }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new IOException(e);
        }
        return cipher;
    }

    public byte[] encrypt(byte[] plainText) throws IOException {
        GCMParameterSpec iv = makeIV();
        Cipher cipher = makeCipher(Cipher.ENCRYPT_MODE, iv);
        byte[] cipherText;

        try {
            cipherText = cipher.doFinal(plainText);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException(e);
        }
        byte[] ivBytes = iv.getIV();
        ByteBuffer output = ByteBuffer.allocate(4 + ivBytes.length + cipherText.length);

        output.putInt(ivBytes.length);
        output.put(ivBytes);
        output.put(cipherText);

        return output.array();
    }

    public byte[] decrypt(byte[] cipherText) throws IOException {
        ByteBuffer input = ByteBuffer.wrap(cipherText);
        int ivLength = input.getInt();
        if (ivLength != 12 && ivLength != 16) {
            throw new IllegalArgumentException("Invalid IV length.");
        }

        byte[] ivSource = new byte[ivLength];
        input.get(ivSource);

        byte[] remaining = new byte[input.remaining()];
        input.get(remaining);

        Cipher cipher = makeCipher(Cipher.DECRYPT_MODE, new GCMParameterSpec(CIPHER_AUTH_TAG_LENGTH, ivSource));

        try {
            return cipher.doFinal(remaining);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException(e);
        }
    }
}
