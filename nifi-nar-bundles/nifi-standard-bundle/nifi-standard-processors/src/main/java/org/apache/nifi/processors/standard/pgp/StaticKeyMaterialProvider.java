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
package org.apache.nifi.processors.standard.pgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

// holds a reference to static (string) key material
class StaticKeyMaterialProvider extends AbstractKeyProvider {
    public StaticKeyMaterialProvider(File publicKey, File privateKey) throws IOException, PGPException {
        this(publicKey, privateKey, "");
    }

    public StaticKeyMaterialProvider(File publicKey, File privateKey, String passphrase) throws IOException, PGPException {
        this(new String(Files.readAllBytes(publicKey.toPath()), Charset.defaultCharset()), new String(Files.readAllBytes(privateKey.toPath()), Charset.defaultCharset()), passphrase);
    }

    public StaticKeyMaterialProvider(String publicKeySource, String privateKeySource) throws PGPException, IOException {
        this(publicKeySource, privateKeySource, "");
    }

    public StaticKeyMaterialProvider(String publicKeySource, String privateKeySource, String passphrase) throws PGPException, IOException {
        this(new ByteArrayInputStream(publicKeySource.getBytes()), new ByteArrayInputStream(privateKeySource.getBytes()), passphrase);
    }

    public StaticKeyMaterialProvider(InputStream publicKeyIn, InputStream privateKeyIn) throws IOException, PGPException {
        this(publicKeyIn, privateKeyIn, "");
    }

    public StaticKeyMaterialProvider(InputStream publicKeyIn, InputStream privateKeyIn, String passphrase) throws IOException, PGPException {
        PGPPublicKey publicKey = readPublicKey(publicKeyIn);
        if (publicKey == null)
            throw new PGPException("could not load public key");

        PGPPrivateKey privateKey = readPrivateKey(privateKeyIn, 0, passphrase.toCharArray());
        if (privateKey == null)
            throw new PGPException("could not load private key");

        PGPDigestCalculator checksumCalc = null;
        PGPSecretKey secretKey = new PGPSecretKey(privateKey, publicKey, checksumCalc, false, null);
        init(publicKey, secretKey, privateKey);
    }


    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        JcaPGPPublicKeyRingCollection rings = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        Iterator<PGPPublicKeyRing> ringWalker = rings.iterator();

        while (ringWalker.hasNext()) {
            PGPPublicKeyRing ring = ringWalker.next();
            Iterator<PGPPublicKey> keyWalker = ring.iterator();
            while (keyWalker.hasNext()) {
                PGPPublicKey key = keyWalker.next();
                if (key.isEncryptionKey())
                    return key;
            }
        }
        return null;
    }

    static PGPPrivateKey readPrivateKey(InputStream in, long keyId, char[] passphrase) throws IOException, PGPException {
        PGPSecretKeyRingCollection rings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());
        Iterator<PGPSecretKeyRing> ringWalker = rings.iterator();

        while (ringWalker.hasNext()) {
            PGPSecretKeyRing keyRing = ringWalker.next();
            Iterator<PGPSecretKey> keyWalker = keyRing.iterator();
            while (keyWalker.hasNext()) {
                PGPSecretKey key = keyWalker.next();
                if (key != null && !key.isPrivateKeyEmpty() && key.getKeyID() == (keyId != 0 ? keyId : key.getKeyID())) {
                    PBESecretKeyDecryptor dec = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase);
                    try {
                        return key.extractPrivateKey(dec);
                    } catch (final PGPException ignored) {
                        // pass
                    }
                }
            }
        }
        return null;
    }

    static public List<PGPPublicKey> getPublicKeys(InputStream in) {
        List<PGPPublicKey> keys = new ArrayList<>();
        JcaPGPPublicKeyRingCollection rings;


        try {
            rings = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        } catch (final IOException | PGPException ignored) {
            return null;
        }

        for (PGPPublicKeyRing ring : rings) {
            for (PGPPublicKey key : ring) {
                keys.add(key);
            }
        }

        return keys;
    }


    public static List<PGPSecretKey> getSecretKeys(InputStream in) {
        List<PGPSecretKey> keys = new ArrayList<>();
        KeyFingerPrintCalculator calc = new BcKeyFingerprintCalculator();
        PGPSecretKeyRingCollection rings;

        try {
            rings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), calc);
        } catch (final IOException | PGPException ignored) {
            return null;
        }

        for (PGPSecretKeyRing ring : rings) {
            for (PGPSecretKey secretKey : ring) {
                keys.add(secretKey);
            }
        }
        return keys;
    }


    static public PGPPublicKey getPublicKeyFromUser(List<PGPPublicKey> keys, String userID) {
        for (PGPPublicKey key : keys) {
            Iterator<String> ids = key.getUserIDs();
            while (ids.hasNext()) {
                String id = ids.next();
                if (id.equals(userID)) {
                    return key;
                }
            }
        }
        return null;
    }

    static public PGPSecretKey getSecretKeyFromUser(List<PGPSecretKey> keys, String userID) {
        for (PGPSecretKey key : keys) {
            Iterator<String> ids = key.getUserIDs();
            while (ids.hasNext()) {
                String id = ids.next();
                if (userID == null || userID.equals("") || id.equals(userID))
                    return key;
            }
        }
        return null;
    }

    public static PGPPublicKey getPublicKeyFromId(List<PGPPublicKey> keys, long keyID) {
        for (PGPPublicKey key : keys) {
            if (key.getKeyID() == keyID) {
                return key;
            }
        }
        return null;
    }

    public static PGPSecretKey getSecretKeyFromId(List<PGPSecretKey> keys, long keyID) {
        for (PGPSecretKey key : keys) {
            if (key.getKeyID() == keyID) {
                return key;
            }
        }
        return null;
    }
}
