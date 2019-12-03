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

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;


public interface KeyProvider {
    PGPPublicKey getPublicKey();
    PGPSecretKey getSecretKey();
    PGPPrivateKey getPrivateKey();
}


class AbstractKeyProvider implements KeyProvider {
    PGPPublicKey publicKey;
    PGPSecretKey secretKey;
    PGPPrivateKey privateKey;

    void init(PGPPublicKey publicKey, PGPSecretKey secretKey, PGPPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
    }

    @Override
    public PGPPublicKey getPublicKey() {
        return publicKey;
    }
    
    @Override
    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public PGPPrivateKey getPrivateKey() {
        return privateKey;
    }
}


// generates key material dynamically as needed, e.g., for testing
class TestKeyProvider extends AbstractKeyProvider {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    TestKeyProvider() throws NoSuchAlgorithmException, NoSuchProviderException, PGPException {
        this("", "");
    }

    TestKeyProvider(String identity, String passphrase) throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        final KeyPair keyPair = createKeyPair();
        PGPSecretKey secretKey = createSecretKey(keyPair, identity, passphrase.toCharArray());
        PGPPrivateKey privateKey = extractPrivateKey(secretKey, passphrase.toCharArray());
        PGPPublicKey publicKey = secretKey.getPublicKey();
        init(publicKey, secretKey, privateKey);
    }

    private static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    private static PGPSecretKey createSecretKey(KeyPair keyPair, String identity, char[] passphrase) throws PGPException {
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair pair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

        return new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                pair,
                identity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(pair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passphrase));
    }

    private static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, char[] passphrase) throws PGPException {
        return secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
    }
}


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

        init(publicKey, null, privateKey);
    }

    static public List<PGPPublicKey> getPublicKeys(InputStream in) {
        List<PGPPublicKey> map = new ArrayList<>();
        JcaPGPPublicKeyRingCollection rings;


        try {
            rings = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        } catch (final IOException | PGPException ignored) {
            return null;
        }

        for (PGPPublicKeyRing ring : rings) {
            for (PGPPublicKey key : ring) {
                map.add(key);
            }
        }

        return map;
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
                    } catch (final PGPException ignored){
                        // pass
                    }
                }
            }
        }
        return null;
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
}

