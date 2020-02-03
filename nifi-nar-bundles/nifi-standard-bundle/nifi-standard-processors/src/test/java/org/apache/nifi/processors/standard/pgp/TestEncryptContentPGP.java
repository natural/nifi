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


import net.sf.saxon.serialize.charcode.CharacterSet;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processors.standard.EncryptContent;
import org.apache.nifi.security.util.KeyDerivationFunction;
import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.ECDHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.symmetric.PBEPBKDF2;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TestEncryptContentPGP {
    @Test
    public void testProcessorEncryptAndDecrypt() throws IOException {
        runProcessor(
                TestRunners.newTestRunner(new EncryptContentPGP()),
                EncryptContentPGP.REL_SUCCESS,
                EncryptContentPGP.REL_FAILURE,
                new HashMap<>(){{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.ENCRYPT_MODE);
                    put(EncryptContentPGP.PBE_PASS_PHRASE, "password123");
                }},
                new HashMap<>(){{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.DECRYPT_MODE);
                }});

        runProcessor(
                TestRunners.newTestRunner(new EncryptContentPGP()),
                EncryptContentPGP.REL_SUCCESS,
                EncryptContentPGP.REL_FAILURE,
                new HashMap<>(){{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.ENCRYPT_MODE);
                    put(EncryptContentPGP.PBE_PASS_PHRASE, "password123");
                    put(EncryptContentPGP.ENCRYPT_ENCODING, "1");
                }},
                new HashMap<>(){{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.DECRYPT_MODE);
                }});
    }

    @Test
    @Ignore
    public void testProcessorSignAndVerify() throws IOException {
        MockFlowFile ff = runProcessor(
                TestRunners.newTestRunner(new EncryptContentPGP()),
                EncryptContentPGP.REL_SUCCESS,
                EncryptContentPGP.REL_FAILURE,
                new HashMap<>() {{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.SIGN_MODE);
                    put(EncryptContentPGP.SECRET_KEYRING_FILE, "/tmp/test.key.priv");
                    put(EncryptContentPGP.SIGNATURE_ATTRIBUTE, "test.signature");
                }},
                new HashMap<>() {{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.VERIFY_MODE);
                    put(EncryptContentPGP.PUBLIC_KEYRING_FILE, "/tmp/test.key.pub");
                    put(EncryptContentPGP.SIGNATURE_ATTRIBUTE, "test.signature");
                }}
        );

        Assert.assertNotEquals("signature: ", "", ff.getAttribute("test.signature"));
    }

    @Test
    @Ignore
    public void testProcessorEncryptAndSignAndDecryptAndVerify() throws IOException {
        MockFlowFile ff = runProcessor(
                TestRunners.newTestRunner(new EncryptContentPGP()),
                EncryptContentPGP.REL_SUCCESS,
                EncryptContentPGP.REL_FAILURE,
                new HashMap<>() {{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.ENCRYPT_AND_SIGN_MODE);
                    put(EncryptContentPGP.PUBLIC_KEYRING_FILE, "/tmp/test.key.pub");
                    put(EncryptContentPGP.SECRET_KEYRING_FILE, "/tmp/test.key.priv");
                    put(EncryptContentPGP.SIGNATURE_ATTRIBUTE, "test.signature");
                }},
                new HashMap<>() {{
                    put(EncryptContentPGP.MODE, EncryptContentPGP.DECRYPT_AND_VERIFY_MODE);
                }}
        );
        String sigValue = ff.getAttribute("test.signature");
        Assert.assertNotNull(sigValue);
        Assert.assertNotEquals(sigValue, "");
    }

    @Test
    public void testDynamicEncryptionKeys() throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, IOException {
        KeyProvider[] providers = new KeyProvider[]{
                new TestKeyProvider(),
                new TestKeyProvider("no id", "no password")
        };

        for (KeyProvider provider : providers) {
            runEncryptAndDecrypt(provider);
            runSignAndVerify(provider);
        }
    }

    @Test
    public void testStaticEncryptionKeys() throws PGPException, IOException {
        KeyProvider[] providers = new KeyProvider[]{
                new StaticKeyMaterialProvider(
                        keyResource("rsa_sign_rsa_encrypt.pub"),
                        keyResource("rsa_sign_rsa_encrypt.priv")),

                new StaticKeyMaterialProvider(
                        keyResource("dsa_sign_elgamal_encrypt.pub"),
                        keyResource("dsa_sign_elgamal_encrypt.priv")),
        };

        EncryptContentPGP processor = new EncryptContentPGP();
        for (KeyProvider provider : providers) {
            runEncryptAndDecrypt(provider);
            // runSignAndVerify(provider);
        }
    }


    @Test
    public void testSigningKeysUsedAsEncryptionKeys() throws IOException, PGPException {
        boolean error = false;
        try {
                new StaticKeyMaterialProvider(
                        keyResource("dsa_sign_no_encrypt.pub"),
                        keyResource("dsa_sign_no_encrypt.priv"));


        } catch (final PGPException ignored) {
            error = StringUtils.containsIgnoreCase("could not load public key", ignored.getMessage());
        }
        Assert.assertTrue("DSA signing key will not load", error);

        // However, RSA signing keys are usable as encryption keys:
        KeyProvider provider = new StaticKeyMaterialProvider(
                keyResource("rsa_sign_no_encrypt.pub"),
                keyResource("rsa_sign_no_encrypt.priv"));

        EncryptContentPGP processor = new EncryptContentPGP();
        runEncryptAndDecrypt(provider);
        runSignAndVerify(provider);
    }

    @Test
    public void testMultiKeyFiles() throws IOException, PGPException {
        KeyProvider provider = new StaticKeyMaterialProvider(keyResource("many_keys.pub"), keyResource("many_keys.priv"));
        runEncryptAndDecrypt(provider);
        runSignAndVerify(provider);

        List<PGPPublicKey> publicKeys = StaticKeyMaterialProvider.getPublicKeys(keyResource("many_keys.pub"));
        Assert.assertTrue(publicKeys.size() > 3);

        List<PGPSecretKey> secretKeys = StaticKeyMaterialProvider.getSecretKeys(keyResource("many_keys.priv"));
        Assert.assertTrue(secretKeys.size() > 3);
    }

    @Test
    public void testSignAndVerify() throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException, OperatorCreationException {
        KeyProvider provider = new TestKeyProvider();
        runEncryptAndDecrypt(provider);
        runSignAndVerify(provider);

        provider = new StaticKeyMaterialProvider(keyResource("single_rsa.pub"), keyResource("single_rsa.priv"));
        runEncryptAndDecrypt(provider);
        runSignAndVerify(provider);

        //byte[] pass = Random.randomBytes(32);
        char[] pass = "open swordfish".toCharArray();
        //byte[] bass = "open swordfish".getBytes(Charset.defaultCharset());


        //runSignAndVerify_PBE(pass);
        //runSignAndVerify_PBE(pass);

    }

    // WANT
    @Ignore
    @Test
    public void testEncryptContentBenchmarks() throws IOException, InterruptedException {
        TestRunner testEnc = TestRunners.newTestRunner(new EncryptContent());

        ProcessorBenchmark.run(
                "EncryptContent/PBE",
                testEnc,
                EncryptContent.REL_SUCCESS,
                EncryptContent.REL_FAILURE,

                () -> {
                    return new HashMap<>() {{
                            put("PGP", new HashMap<>() {{
                                put(EncryptContent.ENCRYPTION_ALGORITHM, "PGP");
                            }});

                            put("PGP+armor", new HashMap<>() {{
                                put(EncryptContent.ENCRYPTION_ALGORITHM, "PGP_ASCII_ARMOR");
                            }});
                        }};
                },

                (TestRunner runner, Map<PropertyDescriptor, String> config) -> {
                    testEnc.setProperty(EncryptContent.PASSWORD, Random.randomBytes(32).toString());
                    testEnc.setProperty(EncryptContent.KEY_DERIVATION_FUNCTION, KeyDerivationFunction.NONE.name());
                    testEnc.setProperty(EncryptContent.PGP_SYMMETRIC_ENCRYPTION_CIPHER, "1");
                    testEnc.setProperty(EncryptContent.MODE, EncryptContent.ENCRYPT_MODE);
                    for (PropertyDescriptor prop : config.keySet()) {
                       testEnc.setProperty(prop, config.get(prop));
                    }
                },

                (TestRunner runner, Map<PropertyDescriptor, String> config) -> {
                    testEnc.setProperty(EncryptContent.MODE, EncryptContent.DECRYPT_MODE);
                }
        );

        TestRunner testPGP = TestRunners.newTestRunner(new EncryptContentPGP());
        ProcessorBenchmark.run(
                "EncryptContentPGP/PBE",
                testPGP,
                EncryptContentPGP.REL_SUCCESS,
                EncryptContentPGP.REL_FAILURE,

                () -> {
                    Map<String, Map<PropertyDescriptor, String>> configs = new HashMap<>();

                    for (AllowableValue allowableValue : EncryptContentPGP.ENCRYPT_ALGORITHM.getAllowableValues()) {
                        configs.put(allowableValue.getDisplayName(),
                                new HashMap<>() {{ put(EncryptContentPGP.ENCRYPT_ALGORITHM, allowableValue.getValue()); }});
                    }

                    return configs;
                },

                (TestRunner runner, Map<PropertyDescriptor, String> config) -> {
                    testPGP.setProperty(EncryptContentPGP.PBE_PASS_PHRASE, Random.randomBytes(32).toString());
                    testPGP.setProperty(EncryptContentPGP.MODE, EncryptContentPGP.ENCRYPT_MODE);
                    testPGP.setProperty(EncryptContentPGP.ENCRYPT_ENCODING, "0");

                    for (PropertyDescriptor key : config.keySet()) {
                        testPGP.setProperty(key, config.get(key));
                    }
                },

                (TestRunner runner, Map<PropertyDescriptor, String> config) -> {
                    testPGP.setProperty(EncryptContentPGP.MODE, EncryptContentPGP.DECRYPT_MODE);
                }
        );
    }

    private static void runEncryptAndDecrypt(KeyProvider keys) throws IOException, PGPException {
        byte[] plain = Random.randomBytes(32 + Random.randomInt(4096));
        InputStream plainInput = new ByteArrayInputStream(plain);
        ByteArrayOutputStream cipherOutput = new ByteArrayOutputStream();
        EncryptStreamSession enc = new PublicKeyEncryptKeySession(null, keys.getPublicKey(), PGPEncryptedData.BLOWFISH, true);

        EncryptStreamCallback.encrypt(plainInput, cipherOutput, enc);
        byte[] ciphered = cipherOutput.toByteArray();
        InputStream cipherInput = new ByteArrayInputStream(cipherOutput.toByteArray());
        ByteArrayOutputStream plainOutput = new ByteArrayOutputStream();
        DecryptStreamSession dec = new PrivateKeyDecryptStreamSession(null, keys.getPrivateKey());
        //PBEDecryptStreamSession dec = new PBEDecryptStreamSession(null, "abc".toCharArray());

        DecryptStreamCallback.decrypt(cipherInput, plainOutput, dec);
        byte[] deciphered = plainOutput.toByteArray();

        Assert.assertNotEquals(plain.length, ciphered.length);
        Assert.assertNotEquals(Hex.encodeHexString(plain), Hex.encodeHexString(ciphered));
        Assert.assertEquals(plain.length, deciphered.length);
        Assert.assertEquals(Hex.encodeHexString(plain), Hex.encodeHexString(deciphered));
    }

    private static void runSignAndVerify(KeyProvider keys) throws IOException, PGPException {
        byte[] plain = Random.randomBytes(32 + Random.randomInt(4096));
        InputStream plainInput = new ByteArrayInputStream(plain);
        ByteArrayOutputStream sigOutput = new ByteArrayOutputStream();
        SignStreamSession options = new SignStreamSession(keys.getPrivateKey(), PGPUtil.SHA256);
        OutputStream plainOut = new ByteArrayOutputStream();
        SignStreamCallback.sign(plainInput, plainOut, sigOutput, options);
        byte[] signature = sigOutput.toByteArray();
        VerifyStreamSession verifyOptions = new VerifyStreamSession(null, keys.getPublicKey(), new ByteArrayInputStream(signature));

        boolean verified = VerifyStreamCallback.verify(verifyOptions, new ByteArrayInputStream(plain), new ByteArrayOutputStream());
        Assert.assertNotEquals(Hex.encodeHexString(plain), Hex.encodeHexString(signature));
        Assert.assertTrue("Signature unverified: ", verified);
    }

    @Ignore
    private static void runSignAndVerify_PBE(char[] chars) throws IOException, PGPException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, OperatorCreationException {
        byte[] pass = "password".getBytes(Charset.defaultCharset());
        byte[] salt = Random.randomBytes(16);

        OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

        pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(chars),
                salt,
                100);
        String baseAlgorithm = "aes";
        int keySize = 256;
        int ivSize = 16;
        ParametersWithIV kps = (ParametersWithIV)pGen.generateDerivedParameters(keySize, ivSize);

        SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)kps.getParameters()).getKey(), baseAlgorithm);
        System.out.println("OK " + encKey.getAlgorithm());


        //
        // nKeyPair kpp = new KeyPair(publicObj, privateObj);
        // PGPKeyPair gpp = new JcaPGPKeyPair(1, new PGPKdfParameters(1, 1), kpp, new Date());
        // System.out.println("OK " + gpp.getKeyID());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        ECGenParameterSpec params = new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0");
        // ECParameterSpec params = new ECParameterSpec(curve, g, n, h);
        kpGen.initialize(params);
        KeyPair kp = kpGen.generateKeyPair();
        System.out.println("PUB: " + Hex.encodeHexString(kp.getPublic().getEncoded()));

        // byte[] salt = Random.randomBytes(16);
        SecretKeyFactory factoryBC = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
        AlgorithmIdentifier defaultPRF = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);
        KeySpec keyspecBC = new PBKDF2KeySpec(chars, salt, 10, 128, defaultPRF);
        SecretKey keyBC = factoryBC.generateSecret(keyspecBC);

        // SecretKey secret = new SecretKeySpec(keyBC.getEncoded(), "AES");
        // System.out.println(keyBC.getClass().getName());
        // System.out.println(Hex.encodeHexString(keyBC.getEncoded()));

//
//
//        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//        KeySpec keyspec = new PBEKeySpec("password".toCharArray(), salt, 1000, 128);
//        Key key = factory.generateSecret(keyspec);
//        System.out.println(key.getClass().getName());
//        System.out.println(Arrays.toString(key.getEncoded()));

//        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
//        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(("password").toCharArray()), salt, 1000);
//        KeyParameter params = (KeyParameter)generator.generateDerivedParameters(128);
//        System.out.println(Arrays.toString(params.getKey()));

//        byte[] salt = Random.randomBytes(16);
//        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//        KeySpec keyspec = new PBEKeySpec(chars, salt, 1000, 128);
//        // keyspec = new ScryptKeySpec(chars, salt, 10, 16, 10, 128);
//
//
//        SecretKey key = factory.generateSecret(keyspec);
//
//        System.out.println(key.getClass().getName());
//        System.out.println(Arrays.toString(key.getEncoded()));


        // DefaultJcaJceHelper helper = new DefaultJcaJceHelper();
        // PBEKeyEncryptionMethodGenerator generator = new BcPBEKeyEncryptionMethodGenerator(chars);
        // byte[] keyMaterial = generator.getKey(SymmetricKeyAlgorithmTags.BLOWFISH);
        // String algon = "Alg.Alias.AlgorithmParameters.1.2.840.113549.1.5.12"; //  -> PBKDF2";
        // KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        // KeyPairGenerator kf = helper.createKeyPairGenerator("RSA");

        // new PBEPBKDF2.PBKDF2withSHA224();
        //PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(keyMaterial);
        // KeySpec ks = new PBEKeySpec(chars);
        // char[] password, byte[] salt, int iterationCount, int keySize, AlgorithmIdentifier prf
//
//        byte[] salt = "abcd".getBytes(Charset.defaultCharset());
//        int iters = 1;
//        int ksize = 32;
//        AlgorithmIdentifier prf = null;
//        // PrivateKey key = kf.generatePrivate(new PBKDF2KeySpec(chars, salt, 1, 32, prf));
//
//        KeySpec ks = new PBKDF2KeySpec(chars, salt, iters, ksize, prf);
        // KeyPair kp = kf.generateKeyPair();
//        PrivateKey privateKey = kp.getPrivate(); // kf.generatePrivate(ks);
//        PublicKey publicKey =  kp.getPublic(); // kf.generatePublic(ks);

        JcaPGPKeyConverter rc = new JcaPGPKeyConverter();
        JcaPGPKeyPair x = new JcaPGPKeyPair(1, kp, new Date());
        // PGPPublicKey pgpPublicKey = rc.getPGPPublicKey(19, key, new Date());
        PGPPrivateKey priv = x.getPrivateKey(); // null ; // new JcaPGPPrivateKey(0, privateKey);
        PGPPublicKey pub = x.getPublicKey(); // null  ; //rc.getPGPPublicKey(1, publicKey, new Date()); //  (PGPPublicKey) publicKey;


        byte[] plain = Random.randomBytes(32 + Random.randomInt(4096));
        InputStream plainInput = new ByteArrayInputStream(plain);
        ByteArrayOutputStream sigOutput = new ByteArrayOutputStream();
        SignStreamSession options = new SignStreamSession(priv, PGPUtil.SHA256);
        OutputStream plainOut = new ByteArrayOutputStream();
        SignStreamCallback.sign(plainInput, plainOut, sigOutput, options);
        byte[] signature = sigOutput.toByteArray();

        VerifyStreamSession verifyOptions = new VerifyStreamSession(null, pub, new ByteArrayInputStream(signature));
        boolean verified = VerifyStreamCallback.verify(verifyOptions, new ByteArrayInputStream(plain), new ByteArrayOutputStream());
        Assert.assertNotEquals(Hex.encodeHexString(plain), Hex.encodeHexString(signature));
        Assert.assertTrue("Signature unverified: ", verified);


        // do it again
    }


    private static MockFlowFile runProcessor(TestRunner runner, Relationship success, Relationship failure, Map<PropertyDescriptor, String> forward, Map<PropertyDescriptor, String> reverse) throws IOException {
        byte[] body = Random.randomBytes(1024*1024);
        for (Map.Entry<PropertyDescriptor, String> property : forward.entrySet()) {
            runner.setProperty(property.getKey(), property.getValue());
        }
        runner.setThreadCount(1);
        runner.enqueue(body);
        runner.clearTransferState();
        runner.run(1);
        runner.assertAllFlowFilesTransferred(success, 1);
        Assert.assertEquals(runner.getFlowFilesForRelationship(failure).size(), 0);
        MockFlowFile flowFile = runner.getFlowFilesForRelationship(success).get(0);
        // todo:  intermediate check against new parameter "differentInBetween"
        runner.assertQueueEmpty();
        for (Map.Entry<PropertyDescriptor, String> property : reverse.entrySet()) {
            runner.setProperty(property.getKey(), property.getValue());
        }
        runner.enqueue(flowFile);
        runner.clearTransferState();
        runner.run(1);
        runner.assertAllFlowFilesTransferred(success, 1);
        Assert.assertEquals(runner.getFlowFilesForRelationship(failure).size(), 0);
        flowFile = runner.getFlowFilesForRelationship(success).get(0);
        flowFile.assertContentEquals(body);
        // System.out.println("Decrypted: " + Hex.encodeHexString(Arrays.copyOf(flowFile.toByteArray(), 32)));
        // System.out.println("Original : " + Hex.encodeHexString(Arrays.copyOf(body, 32)));
        return flowFile;
    }

    private InputStream keyResource(String name) {
        Class<? extends TestEncryptContentPGP> cls = this.getClass();
        return cls.getResourceAsStream("/" + cls.getSimpleName() +  "/" + name);
    }
}
