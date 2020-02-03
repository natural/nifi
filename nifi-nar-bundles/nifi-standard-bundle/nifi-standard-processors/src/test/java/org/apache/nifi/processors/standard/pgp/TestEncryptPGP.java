package org.apache.nifi.processors.standard.pgp;

import org.apache.calcite.util.Static;
import org.apache.commons.codec.binary.Hex;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;


public class TestEncryptPGP {
    private static final String SERVICE_ID = "pgp-key-service";

    @BeforeClass
    public static void setupServiceControllerTestClass() throws IOException {
        PGPKeyMaterialControllerServiceTest.setupKeyAndKeyRings();
    }

    @Test
    public void testSomeBasicEncryptAndDecrypt() throws InitializationException {
        String algo = "7";

        // Basic encryption via an encryption processor configured with a key material service:
        TestRunner runner = TestRunners.newTestRunner(new EncryptPGP());
        runner.setProperty(EncryptPGP.ENCRYPT_ALGORITHM, algo);
        runner.setProperty(EncryptPGP.PGP_KEY_SERVICE, SERVICE_ID);

        PGPKeyMaterialControllerService service = new PGPKeyMaterialControllerService();
        runner.addControllerService(SERVICE_ID, service, new HashMap<>() {{
            put(PGPKeyMaterialControllerService.PUBLIC_KEYRING_TEXT.getName(), PGPKeyMaterialControllerServiceTest.onePublicKeyRaw);
        }});
        runner.assertValid(service);
        runner.enableControllerService(service);

        String plainText = "hello, pgp encrypt.";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        runner.enqueue(plainBytes);
        runner.clearTransferState();
        runner.run();
        runner.assertAllFlowFilesTransferred(EncryptPGP.REL_SUCCESS, 1);

        List<MockFlowFile> flows = runner.getFlowFilesForRelationship(EncryptPGP.REL_SUCCESS);
        Assert.assertEquals(1, flows.size());
        byte[] cipherBytes = flows.get(0).toByteArray();
        Assert.assertNotEquals(Hex.encodeHex(cipherBytes), Hex.encodeHex(plainBytes));

        // decrypt via a decryption processor configured with a new key material service:
        runner = TestRunners.newTestRunner(new DecryptPGP());
        runner.setProperty(EncryptPGP.PGP_KEY_SERVICE, SERVICE_ID);
        service = new PGPKeyMaterialControllerService();
        runner.addControllerService(SERVICE_ID, service, new HashMap<>() {{
            put(PGPKeyMaterialControllerService.SECRET_KEYRING_TEXT.getName(), PGPKeyMaterialControllerServiceTest.oneSecretKeyRaw);
            put(PGPKeyMaterialControllerService.PRIVATE_KEY_PASS_PHRASE.getName(), PGPKeyMaterialControllerServiceTest.CORRECT_PASSWORD);
        }});
        runner.assertValid(service);
        runner.enableControllerService(service);
        runner.enqueue(cipherBytes);
        runner.clearTransferState();
        runner.run();
        runner.assertAllFlowFilesTransferred(DecryptPGP.REL_SUCCESS, 1);

        flows = runner.getFlowFilesForRelationship(DecryptPGP.REL_SUCCESS);
        Assert.assertEquals(1, flows.size());
        Assert.assertArrayEquals(flows.get(0).toByteArray(), plainBytes);


        // Basic signing via a signing processor configured with a key material service:
        runner = TestRunners.newTestRunner(new SignPGP());
        runner.setProperty(SignPGP.SIGNATURE_HASH_ALGORITHM, "8"); // sha256
        runner.setProperty(SignPGP.PGP_KEY_SERVICE, SERVICE_ID);

        service = new PGPKeyMaterialControllerService();
        runner.addControllerService(SERVICE_ID, service, new HashMap<>() {{
            put(PGPKeyMaterialControllerService.SECRET_KEYRING_TEXT.getName(), PGPKeyMaterialControllerServiceTest.oneSecretKeyRaw);
            put(PGPKeyMaterialControllerService.PRIVATE_KEY_PASS_PHRASE.getName(), PGPKeyMaterialControllerServiceTest.CORRECT_PASSWORD);
        }});
        runner.enableControllerService(service);
        runner.enqueue(plainBytes);
        runner.clearTransferState();
        runner.run();
        runner.assertAllFlowFilesTransferred(SignPGP.REL_SUCCESS, 1);

        flows = runner.getFlowFilesForRelationship(SignPGP.REL_SUCCESS);
        Assert.assertEquals(1, flows.size());

        MockFlowFile flow = flows.get(0);
        String sigValue = flow.getAttribute(AbstractProcessorPGP.DEFAULT_SIGNATURE_ATTRIBUTE);
        Assert.assertNotNull(sigValue);
        Assert.assertNotEquals(sigValue, "");


        runner = TestRunners.newTestRunner(new VerifyPGP());
        runner.setProperty(VerifyPGP.PGP_KEY_SERVICE, SERVICE_ID);
        service = new PGPKeyMaterialControllerService();
        runner.addControllerService(SERVICE_ID, service, new HashMap<>() {{
            put(PGPKeyMaterialControllerService.PUBLIC_KEYRING_TEXT.getName(), PGPKeyMaterialControllerServiceTest.onePublicKeyRaw);
        }});
        runner.enableControllerService(service);
        runner.enqueue(flow);
        runner.clearTransferState();
        runner.run();
        runner.assertAllFlowFilesTransferred(VerifyPGP.REL_SUCCESS, 1);
    }

    // older tests helpers, should re-integrate?
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
}