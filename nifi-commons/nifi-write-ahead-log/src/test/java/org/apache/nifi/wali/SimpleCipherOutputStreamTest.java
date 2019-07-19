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
import java.io.OutputStream;

public class SimpleCipherOutputStreamTest extends SimpleCipherToolTest {
    private static byte[] secret;
    private static SecretKey key;

    @BeforeClass
    public static void setUpClass() {
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
        OutputStream stream = SimpleCipherOutputStream.initWithKey(cipherByteOutputStream, key);

        stream.write(secret);
        stream.close();

        byte[] cipherText = cipherByteOutputStream.toByteArray();
        ByteArrayInputStream cipherByteInputStream = new ByteArrayInputStream(cipherText);
        SimpleCipherInputStream cipherInputStream = SimpleCipherInputStream.initWithKey(cipherByteInputStream, key);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        byte[] plainText = new byte[cipherInputStream.cipher.getOutputSize(cipherText.length)];
        int len;
        while ((len = cipherInputStream.read(plainText, 0, plainText.length)) != -1) {
            buffer.write(plainText, 0, len);
        }

        Assert.assertArrayEquals(secret, buffer.toByteArray());
    }
}