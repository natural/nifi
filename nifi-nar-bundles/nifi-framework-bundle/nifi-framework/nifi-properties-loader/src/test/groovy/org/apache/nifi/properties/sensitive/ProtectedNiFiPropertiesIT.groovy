package org.apache.nifi.properties.sensitive

import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.AWSKMSClientBuilder
import com.amazonaws.services.kms.model.CreateAliasRequest
import com.amazonaws.services.kms.model.CreateKeyRequest
import com.amazonaws.services.kms.model.CreateKeyResult
import com.amazonaws.services.kms.model.DescribeKeyRequest
import com.amazonaws.services.kms.model.DescribeKeyResult
import com.amazonaws.services.kms.model.DisableKeyRequest
import com.amazonaws.services.kms.model.GenerateDataKeyRequest
import com.amazonaws.services.kms.model.GenerateDataKeyResult
import com.amazonaws.services.kms.model.ScheduleKeyDeletionRequest
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.SecureRandom


@RunWith(JUnit4.class)
class ProtectedNiFiPropertiesIT extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(ProtectedNiFiPropertiesIT.class)

    private static String[] knownGoodKeys = []
    private static AWSKMSClient client

    @BeforeClass
    static void setUpOnce() throws Exception {
        client = AWSKMSClientBuilder.standard().build()

        // generate a cmk
        CreateKeyRequest cmkRequest = new CreateKeyRequest().withDescription("CMK for unit tests")
        CreateKeyResult cmkResult = client.createKey(cmkRequest)

        // from the cmk, generate a dek
        GenerateDataKeyRequest dekRequest = new GenerateDataKeyRequest().withKeyId(cmkResult.keyMetadata.getKeyId()).withKeySpec("AES_128")
        GenerateDataKeyResult dekResult = client.generateDataKey(dekRequest)

        // add an alias to the dek
        final String aliasName = "alias/hello-aws-kms-unit-tests-" + UUID.randomUUID().toString()
        CreateAliasRequest aliasReq = new CreateAliasRequest().withAliasName(aliasName).withTargetKeyId(dekResult.getKeyId())
        client.createAlias(aliasReq)

        // re-read the dek so we have the arn
        DescribeKeyRequest descRequest = new DescribeKeyRequest().withKeyId(dekResult.getKeyId())
        DescribeKeyResult descResult = client.describeKey(descRequest)

        knownGoodKeys = [
                dekResult.getKeyId(),
                descResult.keyMetadata.getArn(),
                aliasName
        ]
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
    }

    @AfterClass
    static void tearDownOnce() {
        if (knownGoodKeys.size() > 0) {
            ScheduleKeyDeletionRequest req = new ScheduleKeyDeletionRequest().withKeyId(knownGoodKeys[0]).withPendingWindowInDays(7)
            client.scheduleKeyDeletion(req)
        }
    }

    @Test
    void testShouldThrowExceptionsWithBadKeys() throws Exception {
        SensitivePropertyProvider propProvider
        String msg

        msg = shouldFail(SensitivePropertyProtectionException) {
            propProvider = new AWSKMSSensitivePropertyProvider("")
        }

        assert msg =~ "The key cannot be empty"
        assert propProvider == null

        def badKeyExceptions = [com.amazonaws.SdkClientException,
                                com.amazonaws.services.kms.model.NotFoundException]

        badKeyExceptions.each { exc ->
            msg = shouldFail(exc) {
                propProvider = new AWSKMSSensitivePropertyProvider("bad key")
                propProvider.protect("value")
            }
            assert msg =~ "Invalid keyId"
        }
    }

    @Test
    void testShouldProtectAndUnprotectValues() throws Exception {
        SensitivePropertyProvider propProvider
        String plainText

        knownGoodKeys.each { k ->
            propProvider = new AWSKMSSensitivePropertyProvider(k)
            assert propProvider != null

            byte[] randBytes = new byte[1024]
            new SecureRandom().nextBytes(randBytes)
            plainText = randBytes.encodeBase64()

            assert plainText != null
            assert plainText != ""

            assert plainText == propProvider.unprotect(propProvider.protect(plainText))
        }
    }

    @Test
    void testShouldHandleProtectEmptyValue() throws Exception {
        SensitivePropertyProvider propProvider
        final List<String> EMPTY_PLAINTEXTS = ["", "    ", null]

        knownGoodKeys.each { k ->
            propProvider = new AWSKMSSensitivePropertyProvider(k)
            assert propProvider != null

            EMPTY_PLAINTEXTS.each { String emptyPlaintext ->
                def msg = shouldFail(IllegalArgumentException) {
                    propProvider.protect(emptyPlaintext)
                }
                assert msg == "Cannot encrypt an empty value"
            }
        }
    }

    @Test
    void testShouldUnprotectValue() throws Exception {
        SensitivePropertyProvider propProvider
        final List<String> BAD_CIPHERTEXTS = ["any", "bad", "value"]

        knownGoodKeys.each { k ->
            propProvider = new AWSKMSSensitivePropertyProvider(k)
            assert propProvider != null

            BAD_CIPHERTEXTS.each { String emptyPlaintext ->
                def msg = shouldFail(org.bouncycastle.util.encoders.DecoderException) {
                    propProvider.unprotect(emptyPlaintext)
                }
                assert msg != null
            }
        }
    }

    @Test
    void testConstructorShouldCreateNewInstance() throws Exception {
        // Arrange
        def values = ["thisIsABadPassword", "thisIsABadSensitiveKeyPassword", "thisIsABadKeystorePassword", "thisIsABadKeyPassword", "thisIsABadTruststorePassword", "This is an encrypted banner message", "nififtw!"]

        knownGoodKeys.each { k ->
            SensitivePropertyProvider propProvider = new AWSKMSSensitivePropertyProvider(k)
            assert propProvider != null

            // Act
            def encryptedValues = values.collect { String v ->
                propProvider.protect(v)
            }
            assert values == encryptedValues.collect { propProvider.unprotect(it) }
        }
    }


}
