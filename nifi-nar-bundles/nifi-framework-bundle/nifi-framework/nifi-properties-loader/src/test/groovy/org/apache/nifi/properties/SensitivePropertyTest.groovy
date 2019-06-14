package org.apache.nifi.properties

import org.apache.nifi.properties.sensitive.SensitiveProperty
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.junit.runners.JUnit4

import java.security.Security

@RunWith(JUnit4.class)
class SensitivePropertyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(SensitivePropertyTest.class)

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        // setupTmpDir()
    }

    @AfterClass
    static void tearDownOnce() throws Exception {
        // File tmpDir = new File("target/tmp/")
        // tmpDir.delete()
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
        // TestAppender.reset()
    }

    @Test
    void testSomethingBasicWorksLikeYouLike() throws Exception {
        // SensitiveProperty sp = SensitiveProperty.fromAnyValue("any old value will do")
        // assert sp.getName() == "AES Sensitive Property Provider"

        assert 1 == 1

    }

}
