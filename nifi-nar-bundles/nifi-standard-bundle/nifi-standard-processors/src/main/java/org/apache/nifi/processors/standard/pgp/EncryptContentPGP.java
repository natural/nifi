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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.nifi.annotation.behavior.EventDriven;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.SideEffectFree;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.behavior.SystemResource;
import org.apache.nifi.annotation.behavior.SystemResourceConsideration;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.util.StopWatch;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;


@EventDriven
@SideEffectFree
@SupportsBatching
@InputRequirement(InputRequirement.Requirement.INPUT_REQUIRED)
@Tags({"encryption", "decryption", "OpenPGP", "PGP", "GPG"})
@CapabilityDescription("Encrypts and Decrypts, Signs and Verifies a FlowFile using PGP keys.")
@SystemResourceConsideration(resource = SystemResource.CPU)

public class EncryptContentPGP extends AbstractProcessor {
    public static final PropertyDescriptor ENCRYPT_ALGORITHM = new PropertyDescriptor.Builder()
            .name("encrypt-algorithm")
            .displayName("Encryption Cipher Algorithm")
            .description("The cipher algorithm used when encrypting data.  Decryption algorithms are detected automatically and do not need to be specified.")
            .allowableValues(getCipherAllowableValues())
            .defaultValue(getCipherDefaultValue())
            .build();
    public static final PropertyDescriptor ENCRYPT_ENCODING = new PropertyDescriptor.Builder()
            .name("encrypt-encoding")
            .displayName("Encryption Data Encoding")
            .description("The data encoding method used when writing encrypting data.")
            .allowableValues(
                    new AllowableValue("0", "Raw"),
                    new AllowableValue("1", "PGP Armor"))
            .defaultValue("0")
            .build();
    public static final PropertyDescriptor PBE_PASS_PHRASE = new PropertyDescriptor.Builder()
            .name("pbe-pass-phrase")
            .displayName("Encryption Pass Phrase")
            .description("This is the pass phrase for password-based encyrption.  If specified, keys are ignored.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .sensitive(true)
            .build();
    public static final PropertyDescriptor SIGNATURE_HASH_ALGORITHM = new PropertyDescriptor.Builder()
            .name("signature-hash-algorithm")
            .displayName("Signature Hash Function")
            .description("The hash function used when signing data.")
            .allowableValues(getSignatureHashAllowableValues())
            .defaultValue(getSignatureHashDefaultValue())
            .build();
    public static final PropertyDescriptor SIGNATURE_ATTRIBUTE = new PropertyDescriptor.Builder()
            .name("signature-attribute")
            .displayName("Signature Attribute")
            .description("The flow file attribute name of the hex-encoded signature when signing and verifying data.")
            .defaultValue("content-signature")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor PUBLIC_KEYRING_FILE = new PropertyDescriptor.Builder()
            .name("public-keyring-file")
            .displayName("Public Key or Keyring File")
            .description("PGP public key or keyring file.")
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();
    public static final PropertyDescriptor PUBLIC_KEYRING_TEXT = new PropertyDescriptor.Builder()
            .name("public-keyring-text")
            .displayName("Public Key or Keyring Text")
            .description("This is the PGP public key or keyring, entered as text.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor PUBLIC_KEY_ID = new PropertyDescriptor.Builder()
            .name("public-key-id")
            .displayName("Public Key ID")
            .description("Key from public keyring for use during Encrypt operations.  Public key selection is automatic for Verify operations.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor SECRET_KEYRING_FILE = new PropertyDescriptor.Builder()
            .name("secret-keyring-file")
            .displayName("Secret Key or Keyring File")
            .description("This is the PGP secret key or keyring file.")
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();
    public static final PropertyDescriptor SECRET_KEYRING_TEXT = new PropertyDescriptor.Builder()
            .name("secret-keyring-text")
            .displayName("Secret Key or Keyring Text")
            .description("This is the PGP secret key or keyring, entered as text.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();
    public static final PropertyDescriptor SECRET_KEY_ID = new PropertyDescriptor.Builder()
            .name("secret-key-id")
            .displayName("Secret Key ID")
            .description("This is the key ID from secret keyring for use during Sign operations. Secret key selection is automatic for Decrypt operations.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor PRIVATE_KEY_PASS_PHRASE = new PropertyDescriptor.Builder()
            .name("private-key-passphrase")
            .displayName("Private Key Passphrase")
            .description("This is the passphrase for the private key used with Sign, Decrypt operations.")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .sensitive(true)
            .build();
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("Any FlowFile that is successfully encrypted or decrypted will be routed to success")
            .build();
    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("Any FlowFile that cannot be encrypted or decrypted will be routed to failure")
            .build();
    static final String ENCRYPT_MODE = "0";
    static final String DECRYPT_MODE = "1";
    static final String SIGN_MODE = "2";
    static final String VERIFY_MODE = "3";
    static final String ENCRYPT_AND_SIGN_MODE = "4";
    static final String DECRYPT_AND_VERIFY_MODE = "5";
    public static final PropertyDescriptor MODE = new PropertyDescriptor.Builder()
            .name("Mode")
            .description("Processor mode of operation.")
            .defaultValue(ENCRYPT_MODE)
            .allowableValues(
                    new AllowableValue(ENCRYPT_MODE, "Encrypt"),
                    new AllowableValue(ENCRYPT_AND_SIGN_MODE, "Encrypt and Sign"),
                    new AllowableValue(DECRYPT_MODE, "Decrypt"),
                    new AllowableValue(DECRYPT_AND_VERIFY_MODE, "Decrypt and Verify"),
                    new AllowableValue(SIGN_MODE, "Sign"),
                    new AllowableValue(VERIFY_MODE, "Verify"))
            .required(true)
            .build();

    // Processor method overrides start here.

    private static AllowableValue[] getCipherAllowableValues() {
        return new AllowableValue[]{
                // Values match integer values in org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
                // 0 - NULL not supported
                new AllowableValue("1", "IDEA"),
                new AllowableValue("2", "TRIPLE DES"),
                new AllowableValue("3", "CAST5"),
                new AllowableValue("4", "BLOWFISH"),
                new AllowableValue("6", "DES"),
                // 6 - SAFER not supported
                new AllowableValue("7", "AES 128"),
                new AllowableValue("8", "AES 192"),
                new AllowableValue("9", "AES 256"),
                new AllowableValue("10", "TWOFISH"),
                new AllowableValue("11", "CAMELLIA 128"),
                new AllowableValue("12", "CAMELLIA 192"),
                new AllowableValue("13", "CAMELLIA 256")};
    }

    private static String getCipherDefaultValue() {
        return String.valueOf(PGPEncryptedData.AES_128);
    }

    private static String getSignatureHashDefaultValue() {
        return String.valueOf(PGPUtil.SHA256);
    }

    private static AllowableValue[] getSignatureHashAllowableValues() {
        return new AllowableValue[]{
                // Values match integer values in org.bouncycastle.bcpg.HashAlgorithmTags
                new AllowableValue("1", "MD5"),
                new AllowableValue("2", "SHA1"),
                //new AllowableValue("3", "RIPEMD160"),
                //new AllowableValue("4", "DOUBLE_SHA (experimental)"),
                //new AllowableValue("5", "MD2"),
                new AllowableValue("6", "TIGER 192"),
                //new AllowableValue("7", "HAVAL (5 pass 160 bit)"),
                new AllowableValue("8", "SHA 256"),
                new AllowableValue("9", "SHA 384"),
                new AllowableValue("10", "SHA 512"),
                //new AllowableValue("11","SHA 224")
        };
    }


    // What follows are our "session builders" that we use to provide options and state to the various callbacks.

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        final FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        final String mode = context.getProperty(MODE).getValue();
        final ComponentLog logger = getLogger();
        final ExtendedStreamCallback callback;

        try {
            switch (mode) {
                case DECRYPT_MODE:
                    callback = new DecryptStreamCallback(buildDecryptSession(context));
                    break;

                case DECRYPT_AND_VERIFY_MODE:
                    callback = new SerialStreamCallback(
                            new VerifyStreamCallback(buildVerifySession(context, flowFile)),
                            new DecryptStreamCallback(buildDecryptSession(context)));
                    break;

                case ENCRYPT_MODE:
                    callback = new EncryptStreamCallback(buildEncryptSession(context));
                    break;

                case ENCRYPT_AND_SIGN_MODE:
                    callback = new SerialStreamCallback(
                            new EncryptStreamCallback(buildEncryptSession(context)),
                            new SignStreamCallback(buildSignSession(context, flowFile, session)));
                    break;

                case SIGN_MODE:
                    callback = new SignStreamCallback(buildSignSession(context, flowFile, session));
                    break;

                case VERIFY_MODE:
                    callback = new VerifyStreamCallback(buildVerifySession(context, flowFile));
                    break;

                default:
                    throw new IOException("Unknown processor mode.");
            }
        } catch (final IOException | PGPException | DecoderException e) {
            logger.error("Exception constructing stream callback", e);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        try {
            final StopWatch stopWatch = new StopWatch(true);
            final FlowFile finalFlow = session.write(flowFile, callback);
            callback.postProcess(session, finalFlow);
            logger.debug("Called to {} flow {}", new Object[]{mode, flowFile});
            session.getProvenanceReporter().modifyContent(finalFlow, stopWatch.getElapsed(TimeUnit.MILLISECONDS));
            session.transfer(finalFlow, REL_SUCCESS);
        } catch (final ProcessException e) {
            logger.error("Exception in {} flow {} ", new Object[]{mode, flowFile});
            session.transfer(flowFile, REL_FAILURE);
        }
    }

    // add support for ascii armor prop + value passed thru to session

    @Override
    public Set<Relationship> getRelationships() {
        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        return Collections.unmodifiableSet(relationships);
    }

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        final List<PropertyDescriptor> properties = new ArrayList<>();

        properties.add(MODE);
        properties.add(ENCRYPT_ALGORITHM);
        properties.add(ENCRYPT_ENCODING);
        properties.add(PBE_PASS_PHRASE);

        properties.add(SIGNATURE_ATTRIBUTE);
        properties.add(SIGNATURE_HASH_ALGORITHM);

        properties.add(PUBLIC_KEYRING_FILE);
        properties.add(PUBLIC_KEYRING_TEXT);
        properties.add(PUBLIC_KEY_ID);          // Build with allowable values here

        properties.add(SECRET_KEYRING_FILE);
        properties.add(SECRET_KEYRING_TEXT);
        properties.add(SECRET_KEY_ID);          // Also here
        properties.add(PRIVATE_KEY_PASS_PHRASE);

        return properties;
    }

    @Override
    protected Collection<ValidationResult> customValidate(final ValidationContext context) {
        final List<ValidationResult> validationResults = new ArrayList<>(super.customValidate(context));
        String mode = context.getProperty(MODE).getValue();
        boolean requirePublicKey = false, requirePrivateKey = false;

        switch (mode) {
            case ENCRYPT_MODE:
            case VERIFY_MODE: {
                requirePublicKey = true;
                break;
            }
            case DECRYPT_MODE:
            case SIGN_MODE: {
                requirePrivateKey = true;
                break;
            }
        }

        if (requirePublicKey) {
        }

        if (requirePrivateKey) {
        }
        return validationResults;
    }

    // What follows are the getters for processor instance properties.  We're doing the work of lookup, conversion, and caching.

    private SignStreamSession buildSignSession(ProcessContext context, FlowFile flowFile, ProcessSession session) throws PGPException, IOException {
        PGPPrivateKey privateKey = getPrivateKey(context);
        String attribute = context.getProperty(SIGNATURE_ATTRIBUTE).getValue();
        int algo = getSignHashAlgorithm(context);

        return new SignStreamSession(getLogger(), privateKey, algo, attribute, session, flowFile);
    }

    private EncryptStreamSession buildEncryptSession(ProcessContext context) throws IOException, PGPException {
        PGPPublicKey publicKey = getPublicKey(context);
        char[] passphrase = getPBEPassPhrase(context);
        int algo = getEncryptAlgorithm(context);
        boolean armor = 1 == getEncryptionEncoding(context);

        if (publicKey != null) {
            return new PublicKeyEncryptKeySession(getLogger(), publicKey, algo, armor);
        }

        if (passphrase != null && passphrase.length > 0) {
            return new PBEEncryptStreamSession(getLogger(), passphrase, algo, armor);
        }

        throw new PGPException("Context not configured for encryption.  Specify public key or PBE pass-phrase");
    }

    private VerifyStreamSession buildVerifySession(ProcessContext context, FlowFile flowFile) throws IOException, PGPException, DecoderException {
        PGPPublicKey publicKey = getPublicKey(context);
        InputStream signature = getSignature(context, flowFile);

        return new VerifyStreamSession(getLogger(), publicKey, signature);
    }

    private DecryptStreamSession buildDecryptSession(ProcessContext context) throws PGPException, IOException {
        PGPPrivateKey privateKey = getPrivateKey(context);
        char[] passphrase = getPBEPassPhrase(context);

        if (privateKey != null) {
            return new PrivateKeyDecryptStreamSession(getLogger(), privateKey);
        }
        return new PBEDecryptStreamSession(getLogger(), passphrase);
    }

    private char[] getPBEPassPhrase(ProcessContext context) {
        char[] passphrase = null;
        if (context.getProperty(PBE_PASS_PHRASE).isSet()) {
            String value = context.getProperty(PBE_PASS_PHRASE).evaluateAttributeExpressions().getValue();
            passphrase = value.toCharArray();
        }
        return passphrase;
    }

    private InputStream getSignature(ProcessContext context, FlowFile flowFile) throws DecoderException {
        String attribute = context.getProperty(SIGNATURE_ATTRIBUTE).getValue();
        String signature = flowFile.getAttribute(attribute);
        return new ByteArrayInputStream(Hex.decodeHex(signature));
    }

    private PGPPrivateKey getPrivateKey(ProcessContext context) throws PGPException, IOException {
        long keyId = 0;
        if (context.getProperty(SECRET_KEY_ID).isSet()) {
            keyId = Long.parseLong(context.getProperty(SECRET_KEY_ID).getValue());
        }

        char[] passphrase = null;
        if (context.getProperty(PRIVATE_KEY_PASS_PHRASE).isSet()) {
            passphrase = context.getProperty(PRIVATE_KEY_PASS_PHRASE).getValue().toCharArray();
        }

        if (context.getProperty(SECRET_KEYRING_TEXT).isSet()) {
            String text = context.getProperty(SECRET_KEYRING_TEXT).getValue();
            InputStream input = new ByteArrayInputStream(text.getBytes(Charset.defaultCharset()));
            return StaticKeyMaterialProvider.readPrivateKey(input, keyId, passphrase);
        }

        if (context.getProperty(SECRET_KEYRING_FILE).isSet()) {
            FileInputStream input = new FileInputStream(new File(context.getProperty(SECRET_KEYRING_FILE).getValue()));
            return StaticKeyMaterialProvider.readPrivateKey(input, keyId, passphrase);
        }

        return null;
    }

    // What follows are static helpers for building the properties at the head of the class.

    private PGPPublicKey getPublicKey(ProcessContext context) throws IOException, PGPException {
        // long keyId = Long.parseLong(context.getProperty(PUBLIC_KEY_ID).getValue());
        // uh?

        if (context.getProperty(PUBLIC_KEYRING_TEXT).isSet()) {
            String content = context.getProperty(PUBLIC_KEYRING_TEXT).getValue();
            InputStream input = new ByteArrayInputStream(content.getBytes(Charset.defaultCharset()));
            return StaticKeyMaterialProvider.readPublicKey(input);
        }

        if (context.getProperty(PUBLIC_KEYRING_FILE).isSet()) {
            FileInputStream input = new FileInputStream(new File(context.getProperty(PUBLIC_KEYRING_FILE).getValue()));
            return StaticKeyMaterialProvider.readPublicKey(input);
        }

        return null;
    }

    private int getEncryptAlgorithm(ProcessContext context) {
        return context.getProperty(ENCRYPT_ALGORITHM).asInteger();
    }

    private int getEncryptionEncoding(ProcessContext context) {
        return context.getProperty(ENCRYPT_ENCODING).asInteger();
    }

    private int getSignHashAlgorithm(ProcessContext context) {
        return context.getProperty(SIGNATURE_HASH_ALGORITHM).asInteger();
    }
}
