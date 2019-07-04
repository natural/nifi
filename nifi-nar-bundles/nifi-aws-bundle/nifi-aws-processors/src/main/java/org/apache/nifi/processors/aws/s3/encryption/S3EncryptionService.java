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
package org.apache.nifi.processors.aws.s3.encryption;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.UploadPartRequest;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnEnabled;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.controller.AbstractControllerService;
import org.apache.nifi.controller.ConfigurationContext;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.util.StandardValidators;

import org.apache.nifi.processors.aws.s3.AbstractS3EncryptionService;
import org.apache.nifi.processors.aws.s3.AbstractS3Processor;

import org.apache.nifi.reporting.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Tags({"service", "encryption", "encrypt", "decryption", "decrypt", "key"})
public class S3EncryptionService extends AbstractControllerService implements AbstractS3EncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(S3EncryptionService.class);

    public static final String METHOD_NAME_NONE = "NONE";
    public static final String METHOD_NAME_SSE_S3 = "SSE_S3";
    public static final String METHOD_NAME_SSE_KMS = "SSE_KMS";
    public static final String METHOD_NAME_SSE_C = "SSE_C";
    public static final String METHOD_NAME_CSE_KMS = "CSE_KMS";
    public static final String METHOD_NAME_CSE_CMK = "CSE_CMK";

    private static final Map<String, S3EncryptionStrategy> namedStrategies = new HashMap<String, S3EncryptionStrategy>() {{
        put(METHOD_NAME_NONE, new NoOpEncryptionStrategy());
        put(METHOD_NAME_SSE_S3, new ServerSideS3EncryptionStrategy());
        put(METHOD_NAME_SSE_KMS, new ServerSideKMSEncryptionStrategy());
        put(METHOD_NAME_SSE_C, new ServerSideCEKEncryptionStrategy());
        put(METHOD_NAME_CSE_KMS, new ClientSideKMSEncryptionStrategy());
        put(METHOD_NAME_CSE_CMK, new ClientSideCMKEncryptionStrategy());
    }};

    private static final AllowableValue NONE = new AllowableValue(METHOD_NAME_NONE, "None","No encryption.");
    private static final AllowableValue SSE_S3 = new AllowableValue(METHOD_NAME_SSE_S3, "Server-side S3","Use server-side, S3-managed encryption.");
    private static final AllowableValue SSE_KMS = new AllowableValue(METHOD_NAME_SSE_KMS, "Server-side KMS","Use server-side, KMS key to perform encryption.");
    private static final AllowableValue SSE_C = new AllowableValue(METHOD_NAME_SSE_C, "Server-side Customer Key","Use server-side, customer-supplied key for encryption.");
    private static final AllowableValue CSE_KMS = new AllowableValue(METHOD_NAME_CSE_KMS, "Client-side KMS","Use client-side, KMS key to perform encryption.");
    private static final AllowableValue CSE_CMK = new AllowableValue(METHOD_NAME_CSE_CMK, "Client-side Customer Master Key","Use client-side, customer-supplied master key to perform encryption.");

    public static final PropertyDescriptor ENCRYPTION_METHOD = new PropertyDescriptor.Builder()
            .name("Encryption Method")
            .displayName("Encryption Method")
            .description("Method to use for S3 data encryption and decryption.")
            .allowableValues(NONE, SSE_S3, SSE_KMS, SSE_C, CSE_KMS, CSE_CMK)
            .required(true)
            .defaultValue(NONE.getValue())
            .build();

    public static final PropertyDescriptor ENCRYPTION_VALUE = new PropertyDescriptor.Builder()
            .name("Key ID or Key Material")
            .displayName("Key ID or Key Material")
            .description("Key ID or Key Material used to encrypt and decrypt S3 data.")
            .required(false)
            .sensitive(true)
            .addValidator(new StandardValidators.StringLengthValidator(0, 4096))
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .build();

    public static final PropertyDescriptor REGION = new PropertyDescriptor.Builder()
            .name("Region")
            .required(false)
            .allowableValues(AbstractS3Processor.getAvailableRegions())
            .defaultValue(AbstractS3Processor.createAllowableValue(Regions.DEFAULT_REGION).getValue())
            .build();

    private String keyValue = "";
    private String region = "";
    private S3EncryptionStrategy encryptionStrategy = null;
    private String strategyName = "";

    @OnEnabled
    public void onConfigured(final ConfigurationContext context) throws InitializationException {
        strategyName = context.getProperty(ENCRYPTION_METHOD).getValue();

        keyValue = context.getProperty(ENCRYPTION_VALUE).getValue();
        if (context.getProperty(REGION) != null ) {
            region = context.getProperty(REGION).getValue();
        }
        encryptionStrategy = namedStrategies.get(strategyName);

        if (encryptionStrategy == null) {
            final String msg = "No encryption method found for: " + strategyName;
            logger.warn(msg);
            throw new InitializationException(msg);
        }
    }

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        final List<PropertyDescriptor> properties = new ArrayList<>();
        properties.add(ENCRYPTION_METHOD);
        properties.add(ENCRYPTION_VALUE);
        properties.add(REGION);
        return Collections.unmodifiableList(properties);
    }

    @Override
    public void configurePutObjectRequest(PutObjectRequest request, ObjectMetadata objectMetadata) throws IOException {
        if (encryptionStrategy == null) {
            throw new IOException("No encryption method set.");
        }
        encryptionStrategy.configurePutObjectRequest(request, objectMetadata, keyValue);
    }

    @Override
    public void configureInitiateMultipartUploadRequest(InitiateMultipartUploadRequest request, ObjectMetadata objectMetadata) throws IOException {
        if (encryptionStrategy == null) {
            throw new IOException("No encryption method set.");
        }
        encryptionStrategy.configureInitiateMultipartUploadRequest(request, objectMetadata, keyValue);
    }

    @Override
    public void configureGetObjectRequest(GetObjectRequest request, ObjectMetadata objectMetadata) throws IOException {
        if (encryptionStrategy == null) {
            throw new IOException("No encryption method set.");
        }
        encryptionStrategy.configureGetObjectRequest(request, objectMetadata, keyValue);
    }

    @Override
    public void configureUploadPartRequest(UploadPartRequest request, ObjectMetadata objectMetadata) throws IOException {
        if (encryptionStrategy == null) {
            throw new IOException("No encryption method set.");
        }
        encryptionStrategy.configureUploadPartRequest(request, objectMetadata, keyValue);
    }

    @Override
    public AmazonS3Client createClient(AWSCredentialsProvider credentialsProvider, ClientConfiguration clientConfiguration) {
        return encryptionStrategy.createClient(credentialsProvider, clientConfiguration, region, keyValue);
    }

    @Override
    public String getRegion() {
        return region;
    }

    @Override
    public String getStrategyName() {
        return strategyName;
    }
}


