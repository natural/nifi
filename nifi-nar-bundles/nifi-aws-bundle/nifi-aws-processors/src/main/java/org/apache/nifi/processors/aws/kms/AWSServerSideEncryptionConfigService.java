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
package org.apache.nifi.processors.aws.kms;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.SSEAwsKeyManagementParams;
import com.amazonaws.services.s3.model.SSECustomerKey;
import com.amazonaws.services.s3.model.UploadPartRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnEnabled;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.controller.AbstractControllerService;
import org.apache.nifi.controller.ConfigurationContext;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.reporting.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;


@Tags({"service", "encryption", "encrypt", "decryption", "decrypt", "key"})
public class AWSServerSideEncryptionConfigService extends AbstractControllerService implements ServerSideEncryptionConfigService {
    private static final Logger logger = LoggerFactory.getLogger(AWSServerSideEncryptionConfigService.class);

    // Allowable encryption methods:
    private static final AllowableValue NONE = new AllowableValue("None", "None","Do not use server-side encryption.");
    private static final AllowableValue SSE_S3 = new AllowableValue("S3", "S3", "Use S3 managed encryption.");
    private static final AllowableValue SSE_KMS = new AllowableValue("KMS", "KMS", "Use specified KMS key to perform encryption.");
    private static final AllowableValue SSE_C = new AllowableValue("Customer", "Customer", "Use encryption key supplied by customer.");

    private static final PropertyDescriptor ENCRYPTION_METHOD = new PropertyDescriptor.Builder()
            .name("Encryption Method")
            .displayName("Server-Side Encryption Method")
            .description("Which server-side encryption method to use, if any.")
            .allowableValues(NONE, SSE_S3, SSE_KMS, SSE_C)
            .required(true)
            .defaultValue(NONE.getValue())
            .build();

    private static final PropertyDescriptor KEY_ID = new PropertyDescriptor.Builder()
            .name("Key ID")
            .displayName("KMS Key ID")
            .description("Key ID used in SSE-KMS encryption.")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .build();

    private static final PropertyDescriptor KEY_MATERIAL = new PropertyDescriptor.Builder()
            .name("Key Material")
            .displayName("Customer Key Material")
            .description("Key material for use in SSE-C Key encryption.")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .sensitive(true)
            .build();

    private String encryptionMethod = "";
    private String keyId = "";
    private String keyMaterial = "";

    @Override
    protected Collection<ValidationResult> customValidate(ValidationContext validationContext) {
        final List<ValidationResult> validationResults = new ArrayList<>();
        final String encryptionMethod = validationContext.getProperty(ENCRYPTION_METHOD).getValue();

        // ensure the Key ID is set when enc method is SSE KMS
        if (encryptionMethod.equals(SSE_KMS.getValue())) {
            if (!validationContext.getProperty(KEY_ID).isSet()) {
                validationResults.add(new ValidationResult.Builder()
                        .subject(SSE_KMS.getDisplayName())
                        .explanation(KEY_ID.getName() + " must be set when using the " + SSE_KMS.getDisplayName() + " encryption method")
                        .valid(false)
                        .build());
            }
        }

        // ensure the Key Material is set when the enc method is SSE C (client key)
        if (encryptionMethod.equals(SSE_C.getValue())) {
            // KEY_MATERIAL must be base64 encoded, and when decoded, must be 256 bits/32 bytes.
            if (!validationContext.getProperty(KEY_MATERIAL).isSet()) {
                validationResults.add(new ValidationResult.Builder()
                        .subject(SSE_C.getDisplayName())
                        .explanation(KEY_MATERIAL.getName() + " must be set when using the " + SSE_C.getDisplayName() + " encryption method")
                        .valid(false)
                        .build());
            }
        }

        return validationResults;
    }

    @OnEnabled
    public void onConfigured(final ConfigurationContext context) throws InitializationException {
        encryptionMethod = context.getProperty(ENCRYPTION_METHOD).getValue();
        keyId = context.getProperty(KEY_ID).getValue();
        keyMaterial = context.getProperty(KEY_MATERIAL).getValue();
    }

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        final List<PropertyDescriptor> properties = new ArrayList<>();
        properties.add(ENCRYPTION_METHOD);
        properties.add(KEY_ID);
        properties.add(KEY_MATERIAL);
        return Collections.unmodifiableList(properties);
    }

    // Key for fun:
    //
    // N/XPzMAOl1V/hTEA9X9+6D4iBrsOi/+jflt4br90RF0=

    /**
     * Configure a request with server-side encryption parameters.
     *
     * NB:  we're doing the object type casting because both `setSSEAwsKeyManagementParams` and
     * `setSSECustomerKey` aren't defined on the same base type.
     *
     * @param request AWS request; must be {@link PutObjectRequest} or {@link InitiateMultipartUploadRequest} instance.
     * @param objectMetadata request metadata.
     * @throws IOException when request object cannot be cast to expected subclass.
     */
    public void configureRequest(AmazonWebServiceRequest request, ObjectMetadata objectMetadata) throws IOException {
        PutObjectRequest putObjectRequest = toPutObjectRequest(request);
        InitiateMultipartUploadRequest initUploadRequest = toMultipartUploadRequest(request);
        UploadPartRequest uploadPartRequest = toUploadPartRequest(request);

        if (StringUtils.equals(encryptionMethod, SSE_S3.getValue())) {
            objectMetadata.setSSEAlgorithm(ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION);

        } else if (StringUtils.equals(encryptionMethod, SSE_KMS.getValue())) {
            SSEAwsKeyManagementParams keyParams = new SSEAwsKeyManagementParams(keyId);

            if (putObjectRequest != null) {
                putObjectRequest.setSSEAwsKeyManagementParams(keyParams);
            } else if (initUploadRequest != null) {
                initUploadRequest.setSSEAwsKeyManagementParams(keyParams);
            } else if (uploadPartRequest != null) {
                // upload parts don't re-specify KMS key information.
            } else {
                throw new IOException("Cannot cast request to subtype.");
            }

        } else if (StringUtils.equals(encryptionMethod, SSE_C.getValue())) {
            SSECustomerKey customerKey = new SSECustomerKey(keyMaterial);

            if (putObjectRequest != null) {
                putObjectRequest.setSSECustomerKey(customerKey);
            } else if (initUploadRequest != null) {
                initUploadRequest.setSSECustomerKey(customerKey);
            } else if (uploadPartRequest != null) {
                // but upload parts do need to re-specify customer keys:
                uploadPartRequest.setSSECustomerKey(customerKey);
            } else {
                throw new IOException("Cannot cast request to subtype.");
            }
        }
    }

    // Casts a request to an {@link InitiateMultipartUploadRequest} instance.
    private static InitiateMultipartUploadRequest toMultipartUploadRequest(AmazonWebServiceRequest webServiceRequest) {
        try {
            return (InitiateMultipartUploadRequest) webServiceRequest;
        } catch (final ClassCastException ignored) {
            return null;
        }
    }

    // Casts a request to a {@link PutObjectRequest} instance.
    private static PutObjectRequest toPutObjectRequest(AmazonWebServiceRequest webServiceRequest) {
        try {
            return (PutObjectRequest) webServiceRequest;
        } catch (final ClassCastException ignored) {
            return null;
        }
    }


    private static UploadPartRequest toUploadPartRequest(AmazonWebServiceRequest webServiceRequest) {
        try {
            return (UploadPartRequest) webServiceRequest;
        } catch (final ClassCastException ignored) {
            return null;
        }
    }
}
