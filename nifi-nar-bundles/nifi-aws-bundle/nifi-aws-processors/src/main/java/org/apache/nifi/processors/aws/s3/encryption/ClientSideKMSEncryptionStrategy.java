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
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import org.apache.commons.lang3.StringUtils;

public class ClientSideKMSEncryptionStrategy implements S3EncryptionStrategy {
    @Override
    public AmazonS3Client createClient(AWSCredentialsProvider credentialsProvider, ClientConfiguration clientConfiguration, String region, String keyIdOrMaterial) {
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(keyIdOrMaterial);
        boolean haveRegion = StringUtils.isNotBlank(region);

        CryptoConfiguration cryptoConfig = new CryptoConfiguration();
        if (haveRegion) {
            cryptoConfig.setAwsKmsRegion(Region.getRegion(Regions.fromName(region)));
        }

        AmazonS3EncryptionClient client = new AmazonS3EncryptionClient(credentialsProvider, materialProvider, cryptoConfig);
        if (haveRegion) {
            client.setRegion(Region.getRegion(Regions.fromName(region)));
        }

        return client;
    }
}
