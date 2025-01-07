package com.aws.service.repo.service;

import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.nio.file.Paths;
import java.util.Map;

@Service
public class AWSAccessService {


    public void accessS3(AwsSessionCredentials awsSessionCredentials) {

        // Create the S3Client
        S3Client s3Client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsSessionCredentials))
                .region(software.amazon.awssdk.regions.Region.US_EAST_1) // Use your bucket's region
                .build();

        // Example: Download an object from the S3 bucket
        String bucketName = "s3-access-indentitypool";
        String objectKey = "images/image.png";

        s3Client.getObject(
                GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(objectKey)
                        .build(),
                Paths.get("F:\\S3DownlaodIamge\\")
        );

        System.out.println("Object downloaded successfully!");
    }


    public String accessDBData(AwsSessionCredentials awsSessionCredentials) {

        // Create the DynamoDbClient
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsSessionCredentials))
                .region(software.amazon.awssdk.regions.Region.US_EAST_1) // Use your table's region
                .build();

// Example: Retrieve an item from DynamoDB
        String tableName = "Customer";
        String keyName = "cust_id";
        String keyValue = "rashmi11070";

        GetItemRequest getItemRequest = GetItemRequest.builder()
                .tableName(tableName)
                .key(Map.of(keyName, AttributeValue.builder().s(keyValue).build()))
                .build();

        GetItemResponse getItemResponse = dynamoDbClient.getItem(getItemRequest);

        if (getItemResponse.hasItem()) {
            Map<String, AttributeValue> item = getItemResponse.item();
            System.out.println("Retrieved item: " + item);
            return item.toString();
        } else {
            System.out.println("No item found with key: " + keyValue);
        }

        return null;
    }
}
