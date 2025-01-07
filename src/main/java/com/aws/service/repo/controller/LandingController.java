package com.aws.service.repo.controller;

import com.aws.service.repo.service.AWSAccessService;
import com.aws.service.repo.service.CognitoService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

@RestController
public class LandingController {

    private final CognitoService cognitoService;
    private final AWSAccessService awsAccessService;


    public LandingController(CognitoService cognitoService, AWSAccessService awsAccessService) {
        this.cognitoService = cognitoService;
        this.awsAccessService = awsAccessService;
    }

    @GetMapping("/")
    public String landing() {
        return "Welcome to AWS Resource Page..!!";
    }

    @GetMapping("/authenticated/user")
    public String authenticatedUser() {
        AwsSessionCredentials awsSessionCredentials = cognitoService.getTemporaryAWSCredentials();

        awsAccessService.accessS3(awsSessionCredentials);
        awsAccessService.accessDBData(awsSessionCredentials);
        return "Welcome to Authenticated User from Cognito Pool Admin Page";
    }

    @GetMapping("/unAuthenticated/user")
    public String unAuthenticatedUser() {
        AwsSessionCredentials awsSessionCredentials = cognitoService.getTemporaryAWSCredentialsForGuest();

        awsAccessService.accessS3(awsSessionCredentials);
        awsAccessService.accessDBData(awsSessionCredentials);
        return "Welcome to Guest User from Identity Pool to Access AWS Service";
    }
}
