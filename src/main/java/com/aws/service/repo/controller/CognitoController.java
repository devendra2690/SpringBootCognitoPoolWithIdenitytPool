package com.aws.service.repo.controller;

import com.aws.service.repo.service.CognitoService;
import org.springframework.web.bind.annotation.*;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

@RestController
@RequestMapping("/api/cognito")
public class CognitoController {

    private final CognitoService cognitoService;

    public CognitoController(CognitoService cognitoService) {
        this.cognitoService = cognitoService;
    }

    @PostMapping("/getTemporaryCredentialsUsingOAuth2")
    public AwsSessionCredentials getTemporaryCredentialsUsingOAuth2(
            @RequestParam String username,
            @RequestParam String password) {
        return cognitoService.getTemporaryAWSCredentials();
    }

    @GetMapping("/getTemporaryCredentialsUsingUsernamePassword")
    public AwsSessionCredentials getTemporaryCredentialsUsingUsernamePassword() {
        return cognitoService.getTemporaryAWSCredentials();
    }
}

