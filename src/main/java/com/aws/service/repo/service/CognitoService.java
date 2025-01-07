package com.aws.service.repo.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdResponse;

import java.util.Map;

@Service
public class CognitoService {

    @Value("${aws.cognito.region}")
    private String region;

    @Value("${aws.cognito.identityPoolId}")
    private String identityPoolId;

    @Value("${aws.cognito.userPoolId}")
    private String userPoolId;

    private final CognitoIdentityClient cognitoIdentityClient;
    private final CognitoAuthenticationService authenticationService;

    public CognitoService(CognitoAuthenticationService authenticationService) {
        this.cognitoIdentityClient = CognitoIdentityClient.builder().build();
        this.authenticationService = authenticationService;
    }

    /**
     * Authenticate the user and fetch temporary AWS credentials.
     *
     * @param username User's username
     * @param password User's password
     * @return temporary AWS credentials
     */
    public AwsSessionCredentials getTemporaryCredentials(String username, String password) {
        // Step 1: Authenticate User and Get Tokens
        Map<String, String> tokens = authenticationService.authenticateUser(username, password);
        String idToken = tokens.get("id_token");

        // Step 2: Get Identity ID
        GetIdRequest getIdRequest = GetIdRequest.builder()
                .identityPoolId(identityPoolId)
                .logins(Map.of("cognito-idp." + region + ".amazonaws.com/" + userPoolId, idToken))
                .build();

        GetIdResponse getIdResponse = cognitoIdentityClient.getId(getIdRequest);
        String identityId = getIdResponse.identityId();

        // Step 3: Get Credentials for Identity
        GetCredentialsForIdentityRequest getCredentialsRequest = GetCredentialsForIdentityRequest.builder()
                .identityId(identityId)
                .logins(Map.of("cognito-idp." + region + ".amazonaws.com/" + userPoolId, idToken))
                .build();

        GetCredentialsForIdentityResponse credentialsResponse = cognitoIdentityClient.getCredentialsForIdentity(getCredentialsRequest);

        // Step 4: Extract temporary AWS credentials
        return AwsSessionCredentials.create(
                credentialsResponse.credentials().accessKeyId(),
                credentialsResponse.credentials().secretKey(),
                credentialsResponse.credentials().sessionToken()
        );
    }

    public AwsSessionCredentials getTemporaryAWSCredentials() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();

            // Retrieve ID token
            String idToken = oidcUser.getIdToken().getTokenValue();

            // Step 2: Get Identity ID
            GetIdRequest getIdRequest = GetIdRequest.builder()
                    .identityPoolId(identityPoolId)
                    .logins(Map.of("cognito-idp." + region + ".amazonaws.com/" + userPoolId, idToken))
                    .build();

            GetIdResponse getIdResponse = cognitoIdentityClient.getId(getIdRequest);
            String identityId = getIdResponse.identityId();

            // Step 3: Get Credentials for Identity
            GetCredentialsForIdentityRequest getCredentialsRequest = GetCredentialsForIdentityRequest.builder()
                    .identityId(identityId)
                    .logins(Map.of("cognito-idp." + region + ".amazonaws.com/" + userPoolId, idToken))
                    .build();

            GetCredentialsForIdentityResponse credentialsResponse = cognitoIdentityClient.getCredentialsForIdentity(getCredentialsRequest);

            // Step 4: Extract temporary AWS credentials
            return AwsSessionCredentials.create(
                    credentialsResponse.credentials().accessKeyId(),
                    credentialsResponse.credentials().secretKey(),
                    credentialsResponse.credentials().sessionToken()
            );
        }

        return null;
    }


    public AwsSessionCredentials getTemporaryAWSCredentialsForGuest() {

        CognitoIdentityClient cognitoIdentityClient = CognitoIdentityClient.create();

        // Get Cognito Identity ID for unauthenticated access
        GetIdRequest getIdRequest = GetIdRequest.builder()
                .identityPoolId(identityPoolId)
                .build();

        GetIdResponse getIdResponse = cognitoIdentityClient.getId(getIdRequest);

        String identityId = getIdResponse.identityId();

        // Get temporary credentials
        GetCredentialsForIdentityRequest credentialsRequest = GetCredentialsForIdentityRequest.builder()
                .identityId(identityId)
                .build();

        GetCredentialsForIdentityResponse credentialsResponse = cognitoIdentityClient.getCredentialsForIdentity(credentialsRequest);

        return AwsSessionCredentials.create(
                credentialsResponse.credentials().accessKeyId(),
                credentialsResponse.credentials().secretKey(),
                credentialsResponse.credentials().sessionToken()
        );
    }

}
