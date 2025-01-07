package com.aws.service.repo.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import java.util.HashMap;
import java.util.Map;

@Service
public class CognitoAuthenticationService {

    @Value("${aws.cognito.userPoolDomain}")
    private String userPoolDomain;

    @Value("${spring.security.oauth2.client.registration.cognito.clientId}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.cognito.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;

    public CognitoAuthenticationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Authenticate the user using Cognito User Pool and get tokens.
     *
     * @param username The username
     * @param password The password
     * @return Response containing id_token, access_token, and refresh_token
     */
    public Map<String, String> authenticateUser(String username, String password) {
        String url = String.format("%s/oauth2/token", userPoolDomain);

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(clientId, clientSecret);
        headers.set("Content-Type", "application/x-www-form-urlencoded");

        Map<String, String> body = new HashMap<>();
        body.put("grant_type", "password");
        body.put("username", username);
        body.put("password", password);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, body, Map.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return (Map<String, String>) response.getBody();
        } else {
            throw new RuntimeException("Authentication failed: " + response.getStatusCode());
        }
    }

    public String getIdToken() {
        String tokenEndpoint = String.format("https://%s/oauth2/token", userPoolDomain);

        HttpHeaders headers = new HttpHeaders();
        //headers.setBasicAuth(clientId, clientSecret);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("scope","https://tl2nc6w6lf.execute-api.us-east-1.amazonaws.com/dev/read");
        body.add("client_id",clientId);
        body.add("client_secret",clientSecret);


        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Map> response = restTemplate.exchange(tokenEndpoint, HttpMethod.POST, request, Map.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> responseBody = response.getBody();
            return responseBody != null ? (String) responseBody.get("access_token") : null;
        } else {
            throw new RuntimeException("Failed to obtain access token");
        }
    }
}

