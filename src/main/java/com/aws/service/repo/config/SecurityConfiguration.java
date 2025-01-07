package com.aws.service.repo.config;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final CustomizeAuthenticationSuccessHandler customizeAuthenticationSuccessHandler;

    @Value("${aws.cognito.logoutUrl}")
    private String logoutUrl;

    @Value("${aws.cognito.loginUrl}")
    private String loginUrl;

    @Value("${aws.cognito.logout.success.redirectUrl}")
    private String logoutRedirectUrl;

    @Value("${spring.security.oauth2.client.registration.cognito.clientId}")
    private String clientId;


    public SecurityConfiguration(CustomizeAuthenticationSuccessHandler customizeAuthenticationSuccessHandler) {
        this.customizeAuthenticationSuccessHandler = customizeAuthenticationSuccessHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(request -> request.requestMatchers("/","/unAuthenticated/*").permitAll()
                        .requestMatchers("/authenticated/*").hasRole("APIGateway") // This can be any role... APIGateway is just example. I used this as a group name from Cognito Pool. Please check userAuthoritiesMapper() below where i am using group to create ROLE
                        .anyRequest().authenticated())
                .oauth2Login(oauth -> oauth.redirectionEndpoint(endPoint -> endPoint.baseUri("/login/oauth2/code/cognito"))
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userAuthoritiesMapper(userAuthoritiesMapper()))
                        .successHandler(customizeAuthenticationSuccessHandler)
                        .failureHandler((request, response, exception) -> {
                            // Redirect to login page on failure
                            response.sendRedirect(loginUrl);
                        }))
                .logout(httpSecurityLogoutConfigurer -> {
                    httpSecurityLogoutConfigurer.logoutSuccessHandler(
                            new CustomLogoutHandler(logoutUrl, logoutRedirectUrl, clientId));
                });
        return http.build();
    }


    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            try {
                OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) new ArrayList<>(authorities).get(
                        0);

                mappedAuthorities = ((ArrayList<?>) oidcUserAuthority.getAttributes()
                        .get("cognito:groups")).stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toSet());
            } catch (Exception exception) {
                System.out.println("Not Authorized!");

                System.out.println(exception.getMessage());
            }

            return mappedAuthorities;
        };
    }

}
