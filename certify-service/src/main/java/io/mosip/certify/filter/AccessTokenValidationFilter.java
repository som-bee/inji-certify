package io.mosip.certify.filter;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.util.CommonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

@Slf4j
@Component
public class AccessTokenValidationFilter extends OncePerRequestFilter {

    @Value("${mosip.certify.authn.issuer-uri:https://stg-id.singpass.gov.sg}")
    private String issuerUri;

    @Value("${mosip.certify.authn.jwk-set-uri:https://stg-id.singpass.gov.sg/.well-known/keys}")
    private String jwkSetUri;

    @Value("#{${mosip.certify.authn.allowed-audiences}}")
    private List<String> allowedAudiences;

    @Value("#{${mosip.certify.authn.filter-urls}}")
    private List<String> urlPatterns;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    private NimbusJwtDecoder nimbusJwtDecoder;

    private boolean isJwt(String token) {
        boolean result = token.split("\\.").length == 3;
        log.info("Token split into {} parts; isJwt = {}", token.split("\\.").length, result);
        return result;
    }

    private NimbusJwtDecoder getNimbusJwtDecoder() {
        if (nimbusJwtDecoder == null) {
            log.info("Creating NimbusJwtDecoder with JWKS URI: {}", jwkSetUri);
            nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            
            // Create a more flexible validator that works with both token types
            nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(),
                    // For Singpass tokens, the 'client_id' might be present instead of 'sub'
                    new JwtClaimValidator<String>(JwtClaimNames.SUB, sub -> sub != null),
                    new JwtClaimValidator<String>("client_id", clientId -> clientId != null),
                    // Check issuer only if it's not empty or null
                    new JwtIssuerValidator(issuerUri),
                    // Audience validation
                    new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, 
                            audiences -> audiences != null && !audiences.isEmpty() && 
                            (audiences.stream().anyMatch(allowedAudiences::contains) || 
                             allowedAudiences.stream().anyMatch(audiences::contains))),
                    new JwtClaimValidator<Instant>(JwtClaimNames.IAT,
                            iat -> iat != null && iat.isBefore(Instant.now(Clock.systemUTC()))),
                    new JwtClaimValidator<Instant>(JwtClaimNames.EXP,
                            exp -> exp != null && exp.isAfter(Instant.now(Clock.systemUTC())))
            ));
            log.info("NimbusJwtDecoder created and configured with issuer: {}", issuerUri);
        }
        return nimbusJwtDecoder;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        final String path = request.getRequestURI();
        log.info("Checking if filter should apply for path: {}", path);
        boolean shouldFilter = urlPatterns.contains(path);
        log.info("Filter applicable for path {}: {}", path, shouldFilter);
        return !shouldFilter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("Starting access token validation for request: {}", request.getRequestURI());

        String authorizationHeader = request.getHeader("Authorization");
        log.info("Authorization header: {}", authorizationHeader);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            log.info("Bearer token extracted. Token length: {}", token.length());

            if (isJwt(token)) {
                log.info("Token appears to be a JWT; proceeding with JWT validation.");
                try {
                    log.info("Decoding JWT using NimbusJwtDecoder.");
                    Jwt jwt = getNimbusJwtDecoder().decode(token);
                    log.info("JWT decoded successfully. Claims: {}", jwt.getClaims());

                    // Populate ParsedAccessToken with claims and calculated at_hash
                    parsedAccessToken.setClaims(new HashMap<>());
                    parsedAccessToken.getClaims().putAll(jwt.getClaims());
                    parsedAccessToken.setAccessTokenHash(CommonUtil.generateOIDCAtHash(token));
                    parsedAccessToken.setActive(true);
                    log.info("Access token is active and valid. Continuing filter chain.");
                    
                    filterChain.doFilter(request, response);
                    return;
                } catch (Exception e) {
                    log.error("Access token validation failed: {}", e.getMessage(), e);
                }
            } else {
                log.warn("Token does not appear to be a JWT; assuming opaque token. Skipping JWT validation.");
            }
        } else {
            log.warn("Authorization header missing or does not start with 'Bearer '.");
        }

        log.error("No valid Bearer token provided; marking access token as inactive and continuing filter chain.");
        parsedAccessToken.setActive(false);
        filterChain.doFilter(request, response);
    }
}


// /*
//  * This Source Code Form is subject to the terms of the Mozilla Public
//  * License, v. 2.0. If a copy of the MPL was not distributed with this
//  * file, You can obtain one at https://mozilla.org/MPL/2.0/.
//  */
// package io.mosip.certify.filter;

// import io.mosip.certify.core.constants.Constants;
// import io.mosip.certify.core.dto.ParsedAccessToken;
// import io.mosip.certify.core.util.CommonUtil;
// import lombok.extern.slf4j.Slf4j;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
// import org.springframework.security.oauth2.jwt.*;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import jakarta.servlet.*;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import java.time.Clock;
// import java.time.Instant;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Objects;

// @Slf4j
// @Component
// public class AccessTokenValidationFilter extends OncePerRequestFilter {

//     @Value("${mosip.certify.authn.issuer-uri}")
//     private String issuerUri;

//     @Value("${mosip.certify.authn.jwk-set-uri}")
//     private String jwkSetUri;

//     @Value("#{${mosip.certify.authn.allowed-audiences}}")
//     private List<String> allowedAudiences;

//     @Value("#{${mosip.certify.authn.filter-urls}}")
//     private List<String> urlPatterns;

//     @Autowired
//     private ParsedAccessToken parsedAccessToken;

//     private NimbusJwtDecoder nimbusJwtDecoder;

//     private boolean isJwt(String token) {
//         boolean result = token.split("\\.").length == 3;
//         log.info("Token split into {} parts; isJwt = {}", token.split("\\.").length, result);
//         return result;
//     }

//     private NimbusJwtDecoder getNimbusJwtDecoder() {
//         if (nimbusJwtDecoder == null) {
//             log.info("Creating NimbusJwtDecoder with JWKS URI: {}", jwkSetUri);
//             nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
//             nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
//                     new JwtTimestampValidator(),
//                     new JwtIssuerValidator(issuerUri),
//                     new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, allowedAudiences::containsAll),
//                     new JwtClaimValidator<String>(JwtClaimNames.SUB, Objects::nonNull),
//                     new JwtClaimValidator<String>(Constants.CLIENT_ID, Objects::nonNull),
//                     new JwtClaimValidator<Instant>(JwtClaimNames.IAT,
//                             iat -> iat != null && iat.isBefore(Instant.now(Clock.systemUTC()))),
//                     new JwtClaimValidator<Instant>(JwtClaimNames.EXP,
//                             exp -> exp != null && exp.isAfter(Instant.now(Clock.systemUTC())))
//             ));
//             log.info("NimbusJwtDecoder created and configured with issuer: {}", issuerUri);
//         }
//         return nimbusJwtDecoder;
//     }

//     @Override
//     protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//         final String path = request.getRequestURI();
//         log.info("Checking if filter should apply for path: {}", path);
//         boolean shouldFilter = urlPatterns.contains(path);
//         log.info("Filter applicable for path {}: {}", path, shouldFilter);
//         return !shouldFilter;
//     }

//     @Override
//     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//             throws ServletException, IOException {
//         log.info("Starting access token validation for request: {}", request.getRequestURI());

//         String authorizationHeader = request.getHeader("Authorization");
//         log.info("Authorization header: {}", authorizationHeader);

//         if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//             String token = authorizationHeader.substring(7);
//             log.info("Bearer token extracted. Token length: {}", token.length());

//             if (isJwt(token)) {
//                 log.info("Token appears to be a JWT; proceeding with JWT validation.");
//                 try {
//                     log.info("Decoding JWT using NimbusJwtDecoder.");
//                     Jwt jwt = getNimbusJwtDecoder().decode(token);
//                     log.info("JWT decoded successfully. Claims: {}", jwt.getClaims());

//                     // Populate ParsedAccessToken with claims and calculated at_hash
//                     parsedAccessToken.setClaims(new HashMap<>());
//                     parsedAccessToken.getClaims().putAll(jwt.getClaims());
//                     parsedAccessToken.setAccessTokenHash(CommonUtil.generateOIDCAtHash(token));
//                     parsedAccessToken.setActive(true);
//                     log.info("Access token is active and valid. Continuing filter chain.");
                    
//                     filterChain.doFilter(request, response);
//                     return;
//                 } catch (Exception e) {
//                     log.error("Access token validation failed: {}", e.getMessage(), e);
//                 }
//             } else {
//                 log.warn("Token does not appear to be a JWT; assuming opaque token. Skipping JWT validation.");
//             }
//         } else {
//             log.warn("Authorization header missing or does not start with 'Bearer '.");
//         }

//         log.error("No valid Bearer token provided; marking access token as inactive and continuing filter chain.");
//         parsedAccessToken.setActive(false);
//         filterChain.doFilter(request, response);
//     }
// }


