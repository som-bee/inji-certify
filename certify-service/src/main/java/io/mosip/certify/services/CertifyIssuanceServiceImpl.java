/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.*;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialMetadata;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialRequestNew;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.AuditHelper;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.validators.CredentialRequestValidator;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.utils.JwtUtils;
import io.mosip.certify.vcsigners.VCSigner;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

    public static final Map<String, List<String>> keyChooser = Map.of(
            SignatureAlg.RSA_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_RSA, Constants.EMPTY_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2018,
            List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2020,
            List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID));
    @Value("${mosip.certify.data-provider-plugin.issuer.vc-sign-algo:Ed25519Signature2020}")
    private String vcSignAlgorithm;
    @Value("#{${mosip.certify.key-values}}")
    private LinkedHashMap<String, LinkedHashMap<String, Object>> issuerMetadata;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private VCSigner vcSigner;

    @Autowired
    private DataProviderPlugin dataProviderPlugin;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerURI;

    @Value("${mosip.certify.data-provider-plugin.issuer-public-key-uri}")
    private String issuerPublicKeyURI;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String renderTemplateId;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    private KeymanagerService keymanagerService;

    private Map<String, Object> didDocument;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {

        log.info("Received credential request at CertifyIsussanceService: {}", credentialRequest);
        // 1. Credential Request validation
        boolean isValidCredentialRequest = CredentialRequestValidator.isValid(credentialRequest);
        if (!isValidCredentialRequest) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();
        // 2. Scope Validation
        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialMetadata credentialMetadata = null;
        for (String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat());
            if (result.isPresent()) {
                credentialMetadata = result.get(); // considering only first credential scope
                break;
            }
        }

        if (credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        ProofValidator proofValidator = proofValidatorFactory
                .getProofValidator(credentialRequest.getProof().getProof_type());
        if (!proofValidator.validate((String) parsedAccessToken.getClaims().get(Constants.CLIENT_ID),
                getValidClientNonce(),
                credentialRequest.getProof())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        // 4. Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return getCredentialResponse(credentialRequest.getFormat(), vcResult);
    }

    @Override
    public Map<String, Object> getCredentialIssuerMetadata(String version) {
        if (issuerMetadata.containsKey(version)) {
            return issuerMetadata.get(version);
        } else if (version != null && version.equals("vd12")) {
            LinkedHashMap<String, Object> originalIssuerMetadata = new LinkedHashMap<>(issuerMetadata.get("latest"));
            Map<String, Object> vd12IssuerMetadata = convertLatestToVd12(originalIssuerMetadata);
            issuerMetadata.put("vd12", (LinkedHashMap<String, Object>) vd12IssuerMetadata);
            return vd12IssuerMetadata;
        } else if (version != null && version.equals("vd11")) {
            LinkedHashMap<String, Object> originalIssuerMetadata = new LinkedHashMap<>(issuerMetadata.get("latest"));
            Map<String, Object> vd11IssuerMetadata = convertLatestToVd11(originalIssuerMetadata);
            issuerMetadata.put("vd11", (LinkedHashMap<String, Object>) vd11IssuerMetadata);
            return vd11IssuerMetadata;
        }
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_OPENID_VERSION);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        if (didDocument != null)
            return didDocument;

        KeyPairGenerateResponseDto keyPairGenerateResponseDto = keymanagerService.getCertificate(
                keyChooser.get(vcSignAlgorithm).getFirst(), Optional.of(keyChooser.get(vcSignAlgorithm).getLast()));
        String certificateString = keyPairGenerateResponseDto.getCertificate();

        didDocument = DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI,
                issuerPublicKeyURI);
        return didDocument;
    }

    private Map<String, Object> convertLatestToVd11(LinkedHashMap<String, Object> vciMetadata) {
        // Create a list to hold the transformed credentials
        List<Map<String, Object>> credentialsList = new ArrayList<>();

        // Check if the original config contains 'credential_configurations_supported'
        if (vciMetadata.containsKey("credential_configurations_supported")) {
            // Cast the value to a Map
            Map<String, Object> originalCredentials = (Map<String, Object>) vciMetadata
                    .get("credential_configurations_supported");

            // Iterate through each credential
            for (Map.Entry<String, Object> entry : originalCredentials.entrySet()) {
                // Cast the credential configuration
                Map<String, Object> credConfig = (Map<String, Object>) entry.getValue();

                // Create a new transformed credential configuration
                Map<String, Object> transformedCredential = new HashMap<>(credConfig);

                // Add 'id' field with the original key
                transformedCredential.put("id", entry.getKey());

                // Rename 'credential_signing_alg_values_supported' to
                // 'cryptographic_suites_supported'
                if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                    transformedCredential.put("cryptographic_suites_supported",
                            transformedCredential.remove("credential_signing_alg_values_supported"));
                }

                // Modify proof_types_supported
                if (transformedCredential.containsKey("proof_types_supported")) {
                    Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential
                            .get("proof_types_supported");
                    transformedCredential.put("proof_types_supported", proofTypes.keySet());
                }

                if (transformedCredential.containsKey("display")) {
                    List<Map<String, Object>> displayMapList = new ArrayList<>(
                            (List<Map<String, Object>>) transformedCredential.get("display"));
                    List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                    for (Map<String, Object> map : displayMapList) {
                        Map<String, Object> displayMap = new HashMap<>(map);
                        displayMap.remove("background_image");
                        newDisplayMapList.add(displayMap);
                    }
                    transformedCredential.put("display", newDisplayMapList);
                }

                // Remove 'order' if it exists
                transformedCredential.remove("order");

                // Add the transformed credential to the list
                credentialsList.add(transformedCredential);
            }

            // Set the transformed credentials in the new configuration
            vciMetadata.put("credentials_supported", credentialsList);
        }

        vciMetadata.remove("credential_configurations_supported");
        vciMetadata.remove("authorization_servers");
        vciMetadata.remove("display");
        String endpoint = (String) vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex + 9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd11/credential");
        return vciMetadata;
    }

    private Map<String, Object> convertLatestToVd12(LinkedHashMap<String, Object> vciMetadata) {
        // Create a new map to store the transformed configuration
        if (vciMetadata.containsKey("credential_configurations_supported")) {
            LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata
                    .get("credential_configurations_supported");
            Map<String, Object> transformedMap = transformCredentialConfiguration(supportedCredentials);
            vciMetadata.put("credentials_supported", transformedMap);
        }

        vciMetadata.remove("credential_configurations_supported");
        String endpoint = (String) vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex + 9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd12/credential");
        return vciMetadata;
    }

    private static Map<String, Object> transformCredentialConfiguration(LinkedHashMap<String, Object> originalConfig) {
        Map<String, Object> transformedConfig = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : originalConfig.entrySet()) {
            Map<String, Object> credentialDetails = (Map<String, Object>) entry.getValue();

            // Create a new map to store modified credential details
            Map<String, Object> transformedCredential = new LinkedHashMap<>(credentialDetails);

            // Replace 'credential_signing_alg_values_supported' with
            // 'cryptographic_suites_supported'
            if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                Object signingAlgs = transformedCredential.remove("credential_signing_alg_values_supported");
                transformedCredential.put("cryptographic_suites_supported", signingAlgs);
            }

            // Modify proof_types_supported
            if (transformedCredential.containsKey("proof_types_supported")) {
                Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential
                        .get("proof_types_supported");
                transformedCredential.put("proof_types_supported", proofTypes.keySet());
            }

            if (transformedCredential.containsKey("display")) {
                List<Map<String, Object>> displayMapList = new ArrayList<>(
                        (List<Map<String, Object>>) transformedCredential.get("display"));
                List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                for (Map<String, Object> map : displayMapList) {
                    Map<String, Object> displayMap = new HashMap<>(map);
                    displayMap.remove("background_image");
                    newDisplayMapList.add(displayMap);
                }
                transformedCredential.put("display", newDisplayMapList);
            }

            // Add the modified credential details to the transformed config
            transformedConfig.put(entry.getKey(), transformedCredential);
        }

        return transformedConfig;
    }

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest,
            CredentialMetadata credentialMetadata,
            String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());

        VCResult<?> vcResult = null;
        switch (credentialRequest.getFormat()) {
            case "ldp_vc":
                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct
                    // one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    templateParams.put(Constants.TEMPLATE_NAME, CredentialUtils.getTemplateName(vcRequestDto));
                    templateParams.put(Constants.ISSUER_URI, issuerURI);
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    jsonObject.put("_holderId", holderId);
                    log.info("holder id: {}", holderId);
                    String unSignedVC = vcFormatter.format(jsonObject, templateParams);
                    log.info("unSignedVC: {}", unSignedVC);
                    Map<String, String> signerSettings = new HashMap<>();
                    // NOTE: This is a quasi implementation to add support for multi-tenancy.
                    signerSettings.put(Constants.APPLICATION_ID, keyChooser.get(vcSignAlgorithm).getFirst());
                    signerSettings.put(Constants.REFERENCE_ID, keyChooser.get(vcSignAlgorithm).getLast());
                    vcResult = vcSigner.attachSignature(unSignedVC, signerSettings);
                } catch (DataProviderExchangeException e) {
                    throw new CertifyException(e.getErrorCode());
                } catch (JSONException e) {
                    log.error(e.getMessage(), e);
                    throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
        }

        log.info("VC result: {}", vcResult);
        if (vcResult != null && vcResult.getCredential() != null)
            return vcResult;

        log.error("Failed to generate VC : {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

    private CredentialResponse<?> getCredentialResponse(String format, VCResult<?> vcResult) {
        switch (format) {
            case "ldp_vc":
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject) vcResult.getCredential());
                return ldpVcResponse;
        }
        throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
    }

    private Optional<CredentialMetadata> getScopeCredentialMapping(String scope, String format) {
        log.info("Starting getScopeCredentialMapping with scope: {} and format: {}", scope, format);

        // Retrieve issuer metadata
        Map<String, Object> vciMetadata = getCredentialIssuerMetadata("latest");
        log.info("Retrieved credential issuer metadata: {}", vciMetadata);

        // Get supported credential configurations
        LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata
                .get("credential_configurations_supported");
        log.info("Supported credentials: {}", supportedCredentials);

        // Search for a credential configuration that matches the given scope
        Optional<Map.Entry<String, Object>> result = supportedCredentials.entrySet().stream()
                .peek(entry -> log.info("Evaluating credential configuration with key: {} and value: {}",
                        entry.getKey(), entry.getValue()))
                .filter(cm -> {
                    LinkedHashMap<String, Object> value = (LinkedHashMap<String, Object>) cm.getValue();
                    boolean matches = value.get("scope").equals(scope);
                    log.info("Credential configuration with key: {} has scope: {}. Matches target scope '{}': {}",
                            cm.getKey(), value.get("scope"), scope, matches);
                    return matches;
                })
                .findFirst();

        if (result.isPresent()) {
            log.info("Found matching credential configuration with key: {}", result.get().getKey());
            LinkedHashMap<String, Object> metadata = (LinkedHashMap<String, Object>) result.get().getValue();

            // Build CredentialMetadata from metadata
            CredentialMetadata credentialMetadata = new CredentialMetadata();
            credentialMetadata.setFormat((String) metadata.get("format"));
            credentialMetadata.setScope((String) metadata.get("scope"));
            credentialMetadata.setId(result.get().getKey());
            log.info("Initial CredentialMetadata built: {}", credentialMetadata);

            // Process additional definition if format equals LDP_VC
            if (format.equals(VCFormats.LDP_VC)) {
                log.info("Format is LDP_VC. Extracting additional credential definition.");
                LinkedHashMap<String, Object> credentialDefinition = (LinkedHashMap<String, Object>) metadata
                        .get("credential_definition");
                log.info("Credential definition: {}", credentialDefinition);
                credentialMetadata.setTypes((List<String>) credentialDefinition.get("type"));
            }
            log.info("Returning CredentialMetadata: {}", credentialMetadata);
            return Optional.of(credentialMetadata);
        }

        log.warn("No matching credential mapping found for scope: {}", scope);
        return Optional.empty();
    }

    private void validateLdpVcFormatRequest(CredentialRequest credentialRequest,
            CredentialMetadata credentialMetadata) {
        if (!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
            throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

        // TODO need to validate Credential_definition as JsonLD document, if invalid
        // throw exception
    }

    private void validateLdpVcFormatRequest(CredentialRequestNew credentialRequest,
            CredentialMetadata credentialMetadata) {
        if (!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
            throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

        // TODO need to validate Credential_definition as JsonLD document, if invalid
        // throw exception
    }

    private String getValidClientNonce() {
        VCIssuanceTransaction transaction = vciCacheService.getVCITransaction(parsedAccessToken.getAccessTokenHash());
        // If the transaction is null, it means that VCI service never created cNonce,
        // its authorization server issued cNonce
        String cNonce = (transaction == null) ? (String) parsedAccessToken.getClaims().get(Constants.C_NONCE)
                : transaction.getCNonce();
        Object nonceExpireSeconds = parsedAccessToken.getClaims().getOrDefault(Constants.C_NONCE_EXPIRES_IN, 0);
        int cNonceExpire = (transaction == null)
                ? nonceExpireSeconds instanceof Long ? (int) (long) nonceExpireSeconds : (int) nonceExpireSeconds
                : transaction.getCNonceExpireSeconds();
        long issuedEpoch = (transaction == null)
                ? ((Instant) parsedAccessToken.getClaims().getOrDefault(JwtClaimNames.IAT, Instant.MIN))
                        .getEpochSecond()
                : transaction.getCNonceIssuedEpoch();

        if (cNonce == null ||
                cNonceExpire <= 0 ||
                (issuedEpoch + cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)) {
            log.error("Client Nonce not found / expired in the access token, generate new cNonce");
            transaction = createVCITransaction();
            throw new InvalidNonceException(transaction.getCNonce(), transaction.getCNonceExpireSeconds());
        }
        return cNonce;
    }

    private VCIssuanceTransaction createVCITransaction() {
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(securityHelperService.generateSecureRandomString(20));
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        transaction.setCNonceExpireSeconds(cNonceExpireSeconds);
        return vciCacheService.setVCITransaction(parsedAccessToken.getAccessTokenHash(), transaction);
    }

    @Override
    public <T> CredentialResponse<T> getCredentialNew(CredentialRequestNew credentialRequest) {
        log.info("Received credential request: {}", credentialRequest);

        // Validate the credential request
        boolean isValidCredentialRequest = new CredentialRequestValidator().isValid(credentialRequest);
        if (!isValidCredentialRequest) {
            log.error("Credential request is invalid: {}", credentialRequest);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }
        log.info("Credential request validated successfully.");

        // Extract the JWT access token from the proof
        String jwt = credentialRequest.getProof().getJwt();
        String accessToken = credentialRequest.getProof().getAccess_token();
        log.info("Using access token from credential proof: {}", accessToken);

        // Validate the JWT using JwtKeyUtil and obtain the claims set
        JWTClaimsSet claimsSet;
        try {
            claimsSet = JwtUtils.validateToken(accessToken);
        } catch (Exception e) {
            log.error("Failed to validate JWT token: {}", e.getMessage());
            throw new NotAuthenticatedException();
        }

        // Check if the access token is active (i.e. not expired)
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime != null && expirationTime.before(new Date())) {
            log.error("Invalid access token. Access token is expired");
            throw new NotAuthenticatedException();
        }
        log.info("Access token is active.");

        // Extract and process the scope claim
        String scopeClaim = null;
        try {
            scopeClaim = claimsSet.getStringClaim("scope");
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (scopeClaim == null) {
            scopeClaim = "";
        }
        log.info("Extracted scope claim: {}", scopeClaim);
        log.info("Credential format : {}", credentialRequest.getFormat());
        CredentialMetadata credentialMetadata = null;
        String scope = "mock_identity_vc_ldp";
        log.info("Processing scope: {}", scope);
        Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat());
        if (result.isPresent()) {
            credentialMetadata = result.get(); // considering only the first matching credential scope
            log.info("Credential metadata mapping found for scope '{}': {}", scope, credentialMetadata);
        }
        // for (String scope : scopeClaim.split(Constants.SPACE)) {
        // log.info("Processing scope: {}", scope);
        // Optional<CredentialMetadata> result = getScopeCredentialMapping(scope,
        // credentialRequest.getFormat());
        // if (result.isPresent()) {
        // credentialMetadata = result.get(); // considering only the first matching
        // credential scope
        // log.info("Credential metadata mapping found for scope '{}': {}", scope,
        // credentialMetadata);
        // break;
        // }
        // }

        if (credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope: {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        // Validate the proof using the appropriate proof validator
        ProofValidator proofValidator = proofValidatorFactory
                .getProofValidator(credentialRequest.getProof().getProof_type());
                
        log.info("Starting proof validation with validator: {}",
        proofValidator.getClass().getSimpleName());
        boolean isProofValid=false;
        try {
        isProofValid = proofValidator.validate(
        claimsSet.getStringClaim(Constants.CLIENT_ID),
        getValidClientNonce(),
        credentialRequest.getProof());
        } catch (ParseException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
        }
        if (!isProofValid) {
        log.error("Proof validation failed for credential request: {}",
        credentialRequest);
        throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }
        log.info("Proof validation successful.");

        // Retrieve the verifiable credential from the configured plugin implementation
        log.info("Retrieving verifiable credential from the plugin implementation.");
        // VCResult<?> vcResult = getVerifiableCredentialNew(credentialRequest,
        // credentialMetadata,
        // proofValidator.getKeyMaterialNew(credentialRequest.getProof()));
        log.info("Holder ID: {}", proofValidator.getKeyMaterialNew(credentialRequest.getProof()));
        VCResult<?> vcResult = getVerifiableCredentialNew(credentialRequest, credentialMetadata, proofValidator.getKeyMaterialNew(credentialRequest.getProof()));
        log.info("Verifiable credential obtained: {}", vcResult);

        // Log the successful audit using an access token hash computed from the token
        // string
        String accessTokenHash = Integer.toHexString(accessToken.hashCode());
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);
        log.info("Audit log recorded for VC issuance.");

        // Build and return the response
        CredentialResponse response = getCredentialResponseNew(credentialRequest.getFormat(), vcResult);
        log.info("Returning credential response: {}", response);
        return response;
    }

    private CredentialResponse<?> getCredentialResponseNew(String format, VCResult<?> vcResult) {
        switch (format) {
            case "ldp_vc":
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject) vcResult.getCredential());
                return ldpVcResponse;
        }
        throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
    }

    private VCResult<?> getVerifiableCredentialNew(CredentialRequestNew credentialRequest,
            CredentialMetadata credentialMetadata, String holderId) {

        log.info("Starting VC generation process.");

        // parsedAccessToken.getClaims().put("accessTokenHash",
        // parsedAccessToken.getAccessTokenHash());
        // log.info("Added accessTokenHash to claims.");

        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());
        log.info("Initialized VCRequestDto with format: {}", credentialRequest.getFormat());

        VCResult<?> vcResult = null;

        switch (credentialRequest.getFormat()) {
            case "ldp_vc":
                log.info("Processing 'ldp_vc' format.");

                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                log.info("Set context, type, and credentialSubject in VCRequestDto.");

                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                log.info("Validated LDP VC format request.");

                try {
                    log.info("Fetching data from DataProviderPlugin.");
                    log.info("Fetching data from DataProviderPlugin using user info from Singpass.");
                    Map<String, Object> identityDetails = new HashMap<>();
                    // Instead of hardcoding, call the helper method using the access token from the
                    // proof:
                    String subValue = JwtUtils.getSubFromUserInfo(credentialRequest.getProof().getAccess_token());
                    identityDetails.put("sub", subValue);
                    JSONObject jsonObject = dataProviderPlugin.fetchData(identityDetails);

                    Map<String, Object> templateParams = new HashMap<>();
                    templateParams.put(Constants.TEMPLATE_NAME, CredentialUtils.getTemplateName(vcRequestDto));
                    templateParams.put(Constants.ISSUER_URI, issuerURI);

                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                        log.info("Added rendering template ID: {}", renderTemplateId);
                    }

                    // jsonObject.put("_holderId", holderId);
                    // log.info("Added holderId to JSON object.");

                    String unSignedVC = vcFormatter.format(jsonObject, templateParams);
                    log.info("Formatted unsigned VC.");

                    Map<String, String> signerSettings = new HashMap<>();
                    signerSettings.put(Constants.APPLICATION_ID, keyChooser.get(vcSignAlgorithm).getFirst());
                    signerSettings.put(Constants.REFERENCE_ID, keyChooser.get(vcSignAlgorithm).getLast());
                    log.info("Configured signer settings with application ID and reference ID.");

                    vcResult = vcSigner.attachSignature(unSignedVC, signerSettings);
                    log.info("Attached signature to VC.");

                } catch (DataProviderExchangeException e) {
                    log.error("DataProviderExchangeException occurred: {}", e.getErrorCode());
                    throw new CertifyException(e.getErrorCode());
                }
                //  catch (JSONException e) {
                //     log.error("JSONException occurred: {}", e.getMessage(), e);
                //     throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
                // }
                break;
            default:
                log.error("Unsupported VC format: {}", credentialRequest.getFormat());
                throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
        }

        if (vcResult != null && vcResult.getCredential() != null) {
            log.info("Successfully generated VC.");
            return vcResult;
        }

        log.error("Failed to generate VC: {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

}
