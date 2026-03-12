package com.demo.service;

import com.demo.models.FinishRequest;

import com.demo.models.StartRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;

import java.nio.ByteBuffer;
import java.util.UUID;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RegisterController {

    private final RelyingParty relyingParty;
    private final ObjectMapper objectMapper;
    private final CredentialRepositoryStub credentialRepository;

    private final ConcurrentHashMap<String, PendingChallenge> pendingRegistrations = new ConcurrentHashMap<>();

    private record PendingChallenge(String username, String optionsJson) {}

    // =========================================================================
    // REGISTRATION — START
    // =========================================================================
    @PostMapping("/registration/start")
    public ResponseEntity<?> start(@RequestBody StartRequest req) throws Exception {
        String username = req.getUsername();
        if (username == null || username.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username is required"));
        }

        ByteArray userHandle = new ByteArray(username.getBytes(StandardCharsets.UTF_8));

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(username)
                .id(userHandle)
                .build();

        AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .authenticatorSelection(authenticatorSelection)
                        .timeout(60_000L)
                        .build());

        String registrationId = UUID.randomUUID().toString();
        pendingRegistrations.put(registrationId, new PendingChallenge(username, options.toJson()));

        return ResponseEntity.ok(Map.of(
                "registrationId", registrationId,
                "publicKey", objectMapper.readTree(options.toCredentialsCreateJson())
        ));
    }

    // =========================================================================
    // REGISTRATION — FINISH
    // =========================================================================
    @PostMapping("/registration/finish")
    public ResponseEntity<?> finish(@RequestBody FinishRequest req) throws Exception {
        PendingChallenge pending = pendingRegistrations.remove(req.getRegistrationId());
        if (pending == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown or expired registrationId"));
        }

        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                PublicKeyCredential.parseRegistrationResponseJson(req.getPublicKeyCredentialString());

        PublicKeyCredentialCreationOptions savedOptions =
                PublicKeyCredentialCreationOptions.fromJson(pending.optionsJson());

        RegistrationResult result;
        try {
            result = relyingParty.finishRegistration(
                    FinishRegistrationOptions.builder()
                            .request(savedOptions)
                            .response(pkc)
                            .build());
        } catch (RegistrationFailedException e) {
            log.error("finishRegistration failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }

        AuthenticatorAttestationResponse attestationResponse = pkc.getResponse();
        AttestationObject attestationObject = attestationResponse.getAttestation();

        String attestationFormat        = attestationObject.getFormat();
        ObjectNode attestationStatement = attestationObject.getAttestationStatement();

        ByteArray aaguidBytes = result.getAaguid();
        ByteBuffer bb = ByteBuffer.wrap(aaguidBytes.getBytes());
        String aaguid = new UUID(bb.getLong(), bb.getLong()).toString();

        String credentialId  = result.getKeyId().getId().getBase64Url();
        String publicKeyCose = result.getPublicKeyCose().getBase64Url();

        AuthenticatorData   authData   = attestationResponse.getParsedAuthenticatorData();
        CollectedClientData clientData = attestationResponse.getClientData();

        ObjectNode dump = objectMapper.createObjectNode();
        dump.put("flow",              "registration");
        dump.put("timestamp",         Instant.now().toString());
        dump.put("username",          pending.username());
        dump.put("credentialId",      credentialId);
        dump.put("publicKeyCose",     publicKeyCose);
        dump.put("aaguid",            aaguid);
        dump.put("attestationFormat", attestationFormat);
        dump.set("attestationStatement", attestationStatement);

        ObjectNode flags = objectMapper.createObjectNode();
        flags.put("UP", authData.getFlags().UP);
        flags.put("UV", authData.getFlags().UV);
        flags.put("AT", authData.getFlags().AT);
        flags.put("ED", authData.getFlags().ED);
        flags.put("BE", authData.getFlags().BE);
        flags.put("BS", authData.getFlags().BS);
        dump.set("authenticatorDataFlags", flags);
        dump.put("signCount", authData.getSignatureCounter());
        dump.put("rpIdHash",  authData.getRpIdHash().getBase64Url());

        authData.getAttestedCredentialData().ifPresent(acd -> {
            ObjectNode acdNode = objectMapper.createObjectNode();
            ByteBuffer acdBb = ByteBuffer.wrap(acd.getAaguid().getBytes());
            acdNode.put("aaguid",       new UUID(acdBb.getLong(), acdBb.getLong()).toString());
            acdNode.put("credentialId", acd.getCredentialId().getBase64Url());
            dump.set("attestedCredentialData", acdNode);
        });

        ObjectNode clientDataNode = objectMapper.createObjectNode();
        clientDataNode.put("type",      clientData.getType());
        clientDataNode.put("origin",    clientData.getOrigin());
        clientDataNode.put("challenge", clientData.getChallenge().getBase64Url());
        dump.set("clientData", clientDataNode);

        dump.put("attestationType",    result.getAttestationType().name());
        dump.put("attestationTrusted", result.isAttestationTrusted());
        dump.put("userVerified",       result.isUserVerified());
        dump.put("backupEligible",     result.isBackupEligible());
        dump.put("backedUp",           result.isBackedUp());
        result.isDiscoverable().ifPresentOrElse(
                v  -> dump.put("discoverable", v),
                () -> dump.put("discoverable", "unknown")
        );
        result.getAuthenticatorAttachment().ifPresent(a ->
                dump.put("authenticatorAttachment", a.getValue())
        );

        if (attestationStatement.has("x5c")) {
            com.fasterxml.jackson.databind.node.ArrayNode certsDecoded = objectMapper.createArrayNode();
            for (com.fasterxml.jackson.databind.JsonNode certNode : attestationStatement.get("x5c")) {
                try {
                    byte[] certBytes = java.util.Base64.getDecoder().decode(certNode.asText());
                    java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                            java.security.cert.CertificateFactory.getInstance("X.509")
                                    .generateCertificate(new java.io.ByteArrayInputStream(certBytes));
                    ObjectNode certInfo = objectMapper.createObjectNode();
                    certInfo.put("subject",      cert.getSubjectX500Principal().getName());
                    certInfo.put("issuer",       cert.getIssuerX500Principal().getName());
                    certInfo.put("serialNumber", cert.getSerialNumber().toString(16));
                    certInfo.put("notBefore",    cert.getNotBefore().toInstant().toString());
                    certInfo.put("notAfter",     cert.getNotAfter().toInstant().toString());
                    certInfo.put("sigAlg",       cert.getSigAlgName());
                    certsDecoded.add(certInfo);
                } catch (Exception e) {
                    certsDecoded.add("(failed to decode: " + e.getMessage() + ")");
                }
            }
            dump.set("x5cDecoded", certsDecoded);
        }

        result.getAttestationTrustPath().ifPresent(chain -> {
            com.fasterxml.jackson.databind.node.ArrayNode trustPath = objectMapper.createArrayNode();
            for (java.security.cert.X509Certificate cert : chain) {
                ObjectNode certInfo = objectMapper.createObjectNode();
                try {
                    certInfo.put("subject", cert.getSubjectX500Principal().getName());
                    certInfo.put("issuer",  cert.getIssuerX500Principal().getName());
                    trustPath.add(certInfo);
                } catch (Exception ignored) {}
            }
            dump.set("attestationTrustPath", trustPath);
        });

        writeDumpToFile(dump, "registration-" + pending.username());

        // Store in repository so finishAssertion() can look it up
        ByteArray userHandle = new ByteArray(pending.username().getBytes(StandardCharsets.UTF_8));
        credentialRepository.storeCredential(
                pending.username(),
                userHandle,
                RegisteredCredential.builder()
                        .credentialId(result.getKeyId().getId())
                        .userHandle(userHandle)
                        .publicKeyCose(result.getPublicKeyCose())
                        .signatureCount(result.getSignatureCount())
                        .build()
        );

        log.info("[REGISTRATION] username={} aaguid={} format={} type={} credentialId={}",
                pending.username(), aaguid, attestationFormat, result.getAttestationType().name(), credentialId);

        ObjectNode response = objectMapper.createObjectNode();
        response.put("status",            "ok");
        response.put("username",          pending.username());
        response.put("credentialId",      credentialId);
        response.put("aaguid",            aaguid);
        response.put("attestationFormat", attestationFormat);
        response.set("attestationStatement", attestationStatement);

        return ResponseEntity.ok(response);
    }

    // =========================================================================
    // File dump — flow+username prefix, timestamped so nothing overwrites
    // =========================================================================
    private void writeDumpToFile(ObjectNode dump, String label) {
        try {
            String timestamp = Instant.now().toString().replace(":", "-").replace(".", "-");
            Path dumpFile = Path.of(label + "-" + timestamp + ".json");
            String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dump);
            Files.writeString(dumpFile, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log.info("Dump written to {}", dumpFile.toAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to write dump", e);
        }
    }
}
