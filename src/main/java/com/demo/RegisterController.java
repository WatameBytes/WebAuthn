package com.demo;

import com.demo.FinishRequest;
import com.demo.StartRequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RegistrationResult;
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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RegisterController {

    private final RelyingParty relyingParty;
    private final ObjectMapper objectMapper;

    // challengeId -> { username, PublicKeyCredentialCreationOptions JSON }
    // Simple in-memory map — no Cassandra, no JPA needed for this exercise
    private final ConcurrentHashMap<String, PendingChallenge> pendingChallenges = new ConcurrentHashMap<>();

    private record PendingChallenge(String username, String optionsJson) {}

    // -------------------------------------------------------------------------
    // POST /registration/start
    // Body: { "username": "rex" }
    // -------------------------------------------------------------------------
    @PostMapping("/registration/start")
    public ResponseEntity<?> start(@RequestBody StartRequest req) throws Exception {
        String username = req.getUsername();
        if (username == null || username.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username is required"));
        }

        // User handle — just UTF-8 bytes of the username keeps it readable in the dump
        ByteArray userHandle = new ByteArray(username.getBytes(StandardCharsets.UTF_8));

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(username)
                .id(userHandle)
                .build();

        AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
                //.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .residentKey(ResidentKeyRequirement.REQUIRED)  // ← actually stores a passkey on the device
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .authenticatorSelection(authenticatorSelection)
                        .timeout(60_000L)
                        .build());

        String registrationId = UUID.randomUUID().toString();
        pendingChallenges.put(registrationId, new PendingChallenge(username, options.toJson()));

        // toCredentialsCreateJson() wraps under "publicKey" — that's the shape the browser expects
        return ResponseEntity.ok(Map.of(
                "registrationId", registrationId,
                "publicKey", objectMapper.readTree(options.toCredentialsCreateJson())
        ));
    }

    // -------------------------------------------------------------------------
    // POST /registration/finish
    // Body: { "registrationId": "...", "publicKeyCredentialString": "<JSON from browser>" }
    // -------------------------------------------------------------------------
    @PostMapping("/registration/finish")
    public ResponseEntity<?> finish(@RequestBody FinishRequest req) throws Exception {
        PendingChallenge pending = pendingChallenges.remove(req.getRegistrationId());
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

        // -----------------------------------------------------------------
        // ATTESTATION EXTRACTION
        // Everything lives on the AttestationObject inside the response
        // -----------------------------------------------------------------
        AuthenticatorAttestationResponse attestationResponse = pkc.getResponse();
        AttestationObject attestationObject = attestationResponse.getAttestation();

        // fmt — e.g. "packed", "fido-u2f", "tpm", "none"
        String attestationFormat = attestationObject.getFormat();

        // attStmt — Yubico already CBOR-decoded this into a Jackson ObjectNode for you
        // For "packed" + YubiKey you'll see: alg (int), sig (bytes), x5c (cert chain)
        ObjectNode attestationStatement = attestationObject.getAttestationStatement();

        // AAGUID — getAaguid() returns a raw 16-byte ByteArray; convert to standard GUID string via UUID
        ByteArray aaguidBytes = result.getAaguid();
        ByteBuffer bb = ByteBuffer.wrap(aaguidBytes.getBytes());
        String aaguid = new UUID(bb.getLong(), bb.getLong()).toString();

        // Credential ID — use getBase64Url(), NOT manual Base64.getEncoder()
        String credentialId = result.getKeyId().getId().getBase64Url();

        // Public key COSE bytes — again, ByteArray gives you getBase64Url() directly
        String publicKeyCose = result.getPublicKeyCose().getBase64Url();

        // AuthenticatorData flags — AuthenticatorData is not generic
        AuthenticatorData authData = attestationResponse.getParsedAuthenticatorData();

        // Client data — Lombok generates getClientData() from the clientData field
        CollectedClientData clientData = attestationResponse.getClientData();

        // -----------------------------------------------------------------
        // Build the dump document
        // -----------------------------------------------------------------
        ObjectNode dump = objectMapper.createObjectNode();
        dump.put("timestamp",         Instant.now().toString());
        dump.put("username",          pending.username());
        dump.put("credentialId",      credentialId);
        dump.put("publicKeyCose",     publicKeyCose);
        dump.put("aaguid",            aaguid);
        dump.put("attestationFormat", attestationFormat);
        dump.set("attestationStatement", attestationStatement);  // full decoded attStmt

        // Flags
        ObjectNode flags = objectMapper.createObjectNode();
        flags.put("UP", authData.getFlags().UP); // user present
        flags.put("UV", authData.getFlags().UV); // user verified
        flags.put("AT", authData.getFlags().AT); // attested credential data included
        flags.put("ED", authData.getFlags().ED); // extension data included
        dump.set("authenticatorDataFlags", flags);
        dump.put("signCount", authData.getSignatureCounter());

        // Attested credential data (nested inside authData)
        authData.getAttestedCredentialData().ifPresent(acd -> {
            ObjectNode acdNode = objectMapper.createObjectNode();
            // acd.getAaguid() is a raw 16-byte ByteArray — same UUID conversion as result.getAaguid()
            ByteBuffer acdBb = ByteBuffer.wrap(acd.getAaguid().getBytes());
            acdNode.put("aaguid",       new UUID(acdBb.getLong(), acdBb.getLong()).toString());
            acdNode.put("credentialId", acd.getCredentialId().getBase64Url());
            dump.set("attestedCredentialData", acdNode);
        });

        // Client data
        ObjectNode clientDataNode = objectMapper.createObjectNode();
        clientDataNode.put("type",      clientData.getType()); // getType() returns String directly
        clientDataNode.put("origin",    clientData.getOrigin());
        clientDataNode.put("challenge", clientData.getChallenge().getBase64Url());
        dump.set("clientData", clientDataNode);

        // -----------------------------------------------------------------
        // RegistrationResult — extra fields
        // -----------------------------------------------------------------
        dump.put("attestationType",    result.getAttestationType().name()); // BASIC, SELF, NONE, ANONYMIZATION_CA, etc.
        dump.put("attestationTrusted", result.isAttestationTrusted());       // always false without an attestationTrustSource
        dump.put("userVerified",       result.isUserVerified());             // UV flag
        dump.put("backupEligible",     result.isBackupEligible());           // BE flag — can this key be synced?
        dump.put("backedUp",           result.isBackedUp());                 // BS flag — is it currently synced?
        result.isDiscoverable().ifPresentOrElse(
                v  -> dump.put("discoverable", v),
                () -> dump.put("discoverable", "unknown") // only known if credProps extension present
        );
        result.getAuthenticatorAttachment().ifPresent(a ->
                dump.put("authenticatorAttachment", a.getValue())               // "platform" or "cross-platform"
        );

        // rpIdHash from authenticator data (SHA-256 of the RP ID — should match hash of "localhost")
        dump.put("rpIdHash", authData.getRpIdHash().getBase64Url());

        // BE / BS flags directly from authData flags
        ObjectNode extraFlags = objectMapper.createObjectNode();
        extraFlags.put("BE", authData.getFlags().BE); // backup eligible
        extraFlags.put("BS", authData.getFlags().BS); // backup state
        dump.set("authenticatorDataFlagsExtra", extraFlags);

        // Decoded x5c certificate chain — subject, issuer, serial, validity per cert
        // The raw certs are already in attestationStatement.x5c, but decoded they're much more readable
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

        // Attestation trust path (only populated if attestationTrustSource is configured on the RP)
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

        writeDumpToFile(dump, pending.username());

        log.info("username={} aaguid={} format={} attestationType={} credentialId={}",
                pending.username(), aaguid, attestationFormat, result.getAttestationType().name(), credentialId);

        // Return the key fields in the response so you can also see them in the browser
        ObjectNode response = objectMapper.createObjectNode();
        response.put("status",            "ok");
        response.put("username",          pending.username());
        response.put("credentialId",      credentialId);
        response.put("aaguid",            aaguid);
        response.put("attestationFormat", attestationFormat);
        response.set("attestationStatement", attestationStatement);

        return ResponseEntity.ok(response);
    }

    private void writeDumpToFile(ObjectNode dump, String username) {
        try {
            // File named after the username — easy to find after registering a real key
            // Append timestamp so multiple registrations for the same user don't overwrite
            String timestamp = Instant.now().toString().replace(":", "-").replace(".", "-");
            Path dumpFile = Path.of(username + "-" + timestamp + ".json");

            String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dump);
            Files.writeString(dumpFile, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log.info("Attestation written to {}", dumpFile.toAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to write attestation dump", e);
        }
    }
}