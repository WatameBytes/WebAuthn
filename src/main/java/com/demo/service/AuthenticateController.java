package com.demo.service;

import com.demo.models.FinishRequestA;
import com.demo.models.FinishResponseA;
import com.demo.models.StartResponseA;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
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
public class AuthenticateController {

    private final RelyingParty relyingParty;
    private final ObjectMapper objectMapper;

    // assertionId -> AssertionRequest JSON
    private final ConcurrentHashMap<String, String> pendingAssertions = new ConcurrentHashMap<>();

    // -------------------------------------------------------------------------
    // POST /authenticate/start
    // Body: {} — usernameless, no username required
    // -------------------------------------------------------------------------
    @PostMapping("/authenticate/start")
    public ResponseEntity<?> start() throws Exception {
        AssertionRequest request = relyingParty.startAssertion(
                StartAssertionOptions.builder()
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .timeout(60_000L)
                        .build());

        String assertionId = UUID.randomUUID().toString();
        pendingAssertions.put(assertionId, request.toJson());

        // toCredentialsGetJson() wraps under "publicKey" — that's the shape the browser expects
        StartResponseA response = new StartResponseA();
        response.setAssertionId(assertionId);
        response.setCredentialJson(request.toCredentialsGetJson());

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // POST /authenticate/finish
    // Body: { "assertionId": "...", "publicKeyCredentialJson": "<JSON from browser>" }
    // Not calling finishAssertion yet — just parsing and logging what came back
    // -------------------------------------------------------------------------
    @PostMapping("/authenticate/finish")
    public ResponseEntity<?> finish(@RequestBody FinishRequestA req) throws Exception {
        String savedJson = pendingAssertions.remove(req.getAssertionId());
        if (savedJson == null) {
            return ResponseEntity.badRequest().body(new FinishResponseA("Unknown or expired assertionId"));
        }

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                PublicKeyCredential.parseAssertionResponseJson(req.getPublicKeyCredentialJson());

        AuthenticatorAssertionResponse assertionResponse = pkc.getResponse();
        AuthenticatorData authData = assertionResponse.getParsedAuthenticatorData();
        CollectedClientData clientData = assertionResponse.getClientData();

        // Decode username from userHandle — we encoded it as UTF-8 bytes during registration
        String username = assertionResponse.getUserHandle()
                .map(uh -> new String(uh.getBytes(), StandardCharsets.UTF_8))
                .orElse("unknown");

        // -----------------------------------------------------------------
        // Build the dump document
        // -----------------------------------------------------------------
        ObjectNode dump = objectMapper.createObjectNode();
        dump.put("timestamp",    Instant.now().toString());
        dump.put("credentialId", pkc.getId().getBase64Url());

        // userHandle — present for discoverable credentials, absent for non-discoverable
        assertionResponse.getUserHandle()
                .ifPresentOrElse(
                        uh -> dump.put("userHandle", uh.getBase64Url()),
                        () -> dump.put("userHandle", "(not present)")
                );
        dump.put("usernameDecoded", username);

        // Signature — raw bytes, base64url encoded
        dump.put("signature", assertionResponse.getSignature().getBase64Url());

        // AuthenticatorData flags
        ObjectNode flags = objectMapper.createObjectNode();
        flags.put("UP", authData.getFlags().UP); // user present
        flags.put("UV", authData.getFlags().UV); // user verified
        flags.put("AT", authData.getFlags().AT); // attested credential data — will be false in assertion
        flags.put("ED", authData.getFlags().ED); // extension data
        flags.put("BE", authData.getFlags().BE); // backup eligible
        flags.put("BS", authData.getFlags().BS); // backup state
        dump.set("authenticatorDataFlags", flags);

        dump.put("signCount", authData.getSignatureCounter());
        dump.put("rpIdHash",  authData.getRpIdHash().getBase64Url());

        // Authenticator attachment — "platform" or "cross-platform" if present
        pkc.getAuthenticatorAttachment()
                .ifPresent(a -> dump.put("authenticatorAttachment", a.getValue()));

        // Client data
        ObjectNode clientDataNode = objectMapper.createObjectNode();
        clientDataNode.put("type",      clientData.getType());
        clientDataNode.put("origin",    clientData.getOrigin());
        clientDataNode.put("challenge", clientData.getChallenge().getBase64Url());
        dump.set("clientData", clientDataNode);

        // Raw authenticatorData bytes — useful to compare with registration authData
        dump.put("authenticatorDataRaw", assertionResponse.getAuthenticatorData().getBase64Url());

        // -----------------------------------------------------------------
        // finishAssertion — cryptographic verification
        // -----------------------------------------------------------------
        AssertionRequest savedRequest = AssertionRequest.fromJson(savedJson);
        AssertionResult result;
        try {
            result = relyingParty.finishAssertion(
                    FinishAssertionOptions.builder()
                            .request(savedRequest)
                            .response(pkc)
                            .build());
        } catch (AssertionFailedException e) {
            log.error("finishAssertion failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new FinishResponseA("Assertion failed: " + e.getMessage()));
        }

        // If we reach here, everything is cryptographically verified:
        // challenge matched, signature valid, origin correct, rpIdHash correct, counter valid
        dump.put("assertionVerified",       true);
        dump.put("username",                result.getUsername());
        dump.put("userHandle",              result.getUserHandle().getBase64Url());
        dump.put("verifiedCredentialId",    result.getCredentialId().getBase64Url());
        dump.put("userVerified",            result.isUserVerified());
        dump.put("signCountAfter",          result.getSignatureCount());
        result.getAuthenticatorAttachment()
                .ifPresent(a -> dump.put("authenticatorAttachment", a.getValue()));

        writeDumpToFile(dump, username);

        log.info("=== ASSERTION VERIFIED ===");
        log.info("username={} credentialId={} UV={} signCount={}",
                result.getUsername(), result.getCredentialId().getBase64Url(),
                result.isUserVerified(), result.getSignatureCount());

        return ResponseEntity.ok(new FinishResponseA("Authenticated: " + result.getUsername()));
    }

    private void writeDumpToFile(ObjectNode dump, String username) {
        try {
            String timestamp = Instant.now().toString().replace(":", "-").replace(".", "-");
            Path dumpFile = Path.of(username + "-Authenticate-" + timestamp + ".json");

            String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dump);
            Files.writeString(dumpFile, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log.info("Assertion dump written to {}", dumpFile.toAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to write assertion dump", e);
        }
    }
}
