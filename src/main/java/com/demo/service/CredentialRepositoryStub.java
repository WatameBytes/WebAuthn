package com.demo.service;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stub CredentialRepository.
 *
 * We only care about capturing attestation data from finishRegistration(),
 * not about building a real credential lookup chain. Everything returns
 * empty — Yubico still runs the full attestation verification path regardless.
 */
/**
 * In-memory CredentialRepository.
 * RegisterController stores credentials here after a successful registration.
 * AuthenticateController's finishAssertion() looks them up here.
 */
@Component
public class CredentialRepositoryStub implements CredentialRepository {

    // credentialId (base64url) -> RegisteredCredential
    private final ConcurrentHashMap<String, RegisteredCredential> store = new ConcurrentHashMap<>();

    // username -> set of credential IDs (for getCredentialIdsForUsername)
    private final ConcurrentHashMap<String, Set<ByteArray>> byUsername = new ConcurrentHashMap<>();

    // userHandle (base64url) -> username
    private final ConcurrentHashMap<String, String> userHandleToUsername = new ConcurrentHashMap<>();

    public void storeCredential(String username, ByteArray userHandle, RegisteredCredential credential) {
        store.put(credential.getCredentialId().getBase64Url(), credential);
        byUsername.computeIfAbsent(username, k -> ConcurrentHashMap.newKeySet())
                .add(credential.getCredentialId());
        userHandleToUsername.put(userHandle.getBase64Url(), username);
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Set<ByteArray> ids = byUsername.getOrDefault(username, Collections.emptySet());
        Set<PublicKeyCredentialDescriptor> descriptors = new HashSet<>();
        for (ByteArray id : ids) {
            descriptors.add(PublicKeyCredentialDescriptor.builder().id(id).build());
        }
        return descriptors;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userHandleToUsername.entrySet().stream()
                .filter(e -> e.getValue().equals(username))
                .findFirst()
                .map(e -> {
                    try { return ByteArray.fromBase64Url(e.getKey()); }
                    catch (Exception ex) { return null; }
                });
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return Optional.ofNullable(userHandleToUsername.get(userHandle.getBase64Url()));
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return Optional.ofNullable(store.get(credentialId.getBase64Url()));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        RegisteredCredential cred = store.get(credentialId.getBase64Url());
        return cred != null ? Set.of(cred) : Collections.emptySet();
    }
}