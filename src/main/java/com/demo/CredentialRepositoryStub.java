package com.demo;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

/**
 * Stub CredentialRepository.
 *
 * We only care about capturing attestation data from finishRegistration(),
 * not about building a real credential lookup chain. Everything returns
 * empty — Yubico still runs the full attestation verification path regardless.
 */
@Component
public class CredentialRepositoryStub implements CredentialRepository {

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        // No existing credentials to exclude — allow any new registration
        return Collections.emptySet();
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.empty();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return Optional.empty();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return Collections.emptySet();
    }
}