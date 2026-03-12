package com.demo.config;

import com.demo.service.CredentialRepositoryStub;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class BackendConfig {

    @Value("${app.relying-party-id}")
    private String relyingPartyId;

    @Value("${app.relying-party-name}")
    private String relyingPartyName;

    @Value("${app.relying-party-origins}")
    private String relyingPartyOrigins;

    @Bean
    public RelyingParty relyingParty(CredentialRepositoryStub stub) {
        Set<String> origins = Arrays.stream(relyingPartyOrigins.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id(relyingPartyId)
                        .name(relyingPartyName)
                        .build())
                .credentialRepository(stub)
                .origins(origins)
                // Request full attestation from the authenticator
                .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
                // Don't reject attestations that aren't in a trusted metadata store
                .allowUntrustedAttestation(true)
                .build();
    }
}
