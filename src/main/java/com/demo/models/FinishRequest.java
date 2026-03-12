package com.demo.models;

import lombok.Data;

@Data
public class FinishRequest {
    private String registrationId;
    // Raw JSON string of the PublicKeyCredential from navigator.credentials.create()
    private String publicKeyCredentialString;
}