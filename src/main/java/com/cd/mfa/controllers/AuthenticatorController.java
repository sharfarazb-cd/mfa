package com.cd.mfa.controllers;

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.cd.mfa.Secret;
import com.cd.mfa.TotpUtil;


@Controller
@RequestMapping("/mfa")
public class AuthenticatorController {
    @Autowired
    TotpUtil totpUtil;

    @PostMapping("/generate-secret")
    public ResponseEntity<String> generateSecret() {
        return ResponseEntity.status(HttpStatus.OK).body(totpUtil.generateSecret());
    }

    @PostMapping("/generate-qr")
    public ResponseEntity<String> generateQr(@RequestBody Secret secret) {
        return ResponseEntity.status(HttpStatus.OK).body(totpUtil.getQRCodeURL(secret.getSecretKey(), "sample@gmail.com", "whio"));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Boolean> verifyOtp(@RequestBody Secret secret) {
        return ResponseEntity.ok().body(totpUtil.verifyCode(secret.getSecretKey(), secret.getCode()));
    }
}
