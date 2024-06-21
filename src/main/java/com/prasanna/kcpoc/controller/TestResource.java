package com.prasanna.kcpoc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestResource{

    @GetMapping("/unprotected")
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("\n unprotected endpoint");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> sayHelloToAdmin(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok("\n Hello Admin, needs admin role, token:\n"+jwt.getIssuer()+","+jwt.getClaimAsString("email"));
    }

    @GetMapping("/user")
    public ResponseEntity<String> sayHelloToUser(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok("\n Hello User, needs user role, token:\n"+jwt.getIssuer()+","+jwt.getClaimAsString("email"));
    }
}
