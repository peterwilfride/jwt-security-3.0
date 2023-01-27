package com.alibou.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
  private final AuthenticationService service;
  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody RegisterRequest request
  ) {
    return ResponseEntity.ok(service.register(request));
  }
  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody AuthenticationRequest request
  ) {
    return ResponseEntity.ok(service.authenticate(request));
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<String> forgot(
          @RequestBody ForgorPasswordRequest request
  ) {
    return ResponseEntity.ok(service.forgot(request));
  }

  @PostMapping("/reset")
  public ResponseEntity<String> reset(
          @RequestBody ResetPasswordRequest request,
          @RequestParam String token
  ) {
    return ResponseEntity.ok(service.reset(request, token));
  }

  /*
  @GetMapping("/teste")
  public ResponseEntity<String> teste(HttpServletRequest request) {
    String res = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
    return ResponseEntity.ok().body(res);
  }*/
}
