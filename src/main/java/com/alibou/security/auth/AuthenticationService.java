package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import org.springframework.mail.SimpleMailMessage;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;
  private final EmailService emailService;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();
    repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }

    public String forgot (ForgorPasswordRequest request) {
      var user = repository.findByEmail(request.getEmail())
              .orElseThrow();
      user.setResetToken(UUID.randomUUID().toString());
      user.setResetTokenExpireDate(new Date(System.currentTimeMillis() + 1000 * 60)); // 1 mim
      repository.save(user);

      String resetUrl = "http://localhost:8080";

      SimpleMailMessage passwordEmailReset = new SimpleMailMessage();
      passwordEmailReset.setFrom("admin@demo.com");
      passwordEmailReset.setTo(user.getEmail());
      passwordEmailReset.setSubject("Password Email Request!");
      passwordEmailReset.setText("To reset your password, click the link below:\n" + resetUrl + "/api/v1/auth/reset?token=" + user.getResetToken());

      emailService.sendEmail(passwordEmailReset);

      return "Email enviado com sucesso para " + user.getEmail();
    }

  public String reset(ResetPasswordRequest request, String token) {
    var user = repository.findByResetToken(token)
            .orElseThrow();

    Date expireDate = user.getResetTokenExpireDate();
    Date now = new Date(System.currentTimeMillis());

    if (now.before(expireDate)) {
      user.setPassword(passwordEncoder.encode(request.getNewPassword()));
      user.setResetToken(null);
      user.setResetTokenExpireDate(null);
      repository.save(user);
      return "Your password was updated succesfully!";
    } else {
      user.setResetToken(null);
      user.setResetTokenExpireDate(null);
      repository.save(user);
      return "The link has expired!";
    }
  }
}
