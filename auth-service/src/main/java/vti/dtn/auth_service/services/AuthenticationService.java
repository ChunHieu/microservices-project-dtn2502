package vti.dtn.auth_service.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import vti.dtn.auth_service.dto.reponse.LoginResponse;
import vti.dtn.auth_service.dto.reponse.RegisterResponse;
import vti.dtn.auth_service.dto.reponse.VerifyTokenResponse;
import vti.dtn.auth_service.dto.request.LoginRequest;
import vti.dtn.auth_service.dto.request.RegisterRequest;
import vti.dtn.auth_service.entity.UserEntity;
import vti.dtn.auth_service.entity.enums.Role;
import vti.dtn.auth_service.repo.UserRepository;

import java.util.Base64;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final int TOKEN_INDEX = 7;

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public RegisterResponse register(RegisterRequest registerRequest){
        String email = registerRequest.getEmail();
        String userName = registerRequest.getUsername();
        String password = registerRequest.getPassword();
        String role = registerRequest.getRole();
        String firstName = registerRequest.getFirstName();
        String lastName = registerRequest.getLastName();

        Optional<UserEntity> userEntityByEmail = userRepository.findByEmail(email);
        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(userName);

        if (userEntityByEmail.isPresent() || userEntityByUsername.isPresent()) {
            return RegisterResponse.builder()
                    .status(400)
                    .message("User already exists!")
                    .build();
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userName)
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .password(passwordEncoder.encode(password)) // ⚠️ Should be encoded!
                .role(Role.toEnum(role)) // Convert string role to enum
                .build();

        userRepository.save(userEntity);

        return RegisterResponse.builder()
                .status(HttpStatus.SC_OK)
                .message("User created successfully")
                .build();

    }

    public LoginResponse login(LoginRequest loginRequest){
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(username);
        if(userEntityByUsername.isPresent()){
            UserEntity userEntity = userEntityByUsername.get();
            String accessToken = jwtService.generateAccessToken(userEntity);
            String refreshToken = jwtService.generateRefreshToken(userEntity);

            userEntity.setAccessToken(accessToken);
            userEntity.setRefreshToken(refreshToken);
            userRepository.save(userEntity);

            return LoginResponse.builder()
                    .status(HttpStatus.SC_OK)
                    .message("Login successful")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(userEntity.getId())
                    .build();
        }else {
            return LoginResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid username or password")
                    .build();
        }
    }

    public  LoginResponse refreshToken(String authHeader){
        if(!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")){
            return LoginResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid token")
                    .build();
        }
        String refreshToken = authHeader.substring(TOKEN_INDEX);
        if( !jwtService.validateToken(refreshToken)) {
            return LoginResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid refresh token")
                    .build();
        }

        String username = jwtService.extractUsername(refreshToken);

        Optional<UserEntity> userFoundByUsername = userRepository.findByUsername(username);
        if (userFoundByUsername.isEmpty()) {
            return LoginResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Token revoked")
                    .build();
        }

        UserEntity userEntity = userFoundByUsername.get();
        String accessToken = jwtService.generateAccessToken(userEntity);
        String newRefreshToken = jwtService.generateRefreshToken(userEntity);

        userEntity.setAccessToken(accessToken);
        userEntity.setRefreshToken(newRefreshToken);
        userRepository.save(userEntity);

        //Response access token and refresh token to client
        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(userEntity.getId())
                .message("Refresh token successfully")
                .status(HttpStatus.SC_OK)
                .build();

    }

    public VerifyTokenResponse verifyToken(String authHeader) { // usage new
        log.info("verifyToken|authHeader: {}", authHeader);

        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            log.error("verifyToken|Authorization header is missing or invalid");
            return VerifyTokenResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid token")
                    .build();
        }

        String token = authHeader.substring(TOKEN_INDEX);
        if( !jwtService.validateToken(token)) {
            log.error("verifyToken|Invalid refresh token");
            return VerifyTokenResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid refresh token")
                    .build();
        }

        String username = jwtService.extractUsername(token);

        Optional<UserEntity> userFoundByUsername = userRepository.findByUsername(username);
        if (userFoundByUsername.isEmpty()) {
            log.error("verifyToken|User not found for username: {}", username);
            return VerifyTokenResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Token revoked")
                    .build();
        }

        String role = userFoundByUsername.get().getRole().name();
        String userInfoStr = username + ":" + role;
        String xUserToken = Base64.getEncoder().encodeToString(userInfoStr.getBytes());

        log.info("verifyToken|X-User-Token: {}", xUserToken);
        return VerifyTokenResponse.builder()
                .status(HttpStatus.SC_OK)
                .message("Success")
                .xUserToken(xUserToken)
                .build();
    }
}
