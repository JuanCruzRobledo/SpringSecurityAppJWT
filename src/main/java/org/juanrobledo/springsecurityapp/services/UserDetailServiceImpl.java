package org.juanrobledo.springsecurityapp.services;

import org.juanrobledo.springsecurityapp.controllers.dto.AuthCreateUserRequest;
import org.juanrobledo.springsecurityapp.controllers.dto.AuthLoginRequest;
import org.juanrobledo.springsecurityapp.controllers.dto.AuthResponse;
import org.juanrobledo.springsecurityapp.persistence.entity.RoleEntity;
import org.juanrobledo.springsecurityapp.persistence.entity.UserEntity;
import org.juanrobledo.springsecurityapp.persistence.repository.RoleRepository;
import org.juanrobledo.springsecurityapp.persistence.repository.UserEntityRepository;
import org.juanrobledo.springsecurityapp.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserEntityRepository entityRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RoleRepository roleRepository;
    private final UserEntityRepository userEntityRepository;

    public UserDetailServiceImpl(UserEntityRepository entityRepository, JwtUtils jwtUtils, PasswordEncoder passwordEncoder, RoleRepository roleRepository, UserEntityRepository userEntityRepository) {
        this.entityRepository = entityRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userEntityRepository = userEntityRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = entityRepository.findUserEntitiesByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User "+username+" not found"));

        List<SimpleGrantedAuthority> grantedAuthorityList = new ArrayList<>();
        userEntity.getRoles()
                .forEach(role -> grantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream()).forEach(permission -> grantedAuthorityList.add(new SimpleGrantedAuthority(permission.getName())));
        return new User(
                userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNonExpired(),
                userEntity.isCredentialsNonExpired(),
                userEntity.isAccountNonLocked(),
                grantedAuthorityList
                );
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username,password);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtils.createToken(authentication);

        AuthResponse authResponse = new AuthResponse(username,"User loged successfuly",accessToken , true);

        return authResponse;
    }

    public Authentication authenticate(String username, String password) {
        UserDetails userDetails = this.loadUserByUsername(username);

        if (userDetails == null) {
            throw new UsernameNotFoundException("User "+username+" not found");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest) {
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String> roleRequest = authCreateUserRequest.roleRequest().roleListName();

        Set<RoleEntity> roleEntities = roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest).stream().collect(Collectors.toSet());


        if (roleEntities.isEmpty()) {
            throw new BadCredentialsException("The roles specified do not exist");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(roleEntities)
                .isEnabled(true)
                .isAccountNonLocked(true)
                .isCredentialsNonExpired(true)
                .isAccountNonExpired(true)
                .build();

        UserEntity userCreated = userEntityRepository.save(userEntity);

        ArrayList<SimpleGrantedAuthority> grantedAuthorityList = new ArrayList<>();

        userCreated.getRoles().forEach(role -> grantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        userCreated.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .forEach(permission -> grantedAuthorityList.add(new SimpleGrantedAuthority(permission.getName())));

        Authentication authentication  = new UsernamePasswordAuthenticationToken(userCreated.getUsername(), userCreated.getPassword(), grantedAuthorityList);

        String accessToken = jwtUtils.createToken(authentication);

        AuthResponse authResponse = new AuthResponse(userCreated.getUsername(),"User created successfuly",accessToken, true);
        return authResponse;
    }
}
