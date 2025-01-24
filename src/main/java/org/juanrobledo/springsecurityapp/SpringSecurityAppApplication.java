package org.juanrobledo.springsecurityapp;

import org.juanrobledo.springsecurityapp.persistence.entity.PermissionEntity;
import org.juanrobledo.springsecurityapp.persistence.entity.RoleEntity;
import org.juanrobledo.springsecurityapp.persistence.entity.RoleEnum;
import org.juanrobledo.springsecurityapp.persistence.entity.UserEntity;
import org.juanrobledo.springsecurityapp.persistence.repository.UserEntityRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityAppApplication.class, args);
    }

    @Bean
    CommandLineRunner init(UserEntityRepository userEntityRepository) {
        return args -> {
            /* CREATE PERMISSIONS */
            PermissionEntity permissionEntity1 = PermissionEntity.builder()
                    .name("CREATE")
                    .build();

            PermissionEntity permissionEntity2 = PermissionEntity.builder()
                    .name("READ")
                    .build();

            PermissionEntity permissionEntity3 = PermissionEntity.builder()
                    .name("UPDATE")
                    .build();

            PermissionEntity permissionEntity4 = PermissionEntity.builder()
                    .name("DELETE")
                    .build();

            /* CREATE ROLES */
            RoleEntity roleAdmin = RoleEntity.builder()
                    .roleEnum(RoleEnum.ADMIN)
                    .permissions(Set.of(permissionEntity1, permissionEntity2, permissionEntity3, permissionEntity4))
                    .build();

            RoleEntity roleUser = RoleEntity.builder()
                    .roleEnum(RoleEnum.USER)
                    .permissions(Set.of(permissionEntity1, permissionEntity2))
                    .build();

            RoleEntity roleInvited = RoleEntity.builder()
                    .roleEnum(RoleEnum.INVITED)
                    .permissions(Set.of(permissionEntity1))
                    .build();

            /* CREATE USERS */

            UserEntity userJuan = UserEntity.builder()
                    .username("juan")
                    .password("$2a$10$xsxt9J1x2gnRnR9Irf7dKu3yhkHjVvcHGfXAKaiV/EljByL2oulJW")
                    .isEnabled(true)
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .roles(Set.of(roleAdmin))
                    .build();

            UserEntity userSantiago = UserEntity.builder()
                    .username("santiago")
                    .password("$2a$10$xsxt9J1x2gnRnR9Irf7dKu3yhkHjVvcHGfXAKaiV/EljByL2oulJW")
                    .isEnabled(true)
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .roles(Set.of(roleUser))
                    .build();

            UserEntity userAgustin = UserEntity.builder()
                    .username("agustin")
                    .password("$2a$10$xsxt9J1x2gnRnR9Irf7dKu3yhkHjVvcHGfXAKaiV/EljByL2oulJW")
                    .isEnabled(true)
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .roles(Set.of(roleInvited))
                    .build();

            userEntityRepository.saveAll(List.of(userJuan, userSantiago, userAgustin));
        };
    }
}
