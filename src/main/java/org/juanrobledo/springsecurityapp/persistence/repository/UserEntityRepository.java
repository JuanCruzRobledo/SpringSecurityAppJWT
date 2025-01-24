package org.juanrobledo.springsecurityapp.persistence.repository;

import org.juanrobledo.springsecurityapp.persistence.entity.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserEntityRepository extends CrudRepository<UserEntity, Long> {
    Optional<UserEntity> findUserEntitiesByUsername(String username);
}
