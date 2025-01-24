package org.juanrobledo.springsecurityapp.persistence.repository;

import org.juanrobledo.springsecurityapp.persistence.entity.RoleEntity;
import org.juanrobledo.springsecurityapp.persistence.entity.RoleEnum;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface RoleRepository extends CrudRepository<RoleEntity, Long> {
    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleEnum);
}
