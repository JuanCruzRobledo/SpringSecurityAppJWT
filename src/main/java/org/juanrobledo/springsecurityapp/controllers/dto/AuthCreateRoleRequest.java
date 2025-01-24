package org.juanrobledo.springsecurityapp.controllers.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

import java.util.List;

@Valid
public record AuthCreateRoleRequest(
        @Size(max = 3, message = "The user cannot have more than 3 roles") List<String> roleListName
    ){
}
