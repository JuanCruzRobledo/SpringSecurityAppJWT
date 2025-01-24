package org.juanrobledo.springsecurityapp.controllers.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username","message","jwt","status"})
public record AuthResponse(String username,
                           String menssage,
                           String jwt ,
                           boolean status) {

}
