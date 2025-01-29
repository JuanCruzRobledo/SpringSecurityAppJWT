package org.juanrobledo.springsecurityapp.util;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component // Marca esta clase como un componente de Spring para que pueda ser inyectado en otras partes de la aplicación.
public class JwtUtils {

    // Se obtiene la clave privada desde el archivo de configuración (application.properties o application.yml).
    @Value("${security.jwt.key.private}")
    private String privatekey;

    // Se obtiene el generador del usuario (issuer), que es opcional y no siempre necesario.
    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    /**
     * Método para generar un token JWT a partir de la autenticación del usuario.
     * @param authentication Información del usuario autenticado.
     * @return Un token JWT firmado.
     */
    public String createToken(Authentication authentication) {
        // Se define el algoritmo de firma HMAC256 utilizando la clave privada.
        Algorithm algorithm = Algorithm.HMAC256(this.privatekey);

        // Se obtiene el nombre del usuario autenticado.
        String username = authentication.getName();

        // Se obtiene la lista de roles/autoridades del usuario y se convierten en una cadena separada por comas.
        String authorities = authentication.getAuthorities()
                .stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority()) // Se extrae el nombre del rol.
                .collect(Collectors.joining(",")); // Se concatenan los roles con comas.

        // Se crea el token JWT con los datos del usuario y la configuración de seguridad.
        String jwtToken = JWT.create()
                .withIssuer(this.userGenerator) // Se establece el generador del token (opcional).
                .withSubject(username) // Se asigna el nombre del usuario como "subject".
                .withClaim("authorities", authorities) // Se añade el claim de los roles.
                .withIssuedAt(new Date(System.currentTimeMillis())) // Fecha de emisión.
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) // Expiración en 30 minutos (1800000 ms).
                .withJWTId(UUID.randomUUID().toString()) // ID único del token.
                .withNotBefore(new Date(System.currentTimeMillis())) // Se establece desde cuándo es válido.
                .sign(algorithm); // Se firma el token con el algoritmo definido.

        return jwtToken; // Se retorna el token generado.
    }

    /**
     * Método para validar un token JWT y devolver la información decodificada.
     * @param token Token JWT a validar.
     * @return Un objeto DecodedJWT con la información del token.
     */
    public DecodedJWT validateToken(String token) {
        try {
            // Se define el algoritmo de validación utilizando la misma clave secreta.
            Algorithm algorithm = Algorithm.HMAC256(this.privatekey);

            // Se crea un verificador de tokens basado en el algoritmo y el issuer (opcional).
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator) // Se verifica que el issuer coincida.
                    .build();

            // Se verifica el token y se obtiene su contenido decodificado.
            DecodedJWT decodedJWT = verifier.verify(token);

            return decodedJWT; // Se retorna el token decodificado si es válido.
        } catch (JWTVerificationException e) {
            // Si el token es inválido o ha expirado, se lanza una excepción.
            throw new JWTVerificationException("Invalid token, not Authorized");
        }
    }

    /**
     * Método para obtener el nombre de usuario almacenado en el token.
     * @param decodedJWT Token JWT decodificado.
     * @return El nombre de usuario contenido en el token.
     */
    public String getUsernameFromToken(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject(); // El "subject" del token representa el nombre de usuario.
    }

    /**
     * Método para obtener un "claim" específico del token JWT.
     * @param decodedJWT Token JWT decodificado.
     * @param claimName Nombre del claim a extraer.
     * @return El claim solicitado.
     */
    public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName) {
        return decodedJWT.getClaim(claimName); // Retorna un claim específico del token.
    }

    /**
     * Método para obtener todos los claims del token JWT.
     * @param decodedJWT Token JWT decodificado.
     * @return Un mapa con todos los claims del token.
     */
    public Map<String, Claim> getClaims(DecodedJWT decodedJWT) {
        return decodedJWT.getClaims(); // Retorna todos los claims en un mapa clave-valor.
    }
}

