package org.juanrobledo.springsecurityapp.config;

import org.juanrobledo.springsecurityapp.config.filter.JwtTokenValidator;
import org.juanrobledo.springsecurityapp.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //Evita tener que configurar un authorizehttpRequest y nos permite trabajar con mappeos
public class SecurityConfig {

    @Autowired
    private JwtUtils jwtUtils;

 /*   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf( csrf -> csrf.disable())
                .sessionManagement( session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http ->{

                    //Configurar los endpoints publicos
                    http.requestMatchers("auth/hello")
                            .permitAll();

                    //Configurar los endpoints privados
                    http.requestMatchers("auth/helloSecured")
                            .hasAuthority("CREATE");

                    //Configurar cualquier otro endpoint -NO ESPECIFICADOS
                    http.anyRequest().denyAll();//Rechaza todos los otros endpoints
                    http.anyRequest().denyAll();//Si tengo las credenciales correctas puedo acceder
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }
*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    // Configurar los endpoints publicos
                    http.requestMatchers("/auth/**").permitAll();

                    // Configurar los endpoints privados
                    http.requestMatchers(HttpMethod.POST, "/method/post").hasAnyRole("ADMIN", "USER");
                    http.requestMatchers(HttpMethod.PATCH, "/method/patch").hasAnyAuthority("DELETE");
                    http.requestMatchers(HttpMethod.GET,"method/get").hasAnyAuthority("CREATE");

                    // Configurar el resto de endpoint - NO ESPECIFICADOS
                    http.anyRequest().denyAll();
                })
                .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class) //Se tiene que validar el token antes del filtro de authenticacion
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
      //authenticationProvider.setUserDetailsService();//Para tener Usuarios en memoria
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }

    //En vez de traer los usuarios de la base de datos se usan usuarios en memoria
//    @Bean
//    public UserDetailsService userDetailsService() {
//
//
//        List<UserDetails> userDetailsList = new ArrayList<UserDetails>();
//        userDetailsList.add(User.withUsername("juan")  //Spring valida los usuarios a traves de este objeto
//                .password("1234")
//                .roles("ADMIN")
//                .authorities("READ","WRITE") //No es lo mismo los persmisos que los roles
//                .build());
//
//        userDetailsList.add(User.withUsername("santiago")  //Spring valida los usuarios a traves de este objeto
//                .password("1234")
//                .roles("USER")
//                .authorities("READ","CREATE") //No es lo mismo los persmisos que los roles
//                .build());
//
//        return new InMemoryUserDetailsManager(userDetailsList);
//    }




    @Bean
    public PasswordEncoder passwordEncoder() {
        //return NoOpPasswordEncoder.getInstance(); //Para pruebas
        return new BCryptPasswordEncoder(); // Para produccion encripta las contraseñas
    }


    //Para ver las contraseñas encriptadas
    //public static void main(String[] args) {
    //    System.out.println("Contraseña:" + new BCryptPasswordEncoder().encode("123456"));
    //}
}
