package springsecurity.config;




import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration{

	
	/*
	AuthenticationManager
	AbstractSecurityWebApplicationInitializer
	UserDetailsService
	AuthenticationProvider
	@EnableWebSecurity
	WebSecurityConfiguration.class
	SpringWebMvcImportSelector.class
	OAuth2ImportSelector.class
	HttpSecurityConfiguration.class 
	Authentication
	AbstractAuthenticationProcessingFilter
	*/
	
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//		manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
//		return manager;
//	}
//	
//	@Bean
//	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/").permitAll().
//				anyRequest().authenticated()).formLogin(withDefaults())
//				.httpBasic(withDefaults());
//		return http.build();
//	}
	
//	@Bean
//	 public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
//	  // We are disabling CSRF so that our forms don't complain about a CSRF token.
//	  // Beware that it can create a security vulnerability
//	  return http.csrf(AbstractHttpConfigurer::disable)
//	    // Here we are configuring our login form
//	    .formLogin(Customizer.withDefaults())
//	    .authorizeHttpRequests(authorize ->
//	      authorize
//	        // We are permitting all static resources to be accessed publicly
//	        .requestMatchers("/images/**", "/css/**", "/js/**", "/WEB-INF/views/**").permitAll()
//	        // We are restricting endpoints for individual roles.
//	        // Only users with allowed roles will be able to access individual endpoints.
//	        .requestMatchers("/course/add").hasRole("ADMIN")
//	        .requestMatchers("/course/show-all").hasAnyRole("ADMIN", "USER")
//	        .requestMatchers("/course/edit").hasAnyRole("USER")
//	        // Following line denotes that all requests must be authenticated.
//	        // Hence, once a request comes to our application, we will check if the user is authenticated or not.
//	        .anyRequest().authenticated()
//	    )
//
//	    .logout(Customizer.withDefaults())
//	    .build();
//
//	 }
//	 @Bean
//	 public UserDetailsService userDetailsService() {
//
//	  UserDetails user = User
//	    .withUsername("user")
//	    .password("{noop}password")
//	    .roles("USER")
//	    .build();
//	  UserDetails admin = User
//	    .withUsername("admin")
//	    .password("{noop}password")
//	    .roles("ADMIN", "USER")
//	    .build();
//	  return new InMemoryUserDetailsManager(user, admin);
//	 }
//
//	 @Bean
//	 public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
//	  return new HandlerMappingIntrospector();
//	 }
	}

