# Spring Boot Cheat Sheet

A reference guide for building production-ready applications with **Spring Boot**, **Spring Security**, **Spring Cloud**, and **Spring Data JPA**.  
Includes code snippets and configuration examples that can be used as building blocks.

---

## 📌 Contents
1. [Configuration Management](#-configuration-management)  
2. [Validation](#-validation)  
3. [Exception Handling](#-exception-handling)  
4. [Logging & Traceability](#-logging--traceability)  
5. [External API Integration](#-external-api-integration)  
   - RestTemplate  
   - RestClient  
   - WebClient  
   - OpenFeign  
6. [Resilience (Resilience4j)](#-resilience-resilience4j)  
7. [Spring Security](#-spring-security)  
8. [Spring Data JPA](#-spring-data-jpa)  
9. [Testing](#-testing)

---

## ⚙️ Configuration Management

Centralize external API URLs, timeouts, and settings with `@ConfigurationProperties`.

```java
// src/main/java/com/example/config/CurrencyApiProperties.java
@ConfigurationProperties(prefix = "currency.api")
public record CurrencyApiProperties(
    String baseUrl,
    String baseCurrency,
    int connectTimeoutMs,
    int readTimeoutMs) {}

// src/main/java/com/example/config/AppConfig.java
@Configuration
@EnableConfigurationProperties(CurrencyApiProperties.class)
public class AppConfig {}

# application.yml
currency:
  api:
    base-url: https://api.exchangerate.host
    base-currency: EUR
    connect-timeout-ms: 1000
    read-timeout-ms: 2000

```

## ✅ Validation

Use jakarta.validation for request DTOs.
```java
public record CreateOrderRequest(
    @Email @NotBlank String customerEmail,
    @Size(min = 1) List<Item> items
) {
    public record Item(
        @NotBlank String sku,
        @Min(1) int qty,
        @DecimalMin("0.0") BigDecimal unitPrice
    ) {}
}

@PostMapping("/api/orders")
public ResponseEntity<Order> create(@Valid @RequestBody CreateOrderRequest req) {
    // ...
}

```

## 🚨 Exception Handling

Use @ControllerAdvice with ProblemDetail for consistent error responses.
```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ProblemDetail onValidation(MethodArgumentNotValidException ex) {
        var pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Validation failed");
        pd.setDetail(ex.getBindingResult().toString());
        return pd;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    ProblemDetail onNotFound(IllegalArgumentException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
    }
}
```


## 📋 Logging & Traceability

Use MDC to add request correlation IDs.

```java
@Component
public class RequestIdFilter implements Filter {
    private static final String HDR = "X-Request-Id";

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
        throws IOException, ServletException {

        HttpServletRequest r = (HttpServletRequest) req;
        String id = Optional.ofNullable(r.getHeader(HDR))
                            .filter(s -> !s.isBlank())
                            .orElse(UUID.randomUUID().toString());

        MDC.put("requestId", id);
        try { chain.doFilter(req, res); }
        finally { MDC.remove("requestId"); }
    }
}
```
Update logback-spring.xml to include %X{requestId}.


## 🌐 External API Integration

### 1. RestTemplate
```java
@Bean
RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder
        .setConnectTimeout(Duration.ofSeconds(1))
        .setReadTimeout(Duration.ofSeconds(2))
        .build();
}

String body = restTemplate.getForObject("https://api.example.com/data", String.class);
```

### 2. RestClient (Spring 6.1+, Boot 3.2+)
```java
@Bean
RestClient restClient(RestClient.Builder builder) {
    return builder
        .baseUrl("https://api.example.com")
        .requestFactory(factory -> {
            if (factory instanceof HttpComponentsClientHttpRequestFactory http) {
                http.setConnectTimeout(1000);
                http.setReadTimeout(2000);
            }
        })
        .build();
}

String result = restClient.get()
    .uri("/data")
    .retrieve()
    .body(String.class);

```

### 3. WebClient

```java
@Bean
WebClient webClient() {
    var httpClient = HttpClient.create()
        .responseTimeout(Duration.ofSeconds(2))
        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 1000);

    return WebClient.builder()
        .baseUrl("https://api.example.com")
        .clientConnector(new ReactorClientHttpConnector(httpClient))
        .build();
}

Mono<String> result = webClient.get()
    .uri("/data")
    .retrieve()
    .bodyToMono(String.class);

```

### 4. OpenFeign
```xml
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>
```
```java
@FeignClient(name = "currencyClient", url = "${currency.api.base-url}")
public interface CurrencyClient {
    @GetMapping("/convert")
    Map<String, Object> convert(@RequestParam String from,
                                @RequestParam String to,
                                @RequestParam String amount);
}
```
```yml
feign:
  client:
    config:
      default:
        connectTimeout: 1000
        readTimeout: 2000

```

## 🔄 Resilience (Resilience4j)
```yml
resilience4j:
  circuitbreaker:
    instances:
      currencyCb:
        sliding-window-size: 10
        failure-rate-threshold: 50
        wait-duration-in-open-state: 10s
  retry:
    instances:
      currencyRetry:
        max-attempts: 3
        wait-duration: 200ms
```
```java
@CircuitBreaker(name = "currencyCb", fallbackMethod = "fallback")
@Retry(name = "currencyRetry")
public OrderView viewWithConvertedTotal(Long id, String currency) { ... }

private OrderView fallback(Long id, String currency, Throwable ex) { ... }
```

## 🔐 Spring Security

Basic setup
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain api(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable())
      .cors(cors -> {})
      .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/actuator/health", "/swagger-ui/**").permitAll()
          .anyRequest().authenticated())
      .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // JWT auth
    return http.build();
  }

  @Bean PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
```
In-memory users
```java
@Bean
UserDetailsService users(PasswordEncoder encoder) {
    var admin = User.withUsername("admin").password(encoder.encode("pass")).roles("ADMIN").build();
    var user  = User.withUsername("user").password(encoder.encode("pass")).roles("USER").build();
    return new InMemoryUserDetailsManager(admin, user);
}
```
Method security
```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/api/admin/reports")
public Report getReports() { ... }
```
### Testing with security
```java
@Test
@WithMockUser(roles = "ADMIN")
void admin_can_access() throws Exception {
  mvc.perform(get("/api/admin/reports"))
     .andExpect(status().isOk());
}
```


## 🗄️ Spring Data JPA

Dependency
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
  <groupId>com.h2database</groupId>
  <artifactId>h2</artifactId>
  <scope>runtime</scope>
</dependency>
```
Entity
```java
@Entity
public class Order {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private String customerEmail;
  private Instant createdAt = Instant.now();
}
```
Repository
```java
public interface OrderRepository extends JpaRepository<Order, Long> {
    List<Order> findByCustomerEmail(String email);
}
```

## 🧪 Testing

Dependencies
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-test</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-test</artifactId>
  <scope>test</scope>
</dependency>
```
Smoke test
```java
@SpringBootTest
class OrdersApplicationTest {
  @Test void contextLoads() { }
}
```
Controller slice test
```java
@WebMvcTest(OrderController.class)
@AutoConfigureMockMvc(addFilters = true)
class OrderControllerTest {

  @Autowired MockMvc mvc;
  @MockBean OrderService service;

  @Test
  @WithMockUser(roles = "USER")
  void listOrders_ok() throws Exception {
    mvc.perform(get("/api/orders")).andExpect(status().isOk());
  }
}
```
Repository test
```java
@DataJpaTest
class OrderRepositoryTest {
  @Autowired OrderRepository repo;

  @Test
  void savesOrder() {
    var o = new Order();
    o.setCustomerEmail("a@b.com");
    repo.save(o);
    assertThat(repo.findByCustomerEmail("a@b.com")).isNotEmpty();
  }
}
```


## ✅ Conclusion

This cheat sheet covers:
	•	Configuration management
	•	Validation
	•	Exception handling
	•	Logging & traceability
	•	External API integration (RestTemplate, RestClient, WebClient, Feign)
	•	Resilience4j
	•	Spring Security
	•	JPA basics
	•	Testing practices

Use these snippets as building blocks for production-ready Spring Boot applications.
