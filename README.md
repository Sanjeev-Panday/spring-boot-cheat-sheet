# Spring Boot Cheat Sheet

A comprehensive reference guide for building production-ready applications with **Spring Boot**, **Spring Security**, **Spring Cloud**, **Spring Data JPA**, and **Spring AI**.  

This cheat sheet includes practical code snippets, configuration examples, and best practices that can be used as building blocks for modern Java applications. Whether you're building REST APIs, integrating AI capabilities, or implementing resilience patterns, you'll find ready-to-use examples here.

**What's Covered:**
- Configuration, validation, and exception handling
- External API integration with multiple clients
- Resilience patterns (Circuit Breaker, Retry, Rate Limiting)
- Security with JWT and OAuth2
- Database access with JPA and advanced querying
- **Spring AI** for chat, embeddings, RAG, and more
- Comprehensive testing strategies

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
9. [Spring AI](#-spring-ai)  
   - Chat/Text Generation  
   - Embeddings & Vector Stores  
   - Image Generation  
   - Function Calling  
   - RAG (Retrieval Augmented Generation)  
10. [Testing](#-testing)

---

## ⚙️ Configuration Management

Centralize external API URLs, timeouts, and settings with `@ConfigurationProperties`.

**Basic Configuration Properties**
```java
// src/main/java/com/example/config/CurrencyApiProperties.java
@ConfigurationProperties(prefix = "currency.api")
@Validated // Enable validation
public record CurrencyApiProperties(
    @NotBlank String baseUrl,
    @NotBlank String baseCurrency,
    @Min(100) int connectTimeoutMs,
    @Min(100) int readTimeoutMs) {}

// src/main/java/com/example/config/AppConfig.java
@Configuration
@EnableConfigurationProperties(CurrencyApiProperties.class)
public class AppConfig {}
```

**Application Configuration (application.yml)**
```yaml
currency:
  api:
    base-url: https://api.exchangerate.host
    base-currency: EUR
    connect-timeout-ms: 1000
    read-timeout-ms: 2000

spring:
  application:
    name: my-service
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}

# Use different configs per environment
---
spring:
  config:
    activate:
      on-profile: prod
      
currency:
  api:
    connect-timeout-ms: 5000
    read-timeout-ms: 10000
```

**Environment Variables**
```bash
# Set via environment
export SPRING_PROFILES_ACTIVE=prod
export CURRENCY_API_BASE_URL=https://api.prod.example.com

# Or via application properties
# ${ENV_VAR:default-value}
```

## ✅ Validation

Use `jakarta.validation` annotations for input validation.

**Request DTO Validation**
```java
public record CreateOrderRequest(
    @Email @NotBlank String customerEmail,
    @Size(min = 1) List<Item> items
) {
    public record Item(
        @NotBlank String sku,
        @Min(1) int qty,
        @DecimalMin("0.01") BigDecimal unitPrice
    ) {}
}

@PostMapping("/api/orders")
public ResponseEntity<Order> create(@Valid @RequestBody CreateOrderRequest req) {
    Order order = orderService.create(req);
    return ResponseEntity.status(HttpStatus.CREATED).body(order);
}
```

**Custom Validators**
```java
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PhoneNumberValidator.class)
public @interface ValidPhoneNumber {
    String message() default "Invalid phone number format";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class PhoneNumberValidator implements ConstraintValidator<ValidPhoneNumber, String> {
    private static final Pattern PHONE_PATTERN = Pattern.compile("^\\+?[1-9]\\d{1,14}$");
    
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value == null || PHONE_PATTERN.matcher(value).matches();
    }
}
```

**Validation Groups**
```java
public interface OnCreate {}
public interface OnUpdate {}

public record UserRequest(
    @Null(groups = OnCreate.class)
    @NotNull(groups = OnUpdate.class)
    Long id,
    
    @NotBlank(groups = {OnCreate.class, OnUpdate.class})
    String username
) {}

@PostMapping("/users")
public ResponseEntity<User> create(@Validated(OnCreate.class) @RequestBody UserRequest req) {
    // id must be null
}

@PutMapping("/users/{id}")
public ResponseEntity<User> update(@Validated(OnUpdate.class) @RequestBody UserRequest req) {
    // id must not be null
}
```

## 🚨 Exception Handling

Use `@ControllerAdvice` with `ProblemDetail` (RFC 7807) for consistent error responses.

**Global Exception Handler**
```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ProblemDetail onValidation(MethodArgumentNotValidException ex) {
        var pd = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "Validation failed"
        );
        pd.setTitle("Invalid Request");
        
        // Add field errors
        Map<String, String> errors = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .collect(Collectors.toMap(
                FieldError::getField,
                err -> Optional.ofNullable(err.getDefaultMessage()).orElse("Invalid value")
            ));
        pd.setProperty("errors", errors);
        
        log.warn("Validation failed: {}", errors);
        return pd;
    }

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    ProblemDetail onNotFound(EntityNotFoundException ex) {
        log.warn("Entity not found: {}", ex.getMessage());
        return ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
    }
    
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ProblemDetail onIllegalArgument(IllegalArgumentException ex) {
        log.warn("Illegal argument: {}", ex.getMessage());
        return ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
    }
    
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    ProblemDetail onUnexpected(Exception ex) {
        log.error("Unexpected error", ex);
        return ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An unexpected error occurred"
        );
    }
}
```

**Custom Business Exception**
```java
@ResponseStatus(HttpStatus.CONFLICT)
public class DuplicateResourceException extends RuntimeException {
    public DuplicateResourceException(String message) {
        super(message);
    }
}

// Usage
if (userRepository.existsByEmail(email)) {
    throw new DuplicateResourceException("User with email " + email + " already exists");
}
```


## 📋 Logging & Traceability

Use MDC (Mapped Diagnostic Context) for request correlation and structured logging.

**Request ID Filter**
```java
@Component
public class RequestIdFilter implements Filter {
    private static final String HDR = "X-Request-Id";

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
        throws IOException, ServletException {

        HttpServletRequest r = (HttpServletRequest) req;
        HttpServletResponse resp = (HttpServletResponse) res;
        
        String id = Optional.ofNullable(r.getHeader(HDR))
                            .filter(s -> !s.isBlank())
                            .orElse(UUID.randomUUID().toString());

        MDC.put("requestId", id);
        resp.setHeader(HDR, id); // Echo back in response
        
        try { 
            chain.doFilter(req, res); 
        } finally { 
            MDC.clear(); 
        }
    }
}
```

**Logback Configuration (logback-spring.xml)**
```xml
<configuration>
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} [requestId=%X{requestId}] - %msg%n</pattern>
        </encoder>
    </appender>
    
    <!-- JSON logging for production -->
    <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <includeMdcKeyName>requestId</includeMdcKeyName>
            <includeMdcKeyName>userId</includeMdcKeyName>
        </encoder>
    </appender>
    
    <springProfile name="prod">
        <root level="INFO">
            <appender-ref ref="JSON"/>
        </root>
    </springProfile>
    
    <springProfile name="dev,test">
        <root level="DEBUG">
            <appender-ref ref="CONSOLE"/>
        </root>
    </springProfile>
</configuration>
```

**Structured Logging Service**
```java
@Service
@Slf4j
public class OrderService {
    
    public Order createOrder(CreateOrderRequest req) {
        // Add user context to MDC
        MDC.put("userId", getCurrentUserId());
        
        log.info("Creating order for customer: {}", req.customerEmail());
        
        try {
            Order order = // ... create order
            log.info("Order created successfully with ID: {}", order.getId());
            return order;
        } catch (Exception e) {
            log.error("Failed to create order", e);
            throw e;
        } finally {
            MDC.remove("userId");
        }
    }
}
```

**Micrometer Tracing (Distributed Tracing)**
```xml
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-brave</artifactId>
</dependency>
<dependency>
    <groupId>io.zipkin.reporter2</groupId>
    <artifactId>zipkin-reporter-brave</artifactId>
</dependency>
```

```yaml
management:
  tracing:
    sampling:
      probability: 1.0 # Sample all requests (use 0.1 for 10% in production)
  zipkin:
    tracing:
      endpoint: http://localhost:9411/api/v2/spans
```


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

Add resilience patterns like circuit breakers, retries, rate limiting, and bulkheads.

**Dependencies**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-aop</artifactId>
</dependency>
<dependency>
    <groupId>io.github.resilience4j</groupId>
    <artifactId>resilience4j-spring-boot3</artifactId>
</dependency>
```

**Configuration**
```yaml
resilience4j:
  circuitbreaker:
    instances:
      currencyCb:
        sliding-window-size: 10
        failure-rate-threshold: 50
        wait-duration-in-open-state: 10s
        permitted-number-of-calls-in-half-open-state: 3
        automatic-transition-from-open-to-half-open-enabled: true
        
  retry:
    instances:
      currencyRetry:
        max-attempts: 3
        wait-duration: 200ms
        exponential-backoff-multiplier: 2
        retry-exceptions:
          - org.springframework.web.client.ResourceAccessException
          
  ratelimiter:
    instances:
      currencyRateLimit:
        limit-for-period: 10
        limit-refresh-period: 1s
        timeout-duration: 0
        
  bulkhead:
    instances:
      currencyBulkhead:
        max-concurrent-calls: 5
        max-wait-duration: 100ms
```

**Using Annotations**
```java
@Service
public class CurrencyService {
    
    @CircuitBreaker(name = "currencyCb", fallbackMethod = "fallbackConversion")
    @Retry(name = "currencyRetry")
    @RateLimiter(name = "currencyRateLimit")
    @Bulkhead(name = "currencyBulkhead")
    public OrderView viewWithConvertedTotal(Long id, String currency) {
        Order order = orderRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Order not found"));
            
        BigDecimal rate = currencyClient.getRate(currency);
        return new OrderView(order, order.getTotal().multiply(rate), currency);
    }
    
    private OrderView fallbackConversion(Long id, String currency, Throwable ex) {
        log.warn("Currency conversion failed, using fallback: {}", ex.getMessage());
        Order order = orderRepository.findById(id).orElseThrow();
        // Return with original currency or cached rate
        return new OrderView(order, order.getTotal(), order.getCurrency());
    }
}
```

**Programmatic Usage**
```java
@Service
public class ResilientService {
    
    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final RetryRegistry retryRegistry;
    
    public String callExternalApi() {
        CircuitBreaker cb = circuitBreakerRegistry.circuitBreaker("currencyCb");
        Retry retry = retryRegistry.retry("currencyRetry");
        
        return Decorators.ofSupplier(() -> externalApiCall())
            .withCircuitBreaker(cb)
            .withRetry(retry)
            .withFallback(Arrays.asList(TimeoutException.class, CallNotPermittedException.class),
                         ex -> "Fallback response")
            .get();
    }
}
```

**Monitoring Circuit Breaker Events**
```java
@Component
public class CircuitBreakerEventLogger {
    
    @PostConstruct
    public void init() {
        circuitBreakerRegistry.circuitBreaker("currencyCb")
            .getEventPublisher()
            .onStateTransition(event -> 
                log.info("Circuit breaker state changed from {} to {}", 
                    event.getStateTransition().getFromState(),
                    event.getStateTransition().getToState())
            )
            .onFailureRateExceeded(event ->
                log.warn("Failure rate exceeded: {}%", event.getFailureRate())
            );
    }
}
```

## 🔐 Spring Security

Secure your application with authentication and authorization.

**Dependencies**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

**Basic Security Configuration**
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain api(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable()) // Disable for stateless APIs
      .cors(cors -> {}) // Enable CORS with default config
      .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/actuator/health", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
          .requestMatchers("/api/public/**").permitAll()
          .requestMatchers("/api/admin/**").hasRole("ADMIN")
          .anyRequest().authenticated())
      .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // JWT-based auth
    return http.build();
  }

  @Bean 
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
```

**JWT Configuration**
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://your-auth-server.com
          # OR use jwk-set-uri directly
          jwk-set-uri: https://your-auth-server.com/.well-known/jwks.json
```

**In-Memory Users (Development Only)**
```java
@Bean
UserDetailsService users(PasswordEncoder encoder) {
    var admin = User.withUsername("admin")
        .password(encoder.encode("admin123"))
        .roles("ADMIN", "USER")
        .build();
    var user = User.withUsername("user")
        .password(encoder.encode("user123"))
        .roles("USER")
        .build();
    return new InMemoryUserDetailsManager(admin, user);
}
```

**Database-Backed Users**
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRoles().toArray(new String[0]))
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(!user.isEnabled())
            .build();
    }
}
```

**Method-Level Security**
```java
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public List<Order> list() {
        return orderService.findAll();
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        orderService.delete(id);
        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/{id}")
    @PostAuthorize("returnObject.customerEmail == authentication.name or hasRole('ADMIN')")
    public Order getById(@PathVariable Long id) {
        return orderService.findById(id);
    }
}
```

**Custom Authorization**
```java
@Service
public class OrderSecurityService {
    
    public boolean isOwner(Long orderId, Authentication auth) {
        Order order = orderRepository.findById(orderId).orElse(null);
        return order != null && order.getCustomerEmail().equals(auth.getName());
    }
}

// Usage
@PreAuthorize("@orderSecurityService.isOwner(#id, authentication)")
@GetMapping("/api/orders/{id}")
public Order getOrder(@PathVariable Long id) { ... }
```

**CORS Configuration**
```java
@Configuration
public class CorsConfig {
    
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://yourdomain.com"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

**Testing with Security**
```java
@WebMvcTest(OrderController.class)
class OrderControllerTest {
    
    @Autowired MockMvc mvc;
    @MockBean OrderService service;
    
    @Test
    @WithMockUser(roles = "ADMIN")
    void admin_can_access() throws Exception {
        mvc.perform(get("/api/admin/reports"))
           .andExpect(status().isOk());
    }
    
    @Test
    void unauthenticated_returns_401() throws Exception {
        mvc.perform(get("/api/orders"))
           .andExpect(status().isUnauthorized());
    }
}
```


## 🗄️ Spring Data JPA

Simplify database access with Spring Data JPA.

**Dependencies**
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<!-- Database driver -->
<dependency>
  <groupId>com.h2database</groupId>
  <artifactId>h2</artifactId>
  <scope>runtime</scope>
</dependency>
<!-- OR PostgreSQL -->
<dependency>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <scope>runtime</scope>
</dependency>
```

**Configuration**
```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/mydb
    username: user
    password: pass
  jpa:
    hibernate:
      ddl-auto: validate # use 'update' in dev, 'validate' in prod
    show-sql: false
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.PostgreSQLDialect
        # Enable batch inserts
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
```

**Entity Definition**
```java
@Entity
@Table(name = "orders")
public class Order {
  @Id 
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  
  @Column(nullable = false)
  private String customerEmail;
  
  @Column(nullable = false)
  private BigDecimal total;
  
  @CreatedDate
  @Column(nullable = false, updatable = false)
  private Instant createdAt;
  
  @LastModifiedDate
  private Instant updatedAt;
  
  @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
  private List<OrderItem> items = new ArrayList<>();
  
  @Version
  private Long version; // Optimistic locking
}

@Entity
@Table(name = "order_items")
public class OrderItem {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "order_id", nullable = false)
  private Order order;
  
  private String sku;
  private int quantity;
  private BigDecimal unitPrice;
}
```

**Repository Interface**
```java
public interface OrderRepository extends JpaRepository<Order, Long> {
    
    // Query methods
    List<Order> findByCustomerEmail(String email);
    
    List<Order> findByCreatedAtBetween(Instant start, Instant end);
    
    @Query("SELECT o FROM Order o WHERE o.total > :minTotal")
    List<Order> findHighValueOrders(@Param("minTotal") BigDecimal minTotal);
    
    // Native query
    @Query(value = "SELECT * FROM orders WHERE customer_email = ?1", nativeQuery = true)
    List<Order> findByEmailNative(String email);
    
    // Projections
    @Query("SELECT o.customerEmail as email, SUM(o.total) as totalSpent " +
           "FROM Order o GROUP BY o.customerEmail")
    List<CustomerSpending> getCustomerSpending();
    
    interface CustomerSpending {
        String getEmail();
        BigDecimal getTotalSpent();
    }
    
    // Modifying queries
    @Modifying
    @Query("UPDATE Order o SET o.status = :status WHERE o.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") String status);
    
    // Pagination and sorting
    Page<Order> findAll(Pageable pageable);
}
```

**Custom Repository Implementation**
```java
public interface OrderRepositoryCustom {
    List<Order> findByComplexCriteria(OrderSearchCriteria criteria);
}

@Repository
public class OrderRepositoryCustomImpl implements OrderRepositoryCustom {
    
    @PersistenceContext
    private EntityManager em;
    
    @Override
    public List<Order> findByComplexCriteria(OrderSearchCriteria criteria) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Order> query = cb.createQuery(Order.class);
        Root<Order> order = query.from(Order.class);
        
        List<Predicate> predicates = new ArrayList<>();
        
        if (criteria.getCustomerEmail() != null) {
            predicates.add(cb.equal(order.get("customerEmail"), criteria.getCustomerEmail()));
        }
        if (criteria.getMinTotal() != null) {
            predicates.add(cb.greaterThanOrEqualTo(order.get("total"), criteria.getMinTotal()));
        }
        
        query.where(predicates.toArray(new Predicate[0]));
        return em.createQuery(query).getResultList();
    }
}

// Extend both interfaces
public interface OrderRepository extends JpaRepository<Order, Long>, OrderRepositoryCustom {
}
```

**Specifications (Type-Safe Queries)**
```java
public class OrderSpecifications {
    
    public static Specification<Order> hasCustomerEmail(String email) {
        return (root, query, cb) -> 
            email == null ? null : cb.equal(root.get("customerEmail"), email);
    }
    
    public static Specification<Order> totalGreaterThan(BigDecimal amount) {
        return (root, query, cb) -> 
            amount == null ? null : cb.greaterThan(root.get("total"), amount);
    }
    
    public static Specification<Order> createdAfter(Instant date) {
        return (root, query, cb) -> 
            date == null ? null : cb.greaterThanOrEqualTo(root.get("createdAt"), date);
    }
}

// Repository
public interface OrderRepository extends JpaRepository<Order, Long>, 
                                         JpaSpecificationExecutor<Order> {
}

// Usage
Specification<Order> spec = Specification
    .where(OrderSpecifications.hasCustomerEmail(email))
    .and(OrderSpecifications.totalGreaterThan(BigDecimal.valueOf(100)))
    .and(OrderSpecifications.createdAfter(Instant.now().minus(30, ChronoUnit.DAYS)));

List<Order> orders = orderRepository.findAll(spec);
```

**Auditing**
```java
@Configuration
@EnableJpaAuditing
public class JpaConfig {
    
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> Optional.ofNullable(SecurityContextHolder.getContext())
            .map(SecurityContext::getAuthentication)
            .filter(Authentication::isAuthenticated)
            .map(Authentication::getName);
    }
}

@Entity
@EntityListeners(AuditingEntityListener.class)
public class Order {
    @CreatedBy
    private String createdBy;
    
    @CreatedDate
    private Instant createdAt;
    
    @LastModifiedBy
    private String lastModifiedBy;
    
    @LastModifiedDate
    private Instant lastModifiedAt;
}
```

**Transaction Management**
```java
@Service
public class OrderService {
    
    @Transactional
    public Order createOrder(CreateOrderRequest req) {
        Order order = new Order();
        order.setCustomerEmail(req.customerEmail());
        
        for (var item : req.items()) {
            OrderItem orderItem = new OrderItem();
            orderItem.setSku(item.sku());
            orderItem.setQuantity(item.qty());
            order.addItem(orderItem);
        }
        
        return orderRepository.save(order);
    }
    
    @Transactional(readOnly = true)
    public List<Order> findByEmail(String email) {
        return orderRepository.findByCustomerEmail(email);
    }
}
```

## 🤖 Spring AI

Spring AI provides a unified abstraction for working with AI models from various providers (OpenAI, Azure OpenAI, Anthropic, Ollama, etc.).

### Dependencies

```xml
<!-- Add Spring AI BOM -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.ai</groupId>
      <artifactId>spring-ai-bom</artifactId>
      <version>1.0.0-M4</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<!-- For OpenAI -->
<dependency>
  <groupId>org.springframework.ai</groupId>
  <artifactId>spring-ai-openai-spring-boot-starter</artifactId>
</dependency>

<!-- For Ollama (local models) -->
<dependency>
  <groupId>org.springframework.ai</groupId>
  <artifactId>spring-ai-ollama-spring-boot-starter</artifactId>
</dependency>

<!-- For Vector Stores -->
<dependency>
  <groupId>org.springframework.ai</groupId>
  <artifactId>spring-ai-pgvector-store-spring-boot-starter</artifactId>
</dependency>
```

### 1. Chat/Text Generation

**Basic Configuration**
```yaml
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}
      chat:
        options:
          model: gpt-4
          temperature: 0.7
          max-tokens: 500
```

**Simple Chat Example**
```java
@RestController
@RequestMapping("/api/ai")
public class AiController {
    
    private final ChatClient chatClient;
    
    public AiController(ChatClient.Builder chatClientBuilder) {
        this.chatClient = chatClientBuilder.build();
    }
    
    @GetMapping("/chat")
    public String chat(@RequestParam String message) {
        return chatClient.prompt()
                .user(message)
                .call()
                .content();
    }
}
```

**Structured Output with Records**
```java
public record MovieRecommendation(
    String title,
    String genre,
    int releaseYear,
    String reason
) {}

@GetMapping("/recommend-movie")
public MovieRecommendation recommendMovie(@RequestParam String preferences) {
    return chatClient.prompt()
            .user(u -> u.text("Recommend a movie based on: {preferences}")
                       .param("preferences", preferences))
            .call()
            .entity(MovieRecommendation.class);
}
```

**Streaming Responses**
```java
@GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
public Flux<String> streamChat(@RequestParam String message) {
    return chatClient.prompt()
            .user(message)
            .stream()
            .content();
}
```

### 2. Embeddings & Vector Stores

**Generate Embeddings**
```java
@Service
public class EmbeddingService {
    
    private final EmbeddingModel embeddingModel;
    
    public EmbeddingService(EmbeddingModel embeddingModel) {
        this.embeddingModel = embeddingModel;
    }
    
    public List<Double> embed(String text) {
        return embeddingModel.embed(text);
    }
}
```

**Vector Store with PGVector**
```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/vectordb
    username: user
    password: pass
  ai:
    vectorstore:
      pgvector:
        index-type: HNSW
        distance-type: COSINE_DISTANCE
        dimensions: 1536
```

```java
@Service
public class DocumentService {
    
    private final VectorStore vectorStore;
    private final EmbeddingModel embeddingModel;
    
    public DocumentService(VectorStore vectorStore, EmbeddingModel embeddingModel) {
        this.vectorStore = vectorStore;
        this.embeddingModel = embeddingModel;
    }
    
    public void addDocument(String content, Map<String, Object> metadata) {
        Document doc = new Document(content, metadata);
        vectorStore.add(List.of(doc));
    }
    
    public List<Document> searchSimilar(String query, int topK) {
        return vectorStore.similaritySearch(
            SearchRequest.query(query).withTopK(topK)
        );
    }
}
```

### 3. Image Generation

```yaml
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}
      image:
        options:
          model: dall-e-3
          size: 1024x1024
          quality: hd
```

```java
@Service
public class ImageService {
    
    private final ImageModel imageModel;
    
    public ImageService(ImageModel imageModel) {
        this.imageModel = imageModel;
    }
    
    public String generateImage(String prompt) {
        ImageResponse response = imageModel.call(
            new ImagePrompt(prompt)
        );
        return response.getResult().getOutput().getUrl();
    }
}
```

### 4. Function Calling

Define functions that the AI can call:

```java
@Configuration
public class AiFunctionConfig {
    
    @Bean
    @Description("Get current weather for a location")
    public Function<WeatherRequest, WeatherResponse> weatherFunction() {
        return request -> {
            // Call actual weather API
            return new WeatherResponse(
                request.location(),
                "Sunny",
                72.5
            );
        };
    }
    
    public record WeatherRequest(String location) {}
    public record WeatherResponse(String location, String condition, double temperature) {}
}
```

**Use Function in Chat**
```java
@Service
public class AssistantService {
    
    private final ChatClient chatClient;
    
    public AssistantService(ChatClient.Builder builder) {
        this.chatClient = builder
            .defaultFunctions("weatherFunction") // Register function
            .build();
    }
    
    public String chat(String message) {
        return chatClient.prompt()
                .user(message)
                .call()
                .content();
    }
}
```

### 5. RAG (Retrieval Augmented Generation)

**Complete RAG Pipeline**
```java
@Service
public class RagService {
    
    private final ChatClient chatClient;
    private final VectorStore vectorStore;
    
    public RagService(ChatClient.Builder builder, VectorStore vectorStore) {
        this.chatClient = builder.build();
        this.vectorStore = vectorStore;
    }
    
    public String answerWithContext(String question) {
        // 1. Retrieve relevant documents
        List<Document> relevantDocs = vectorStore.similaritySearch(
            SearchRequest.query(question).withTopK(3)
        );
        
        // 2. Build context from retrieved documents
        String context = relevantDocs.stream()
            .map(Document::getContent)
            .collect(Collectors.joining("\n\n"));
        
        // 3. Generate answer with context
        String prompt = """
            Answer the question based on the following context.
            If the answer cannot be found in the context, say so.
            
            Context:
            {context}
            
            Question: {question}
            """;
        
        return chatClient.prompt()
                .user(u -> u.text(prompt)
                           .param("context", context)
                           .param("question", question))
                .call()
                .content();
    }
}
```

**Document Ingestion Pipeline**
```java
@Service
public class DocumentIngestionService {
    
    private final VectorStore vectorStore;
    private final DocumentReader documentReader;
    
    public void ingestPdf(Resource pdfResource) {
        // 1. Read and parse document
        List<Document> documents = documentReader.read(pdfResource);
        
        // 2. Split into chunks
        TextSplitter splitter = new TokenTextSplitter();
        List<Document> chunks = splitter.split(documents);
        
        // 3. Store in vector database
        vectorStore.add(chunks);
    }
}
```

### 6. Advisors & Prompt Engineering

**Use Advisors for Cross-Cutting Concerns**
```java
@Configuration
public class ChatClientConfig {
    
    @Bean
    public ChatClient chatClient(ChatClient.Builder builder) {
        return builder
            .defaultAdvisors(
                // Add chat history
                new MessageChatMemoryAdvisor(new InMemoryChatMemory()),
                
                // Log requests/responses
                new LoggingAdvisor(),
                
                // Add custom system message
                new SimpleLoggerAdvisor()
            )
            .build();
    }
}
```

**Prompt Templates**
```java
@Service
public class PromptService {
    
    private final ChatClient chatClient;
    
    @Value("classpath:/prompts/code-review.st")
    private Resource promptTemplate;
    
    public String reviewCode(String code, String language) {
        PromptTemplate template = new PromptTemplate(promptTemplate);
        
        return chatClient.prompt(
            template.create(Map.of(
                "code", code,
                "language", language
            ))
        ).call().content();
    }
}
```

### 7. Observability

Enable observability for AI operations:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: "*"
  metrics:
    tags:
      application: ${spring.application.name}
  tracing:
    sampling:
      probability: 1.0

spring:
  ai:
    openai:
      chat:
        options:
          # Enable token usage tracking
          logprobs: true
```

```java
@Service
public class ObservableAiService {
    
    private final ChatClient chatClient;
    private final MeterRegistry meterRegistry;
    
    public String chat(String message) {
        Timer.Sample sample = Timer.start(meterRegistry);
        
        try {
            String response = chatClient.prompt()
                    .user(message)
                    .call()
                    .content();
            
            sample.stop(Timer.builder("ai.chat.duration")
                    .tag("model", "gpt-4")
                    .register(meterRegistry));
            
            return response;
        } catch (Exception e) {
            meterRegistry.counter("ai.chat.errors").increment();
            throw e;
        }
    }
}
```

## 🧪 Testing

Comprehensive testing strategies for Spring Boot applications.

**Dependencies**
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
<!-- For integration tests with real database -->
<dependency>
  <groupId>org.testcontainers</groupId>
  <artifactId>postgresql</artifactId>
  <scope>test</scope>
</dependency>
```

**1. Unit Tests**
```java
@ExtendWith(MockitoExtension.class)
class OrderServiceTest {
    
    @Mock
    private OrderRepository orderRepository;
    
    @Mock
    private CurrencyClient currencyClient;
    
    @InjectMocks
    private OrderService orderService;
    
    @Test
    void createOrder_success() {
        // Given
        var request = new CreateOrderRequest("user@example.com", List.of());
        var savedOrder = new Order();
        savedOrder.setId(1L);
        
        when(orderRepository.save(any(Order.class))).thenReturn(savedOrder);
        
        // When
        Order result = orderService.createOrder(request);
        
        // Then
        assertThat(result.getId()).isEqualTo(1L);
        verify(orderRepository).save(any(Order.class));
    }
}
```

**2. Controller Tests (Slice)**
```java
@WebMvcTest(OrderController.class)
@AutoConfigureMockMvc
class OrderControllerTest {

  @Autowired MockMvc mvc;
  @MockBean OrderService service;

  @Test
  @WithMockUser(roles = "USER")
  void listOrders_returnsOk() throws Exception {
    when(service.findAll()).thenReturn(List.of(new Order()));
    
    mvc.perform(get("/api/orders"))
       .andExpect(status().isOk())
       .andExpect(jsonPath("$").isArray())
       .andExpect(jsonPath("$.length()").value(1));
  }
  
  @Test
  @WithMockUser
  void createOrder_validRequest_returns201() throws Exception {
    var order = new Order();
    order.setId(1L);
    when(service.createOrder(any())).thenReturn(order);
    
    mvc.perform(post("/api/orders")
           .contentType(MediaType.APPLICATION_JSON)
           .content("""
               {
                 "customerEmail": "test@example.com",
                 "items": [{"sku": "ABC", "qty": 1, "unitPrice": 10.0}]
               }
               """))
       .andExpect(status().isCreated())
       .andExpect(jsonPath("$.id").value(1));
  }
  
  @Test
  void unauthenticated_returns401() throws Exception {
    mvc.perform(get("/api/orders"))
       .andExpect(status().isUnauthorized());
  }
}
```

**3. Repository Tests**
```java
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class OrderRepositoryTest {
  
  @Container
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");
  
  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
  }
  
  @Autowired OrderRepository repo;

  @Test
  void savesOrder() {
    var order = new Order();
    order.setCustomerEmail("a@b.com");
    order.setTotal(BigDecimal.valueOf(100));
    
    Order saved = repo.save(order);
    
    assertThat(saved.getId()).isNotNull();
    assertThat(repo.findByCustomerEmail("a@b.com")).hasSize(1);
  }
  
  @Test
  void findByCustomerEmail_returnsMatchingOrders() {
    // Create test data
    var order1 = createOrder("user1@test.com");
    var order2 = createOrder("user2@test.com");
    var order3 = createOrder("user1@test.com");
    repo.saveAll(List.of(order1, order2, order3));
    
    // Query
    List<Order> results = repo.findByCustomerEmail("user1@test.com");
    
    // Verify
    assertThat(results).hasSize(2);
  }
}
```

**4. Integration Tests**
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class OrderIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");
    
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Test
    void createOrder_endToEnd() {
        var request = new CreateOrderRequest(
            "test@example.com",
            List.of(new Item("SKU123", 2, BigDecimal.valueOf(25.50)))
        );
        
        ResponseEntity<Order> response = restTemplate
            .withBasicAuth("user", "pass")
            .postForEntity("/api/orders", request, Order.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getId()).isNotNull();
        
        // Verify in database
        Order saved = orderRepository.findById(response.getBody().getId()).orElseThrow();
        assertThat(saved.getCustomerEmail()).isEqualTo("test@example.com");
    }
}
```

**5. Testing with MockMvc and REST Assured**
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OrderApiTest {
    
    @LocalServerPort
    private int port;
    
    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.authentication = basic("user", "pass");
    }
    
    @Test
    void getOrders_returnsOrderList() {
        given()
            .when()
            .get("/api/orders")
            .then()
            .statusCode(200)
            .body("$", hasSize(greaterThanOrEqualTo(0)));
    }
}
```

**6. Test Configuration**
```java
@TestConfiguration
public class TestConfig {
    
    @Bean
    @Primary
    public CurrencyClient mockCurrencyClient() {
        CurrencyClient mock = mock(CurrencyClient.class);
        when(mock.getRate(anyString())).thenReturn(BigDecimal.ONE);
        return mock;
    }
}

// Use in tests
@Import(TestConfig.class)
class OrderServiceTest {
    // ...
}
```

**7. Smoke Test**
```java
@SpringBootTest
class ApplicationTest {
    
    @Autowired
    private ApplicationContext context;
    
    @Test
    void contextLoads() {
        assertThat(context).isNotNull();
    }
    
    @Test
    void allBeansLoad() {
        assertThat(context.getBeanDefinitionCount()).isGreaterThan(0);
    }
}
```


## ✅ Conclusion

This comprehensive Spring Boot cheat sheet covers:

**Core Concepts:**
- ⚙️ Configuration management with `@ConfigurationProperties` and profiles
- ✅ Request validation with Jakarta Validation and custom validators
- 🚨 Exception handling with `@ControllerAdvice` and RFC 7807 ProblemDetail
- 📋 Logging, traceability with MDC, and distributed tracing

**Integration & Resilience:**
- 🌐 External API integration (RestTemplate, RestClient, WebClient, OpenFeign)
- 🔄 Resilience patterns (Circuit Breaker, Retry, Rate Limiter, Bulkhead)
- 🔐 Security with Spring Security, JWT, OAuth2, method-level authorization

**Data & AI:**
- 🗄️ Spring Data JPA with repositories, specifications, and auditing
- 🤖 Spring AI for chat, embeddings, vector stores, image generation, and RAG patterns

**Testing:**
- 🧪 Comprehensive testing strategies (unit, integration, slice tests)
- Testing with Testcontainers, MockMvc, and security

**Best Practices:**
- Use configuration properties instead of `@Value` for complex configs
- Enable validation on configuration properties with `@Validated`
- Implement structured logging with MDC for request tracing
- Apply resilience patterns for external API calls
- Use method security for fine-grained authorization
- Leverage JPA specifications for type-safe dynamic queries
- Write comprehensive tests at all levels (unit, slice, integration)
- Use observability tools (metrics, tracing) for production monitoring

Use these code snippets and patterns as building blocks for production-ready Spring Boot applications.

## 📚 Additional Resources

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Data JPA](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/)
- [Spring AI Documentation](https://docs.spring.io/spring-ai/reference/)
- [Resilience4j Guide](https://resilience4j.readme.io/docs/getting-started-3)
- [Baeldung Spring Tutorials](https://www.baeldung.com/spring-tutorial)
