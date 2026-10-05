package com.example.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * Global Filter bảo vệ route /api/courses/**.
 * Dùng chung Secret Key với Identity-Service để verify JWT (HS256).
 * - Token hết hạn / sai chữ ký / thiếu header -> 401 Unauthorized.
 * - Token hợp lệ -> trích role từ payload, gắn header X-User-Role rồi forward.
 */
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    @Value("${app.jwt.secret}")
    private String secret;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Chỉ chặn các request tới Course-Service, các route khác cho qua.
        if (!path.startsWith("/api/courses")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        final Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception ex) {
            // Hết hạn, sai chữ ký, malformed -> 401
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String role = extractRole(claims);

        ServerWebExchange mutated = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("X-User-Role", role)
                        .build())
                .build();

        return chain.filter(mutated);
    }

    @SuppressWarnings("unchecked")
    private String extractRole(Claims claims) {
        // Identity-Service ký claim "role" (số ít); hỗ trợ thêm "roles" để tương thích.
        Object roleObj = claims.get("role");
        if (roleObj == null) {
            roleObj = claims.get("roles");
        }
        if (roleObj instanceof String s) {
            return s;
        }
        if (roleObj instanceof Collection<?> c && !c.isEmpty()) {
            Object first = c.iterator().next();
            return first != null ? first.toString() : "";
        }
        return roleObj != null ? roleObj.toString() : "";
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
