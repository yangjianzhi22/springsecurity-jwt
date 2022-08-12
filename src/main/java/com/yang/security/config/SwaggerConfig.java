package com.yang.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Collections;
import java.util.List;

@Configuration
public class SwaggerConfig {

    @Bean
    public Docket createRestApi() {
        return new Docket(DocumentationType.OAS_30)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.yang.security.controller"))
                .build()
                .securitySchemes(securitySchemes())
                .securityContexts(securityContexts());
    }

    // 设置授权信息
    private List<SecurityScheme> securitySchemes() {
        return Collections.singletonList(new ApiKey("token", "token", "header"));
    }

    // 授权信息全局应用
    private List<SecurityContext> securityContexts() {
        return Collections.singletonList(
                SecurityContext.builder()
                        .securityReferences(Collections.singletonList(new SecurityReference("token", new AuthorizationScope[]{new AuthorizationScope("global", "")})))
                        .build()
        );
    }
}
