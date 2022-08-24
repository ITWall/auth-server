package com.tungns.clientdemo.controller;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class AppController {

    private WebClient webClient;
//    private final String messagesBaseUri;

    @GetMapping("/")
    public String welcome() {
        List<String> authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return "index";
    }

    @GetMapping("/callback")
    public String callback() {
        return "callback";
    }

//    @GetMapping(value = "/login/oauth2/code/client-1-oidc")
//    public String authorizationCodeGrant(Model model,
//                                         @RegisteredOAuth2AuthorizedClient("client-1-oidc")
//                                                 OAuth2AuthorizedClient authorizedClient) {
//
////        String[] messages = this.webClient
////                .get()
////                .uri(this.messagesBaseUri)
////                .attributes(oauth2AuthorizedClient(authorizedClient))
////                .retrieve()
////                .bodyToMono(String[].class)
////                .block();
////        model.addAttribute("messages", messages);
////        oauth2AuthorizedClient(authorizedClient);
//        System.out.println(authorizedClient.getAccessToken().getTokenValue());
//        return "index";
//    }

    @GetMapping(value = "/login/oauth2/code/client-1-oidc", params = {OAuth2ParameterNames.CODE, OAuth2ParameterNames.STATE})
    public String authorizationFailed(Model model, HttpServletRequest request) {
        String code = request.getParameter(OAuth2ParameterNames.CODE);
        System.out.println(code);

        return "index";
    }

//    @GetMapping(value = "/authorize", params = "grant_type=authorization_code")
//    public String authorizationCodeGrant(Model model,
//                                         @RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
//                                                 OAuth2AuthorizedClient authorizedClient) {
//
//        String[] messages = this.webClient
//                .get()
//                .uri(this.messagesBaseUri)
//                .attributes(oauth2AuthorizedClient(authorizedClient))
//                .retrieve()
//                .bodyToMono(String[].class)
//                .block();
//        model.addAttribute("messages", messages);
//
//        return "index";
//    }
}
