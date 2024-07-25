package com.security.oauth.controller;

import com.github.scribejava.apis.TwitterApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.*;
import com.github.scribejava.core.oauth.OAuth10aService;
import com.security.oauth.OAuth1Application;
import jakarta.servlet.http.HttpSession;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.concurrent.ExecutionException;

public class HomeController {
    private String apiKey;
    private String apiSecret;

    private static final String URL = "http://localhost:8080/callback";

    @GetMapping("/")
    public String home() {
        return "Home Page";
    }

    public String login(HttpSession session) throws IOException, ExecutionException, InterruptedException {
        OAuth10aService service = new ServiceBuilder(apiKey)
                .apiSecret(apiSecret)
                .callback(URL)
                .build(TwitterApi.instance());

        OAuth1RequestToken requestToken = service.getRequestToken();
        session.setAttribute("requestToken", requestToken);
        return "redirect:" + service.getAuthorizationUrl(requestToken);
    }

    @GetMapping("/callback")
    public String callBack(@RequestParam("oauth_token") String oauthToken,
                           @RequestParam("oauth_verifier") String oauthVerifier,
                           HttpSession session) throws IOException, ExecutionException, InterruptedException {
        OAuth1RequestToken requestToken = (OAuth1RequestToken) session.getAttribute("requestToken");
        OAuth10aService service = new ServiceBuilder(apiKey).apiSecret(apiSecret).callback(URL).build(TwitterApi.instance());

        OAuth1AccessToken accessToken = service.getAccessToken(requestToken, oauthVerifier);
        session.setAttribute("accessToken", accessToken);
        return "redirect:/secure";
    }

    @GetMapping("/secure")
    public String secure(HttpSession session, Model model) throws IOException, ExecutionException, InterruptedException {
        OAuth1AccessToken accessToken = (OAuth1AccessToken) session.getAttribute("accessToken");
        if (null != accessToken) {
            OAuth10aService service = new ServiceBuilder(apiKey).apiSecret(apiSecret).build(TwitterApi.instance());
            OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.twitter.com/1.1/account/verify_credentials.json");
            service.signRequest(accessToken, request);
            Response response = service.execute(request);
            model.addAttribute("resource", response.getBody());
            return "secure";
        } else {
            return "redirect:/login";
        }
    }
}
