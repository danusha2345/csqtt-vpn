package main

import "testing"

func TestVerificationURL(t *testing.T) {
	for _, u := range []string{"https://id.vk.com/captcha?session_token=test", "https://vk.ru/captcha"} {
		if !allowedVerificationURL(u) {
			t.Fatalf("отклонён %q", u)
		}
	}
	for _, u := range []string{"http://vk.com/", "https://id.vk.com.evil.example/", "https://vk.com@evil.example/", "file:///C:/test", "https://vk.com:444/", "https://evil.example/?vk.com"} {
		if allowedVerificationURL(u) {
			t.Fatalf("разрешён %q", u)
		}
	}
}
