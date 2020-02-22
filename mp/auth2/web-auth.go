package auth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Web Authorization 网页授权, OAuth2.0机制

// CodeRedirectUri step1 CodeRedirectUri("", "", "snsapi_userinfo", "")
func CodeRedirectUri(appId, redirectUri, scope, state string) string {
	// snsapi_base or snsapi_userinfo
	// snsapi_base: 只能获取openid
	// snsapi_userinfo: 获取用户个人信息
	if scope == "" {
		scope = "snsapi_base"
	}
	// 重定向后会带上state参数,开发者可以填写a-zA-Z0-9的参数值,最多128字节
	if state == "" {
		state = "state"
	}
	uri := "https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect"
	return fmt.Sprintf(uri, appId, url.QueryEscape(redirectUri), scope, state)
}

// AccessTokenResult
type AccessTokenResult struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Openid       string `json:"openid"`
	Scope        string `json:"scope"`
}

// AccessToken step2
func AccessToken(appId, appSecret, code string) (result *AccessTokenResult, err error) {
	uri := "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code"
	uri = fmt.Sprintf(uri, appId, appSecret, code)
	bytes, err := Get(uri)
	if err != nil {
		return result, err
	}
	tmp := AccessTokenResult{}
	err = json.Unmarshal(bytes, &tmp)
	result = &tmp
	return result, err
}

// RefreshToken step2.1
func RefreshToken(appId, refreshToken string) (result *AccessTokenResult, err error) {
	uri := "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=%s&grant_type=refresh_token&refresh_token=%s"
	uri = fmt.Sprintf(uri, appId, refreshToken)
	bytes, err := Get(uri)
	if err != nil {
		return result, err
	}
	tmp := AccessTokenResult{}
	err = json.Unmarshal(bytes, &tmp)
	result = &tmp
	return result, err
}

// SnsApiUserInfoResult
type SnsApiUserInfoResult struct {
	Openid     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        string   `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	Headimgurl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	Unionid    string   `json:"unionid"`
}

// SnsApiUserInfo step3
func SnsApiUserInfo(accessToken, openid string) (result *SnsApiUserInfoResult, err error) {
	uri := "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN"
	uri = fmt.Sprintf(uri, accessToken, openid)
	bytes, err := Get(uri)
	if err != nil {
		return result, err
	}
	tmp := SnsApiUserInfoResult{}
	err = json.Unmarshal(bytes, &tmp)
	result = &tmp
	return result, err
}

// Get http/https request
func Get(uri string) (result []byte, err error) {
	cli := &http.Client{}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return result, err
	}
	res, err := cli.Do(req)
	if err != nil {
		return result, err
	}
	defer res.Body.Close()
	return ioutil.ReadAll(res.Body)
}
