package auth2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
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

// AccessToken step2 获取access_token
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

// RefreshToken step2.1 获取刷新access_token refresh_token
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
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	Headimgurl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	Unionid    string   `json:"unionid"`
}

// SnsApiUserInfo step3 获取微信个人信息
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

// AccessTokenEffective 检验授权凭证(access_token)是否有效
func AccessTokenEffective(accessToken, openid string) (err error) {
	uri := "https://api.weixin.qq.com/sns/auth?access_token=%s&openid=%s"
	uri = fmt.Sprintf(uri, accessToken, openid)
	resBytes, err := Get(uri)
	if err != nil {
		return err
	}
	type result struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
	}
	tmp := result{}
	err = json.Unmarshal(resBytes, &tmp)
	if err != nil {
		return err
	}
	// 无效的AccessToken
	if tmp.Errcode != 0 {
		err = errors.New("access_token is invalid")
		return err
	}
	// 有效的AccessToken
	return nil
}

// Get http/https request get请求
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

// Base64Encrypt base64加密
func Base64Encrypt(plainText []byte) string {
	return base64.StdEncoding.EncodeToString(plainText)
}

// Base64Decrypt base64解密
func Base64Decrypt(cipherText string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(cipherText)
}

// AddKvToUrl url链接中添加键值对
func AddKvToUrl(uri, key, val string) string {
	i1 := strings.Index(uri, "?")
	i2 := strings.Index(uri, "#")
	s, s1, s2 := "", "", ""
	if i1 >= 0 {
		if i2 >= 0 {
			if i1 < i2 { // ... ? ... # ...
				s = uri[:i1]
				s1 = uri[i1:i2]
				s2 = uri[i2:]
			} else { // ... # ... ? ...
				s = uri[:i2]
				s1 = uri[i2:]
				s2 = uri[i2:i1]
			}
		} else { // ... ? ...
			s = uri[:i1]
			s1 = uri[i1:]
		}
	} else {
		if i2 >= 0 { // ... # ...
			s = uri[:i2]
			s2 = uri[i2:]
		} else { // ...
			s = uri
		}
	}
	tmp := strings.Index(s1, "?")
	if tmp > 0 {
		s1 = s1[tmp:]
	}
	lens1 := len(s1)
	if lens1 == 0 {
		s1 = fmt.Sprintf("%s?%s=%s", s1, key, val)
	} else if lens1 == 1 {
		s1 = fmt.Sprintf("%s%s=%s", s1, key, val)
	} else {
		s1 = fmt.Sprintf("%s&%s=%s", s1, key, val)
	}
	return fmt.Sprintf("%s%s%s", s, s1, s2)
}
