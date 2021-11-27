package goauth1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sortedQuery struct {
	m    map[string]string
	keys []string
}

func SortedQueryString(m map[string]string) string {
	sq := &sortedQuery{
		m:    m,
		keys: make([]string, len(m)),
	}
	var i int
	for key := range m {
		sq.keys[i] = key
		i++
	}
	sort.Strings(sq.keys)

	values := make([]string, len(sq.keys))
	for i, key := range sq.keys {
		values[i] = fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(sq.m[key]))
	}
	return strings.Join(values, "&")
}

func hmacShaCalc(base, key string) string {
	b := []byte(key)
	h := hmac.New(sha1.New, b)
	io.WriteString(h, base)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func CreateOauth1Header(consumerKey, consumerSecret, accessToken, accessTokenSecret, httpMethod, endpointUri string) string {
	m := map[string]string{}
	m["oauth_consumer_key"] = consumerKey
	m["oauth_nonce"] = createNonce()
	m["oauth_signature_method"] = "HMAC-SHA1"
	m["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	m["oauth_token"] = accessToken
	m["oauth_version"] = "1.0"

	baseQueryString := SortedQueryString(m)
	var base []string
	base = append(base, url.QueryEscape(httpMethod))
	base = append(base, url.QueryEscape(endpointUri))
	base = append(base, url.QueryEscape(baseQueryString))
	sigBase := strings.Join(base, "&")
	sigKey := url.QueryEscape(consumerSecret) + "&" + url.QueryEscape(accessTokenSecret)
	m["oauth_signature"] = hmacShaCalc(sigBase, sigKey)
	authHeader := fmt.Sprintf("OAuth oauth_consumer_key=\"%s\",oauth_nonce=\"%s\",oauth_signature=\"%s\",oauth_signature_method=\"%s\",oauth_timestamp=\"%s\",oauth_token=\"%s\",oauth_version=\"%s\"",
		url.QueryEscape(m["oauth_consumer_key"]),
		url.QueryEscape(m["oauth_nonce"]),
		url.QueryEscape(m["oauth_signature"]),
		url.QueryEscape(m["oauth_signature_method"]),
		url.QueryEscape(m["oauth_timestamp"]),
		url.QueryEscape(m["oauth_token"]),
		url.QueryEscape(m["oauth_version"]),
	)
	return authHeader
}

func createNonce() string {
	n := make([]byte, 32)
	rand.Read(n)
	enc := base64.StdEncoding.EncodeToString(n)
	replaceStr := []string{"+", "/", "="}
	for _, str := range replaceStr {
		enc = strings.Replace(enc, str, "", -1)
	}
	return enc
}
