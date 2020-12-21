package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var ENCRYPT_KEY = ""
var PROXY_URL = ""

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText) % blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS7UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	unpadding := int(plainText[length - 1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := plainText[len(plainText) - unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return plainText[:(length - unpadding)], nil
}

func EncryptData(key string, data []byte) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalln("key error")
	}

	iv := make([]byte, 16)
	rand.Read(iv)

	cbc := cipher.NewCBCEncrypter(block, iv)
	src := PKCS7Padding(data, block.BlockSize())

	crypted := make([]byte, len(src))
	cbc.CryptBlocks(crypted, src)

	return append(iv, crypted...)
}

func DecryptData(key string, data []byte) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalln("key error")
	}

	outbuf := make([]byte, len(data) - 16)

	cbc := cipher.NewCBCDecrypter(block, data[:16])
	cbc.CryptBlocks(outbuf, data[16:])

	outbuf, _ = PKCS7UnPadding(outbuf, block.BlockSize())

	return outbuf
}

func HandleHTTP(w http.ResponseWriter, req *http.Request) {
	var data string
	var requestData string
	var headerData string

	if req.Method == "CONNECT" {
		log.Println("Have no support CONNECT method yet")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	port := "80"
	host := req.URL.Hostname()

	if req.URL.Port() == "" && req.URL.Hostname() == "" {
		tmp := strings.Split(req.Host, ":")
		if len(tmp) == 2 {
			host = tmp[0]
			port = tmp[1]
		}
	} else if req.URL.Port() != "" {
		port = req.URL.Port()
	}

	log.Printf("%s, %s, %s, %s\n", req.Method, host, port, req.URL.RequestURI())

	requestData = ""
	if req.Method == "POST" {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			panic(err)
		}
		requestData = base64.StdEncoding.EncodeToString(b)
	}

	for k, vv := range req.Header {
		for _, v := range vv {
			headerData += fmt.Sprintf("%s=%s\r\n", k, v)
		}
	}
	headerData = base64.StdEncoding.EncodeToString([]byte(headerData))

	data = fmt.Sprintf("%s,%s,%s,%s,%s,%s", host, port, req.Method, req.URL.RequestURI(), headerData, requestData)

	formData := url.Values{
		"clientlog" : { base64.StdEncoding.EncodeToString(EncryptData(ENCRYPT_KEY, []byte(data))) },
	}

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}
	srvReq, err := http.NewRequest("POST", PROXY_URL, bytes.NewReader([]byte(formData.Encode())))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	resp, err := client.Do(srvReq)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	decodeData, _ := base64.StdEncoding.DecodeString(string(body))
	plain := string(DecryptData(ENCRYPT_KEY, decodeData))

	out := strings.Split(plain, ",")
	if len(out) < 3 {
		log.Println(plain)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	headersRaw, _ := base64.StdEncoding.DecodeString(out[1])
	for _, v := range strings.Split(strings.TrimSpace(string(headersRaw)), "\n") {
		if v == "" {
			continue
		}
		pair := strings.SplitN(v, "=", 2)
		if pair[0] == "Transfer-Encoding" {
			continue
		}

		// log.Printf("H: %s, V: %s\n", pair[0], pair[1])

		w.Header().Add(pair[0], pair[1])
	}

	status, _ := strconv.Atoi(out[0])
	w.WriteHeader(status)

	contentRaw, _ := base64.StdEncoding.DecodeString(out[2])
	_, err = w.Write(contentRaw)

	if err := resp.Body.Close(); err != nil {
		log.Println(err)
	}
}

func main() {
	var port string
	flag.StringVar(&port, "port", "8888", "Proxy port")
	flag.StringVar(&PROXY_URL, "url", "", "Proxy URL on remote target")
	flag.StringVar(&ENCRYPT_KEY, "key", "", "Encrypt key of the traffic for remote request")
	flag.Parse()

	if port == "" || PROXY_URL == "" || ENCRYPT_KEY == "" {
		flag.PrintDefaults()
		return
	}

	server := &http.Server{
		Addr: "127.0.0.1:" + port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// log.Println("Connection in")
			HandleHTTP(w, r)
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Printf("HTTP proxy server listening on 127.0.0.1:%s\n", port)

	log.Fatal(server.ListenAndServe())
}