package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/pkg/browser"
)

type User struct {
	Email         string        `json:"email"`
	Avatar        string        `json:"avatar"`
	DisplayName   string        `json:"display_name"`
	Devices       []Device      `json:"devices"`
	Subscriptions Subscriptions `json:"subscriptions"`
	MaxDevices    int           `json:"max_devices"`
}

type Device struct {
	Name        string    `json:"name"`
	UniqueID    *string   `json:"unique_id"` // Using *string to allow null values
	Pubkey      string    `json:"pubkey"`
	IPv4Address string    `json:"ipv4_address"`
	IPv6Address string    `json:"ipv6_address"`
	CreatedAt   time.Time `json:"created_at"`
}

type Subscriptions struct {
	Vpn VPN `json:"vpn"`
}

type VPN struct {
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	RenewsOn  time.Time `json:"renews_on"`
}

type Root struct {
	User  User   `json:"user"`
	Token string `json:"token"`
}

type UploadRes struct {
	Name        string    `json:"name"`
	UniqueID    string    `json:"unique_id"`
	Pubkey      string    `json:"pubkey"`
	IPv4Address string    `json:"ipv4_address"`
	IPv6Address string    `json:"ipv6_address"`
	CreatedAt   time.Time `json:"created_at"`
}

type Relay struct {
	Hostname     string `json:"hostname"`
	IpV4AddrIn   string `json:"ipv4_addr_in"`
	IpV6AddrIn   string `json:"ipv6_addr_in"`
	PubKey       string `json:"public_key"`
	MultihopPort uint16 `json:"multihop_port"`
}

type City struct {
	Name      string  `json:"name"`
	Code      string  `json:"code"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Relays    []Relay `json:"relays"`
}

type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type RelayList struct {
	Countries []Country `json:"countries"`
}

type FlatRelay struct {
	CountryName string
	CountryCode string

	CityName      string
	CityCode      string
	CityLatitude  float64
	CityLongitude float64

	RelayHostname     string
	RelayIpV4AddrIn   string
	RelayIpV6AddrIn   string
	RelayPubKey       string
	RelayMultihopPort uint16
}

type MozClient struct {
	client *http.Client
}

var rELAY_LIST = "https://api.mullvad.net/public/relays/wireguard/v1/"
var bASE_URL = "https://vpn.mozilla.org"
var v1_API = "api/v1"
var v2_API = "api/v2"

func (m *MozClient) GetUser(mozToken string) (*User, error) {
	requestUrl := fmt.Sprintf("%s/%s/vpn/account", bASE_URL, v1_API)
	req, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("unable create GET request err:%s", err)
	}

	bearerAuth := fmt.Sprintf("Bearer %s", mozToken)
	req.Header.Set("Authorization", bearerAuth)

	res, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable perform GET request err:%s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		if res.Body != nil {
			bodyStr, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, fmt.Errorf("unable to get body from HTTP request err:%s", err)
			}
			log.Println("bodyStr", string(bodyStr))
		}
		return nil, fmt.Errorf("did not get HTTP 200 from request err:%s", err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to get body from HTTP request err:%s", err)
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON as User err:%s", err)
	}

	return &user, nil
}

func (m *MozClient) verifyLogin(code string, verifier string) (*Root, error) {
	postBody, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifier,
	})
	postBuffer := bytes.NewBuffer(postBody)

	requestUrl := fmt.Sprintf("%s/%s/vpn/login/verify", bASE_URL, v2_API)
	req, err := http.NewRequest("POST", requestUrl, postBuffer)
	if err != nil {
		return nil, fmt.Errorf("unable create POST request err:%s", err)
	}
	defer req.Body.Close()

	req.Header.Set("User-Agent", "Fyne Moz VPN")
	req.Header.Set("Content-Type", "application/json")

	res, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable perform POST request err:%s", err)

	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("did not get HTTP 200 from request err:%s", err)

	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to get body from HTTP request err:%s", err)
	}

	var result Root
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON as Root err:%s", err)

	}

	return &result, nil
}

func (m *MozClient) Login() (*Root, error) {
	channel := make(chan *Root, 1)
	verifier, browserUrl := createChallengeUrl()
	server := m.startServer(verifier, channel)

	err := browser.OpenURL(browserUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to open URL err:%s", err)
	}

	res := <-channel
	server.Shutdown(context.TODO())
	return res, nil
}

func (m *MozClient) createHandler(verifier string, channel chan<- *Root) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		queries := r.URL.Query()
		code := queries.Get("code")
		log.Println("Code", code)

		if code == "" {
			return
		}

		result, err := m.verifyLogin(code, verifier)
		if err != nil {
			log.Printf("Unable to open URL err:%s\n", err)
			return
		}

		channel <- result
	}
}

func createChallengeUrl() (string, string) {
	a := make([]byte, 32)
	rand.Read(a)

	b := base64.StdEncoding.EncodeToString(a)

	s := sha256.New()
	s.Write([]byte(b))
	c := s.Sum(nil)

	d := base64.StdEncoding.EncodeToString(c)

	browserUrl := fmt.Sprintf(
		"%s/%s/vpn/login/linux?code_challenge_method=S256&code_challenge=%s&port=%s",
		bASE_URL,
		v2_API,
		d,
		"9443")
	return b, browserUrl
}

func (m *MozClient) startServer(verifier string, in chan<- *Root) *http.Server {
	http.HandleFunc("/", m.createHandler(verifier, in))
	server := &http.Server{Addr: ":9443", Handler: nil}
	go server.ListenAndServe()
	return server
}

func (m *MozClient) UploadDevice(pubKey string, mozToken string) (*UploadRes, error) {
	postBody, err := json.Marshal(map[string]string{
		"name":   "MozVPN",
		"pubkey": pubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("unable marshal JSON err:%s", err)
	}

	postStr := bytes.NewBuffer(postBody)
	requestUrl := fmt.Sprintf("%s/%s/vpn/device", bASE_URL, v1_API)
	req, err := http.NewRequest("POST", requestUrl, postStr)
	if err != nil {
		return nil, fmt.Errorf("unable create POST request err:%s", err)
	}

	bearerStr := fmt.Sprintf("Bearer %s", mozToken)
	req.Header.Set("Authorization", bearerStr)
	req.Header.Set("User-Agent", "Fyne Moz VPN")
	req.Header.Set("Content-Type", "application/json")
	res, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable perform POST request err:%s", err)
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to get body from HTTP request err:%s", err)
	}

	var result UploadRes
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON as User err:%s", err)
	}

	return &result, nil
}

func (m *MozClient) GetRelayList() (*RelayList, error) {
	req, err := http.NewRequest("GET", rELAY_LIST, nil)
	if err != nil {
		return nil, fmt.Errorf("unable create GET request to %s err:%s", rELAY_LIST, err)
	}

	res, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable perform GET request err:%s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		if res.Body != nil {
			bodyStr, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, fmt.Errorf("unable to get body from HTTP request to %s err:%s", rELAY_LIST, err)
			}
			log.Println("bodyStr", string(bodyStr))
		}
		return nil, fmt.Errorf("did not get HTTP 200 from request to %s err:%s", rELAY_LIST, err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to get body from HTTP request to %s err:%s", rELAY_LIST, err)
	}

	var relay RelayList
	err = json.Unmarshal(body, &relay)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON as User obtained from %s err:%s", rELAY_LIST, err)
	}

	// result := make([]FlatRelay, 0)

	// for _, c1 := range relay.Countries {
	// 	countryName := c1.Name
	// 	countryCode := c1.Code
	// 	for _, c2 := range c1.Cities {
	// 		cityName := c2.Name
	// 		cityCode := c2.Code
	// 		cityLatitude := c2.Latitude
	// 		cityLongitude := c2.Longitude
	// 		for _, r := range c2.Relays {
	// 			relayHostname := r.Hostname
	// 			relayIpv4AddrIn := r.IpV4AddrIn
	// 			relayIpV6AddrIn := r.IpV6AddrIn
	// 			relayPubKey := r.PubKey
	// 			relayMultihopPort := r.MultihopPort

	// 			flatRelay := FlatRelay{
	// 				CountryName: countryName,
	// 				CountryCode: countryCode,

	// 				CityName:      cityName,
	// 				CityCode:      cityCode,
	// 				CityLatitude:  cityLatitude,
	// 				CityLongitude: cityLongitude,

	// 				RelayHostname:     relayHostname,
	// 				RelayIpV4AddrIn:   relayIpv4AddrIn,
	// 				RelayIpV6AddrIn:   relayIpV6AddrIn,
	// 				RelayPubKey:       relayPubKey,
	// 				RelayMultihopPort: relayMultihopPort,
	// 			}

	// 			result = append(result, flatRelay)

	// 		}
	// 	}
	// }

	// fmt.Println("len(result)", len(result))

	return &relay, nil
}
