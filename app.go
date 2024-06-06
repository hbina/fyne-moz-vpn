package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

type SelectState struct {
	Country string
	City    string
	Relay   string
}

type MozApp struct {
	App         fyne.App
	Window      fyne.Window
	Client      *MozClient
	User        *User
	connected   bool
	relayList   *RelayList
	selectState SelectState
}

var APP_UUID = "c8497240-20ca-11ef-8bd1-27e3d5bda132"

func newMozApp() *MozApp {
	app := app.NewWithID(APP_UUID)
	mainWindow := app.NewWindow("Mozilla VPN")
	mainWindow.Resize(fyne.NewSize(500, 500))

	mozClient := MozClient{
		client: &http.Client{},
	}
	relayList, err := mozClient.GetRelayList()

	if err != nil {
		log.Printf("Unable to get relay list err:%s\n", err)
	}

	mozApp := &MozApp{
		App:       app,
		Window:    mainWindow,
		Client:    &mozClient,
		User:      nil,
		connected: false,
		relayList: relayList,
		selectState: SelectState{
			Country: "",
			City:    "",
			Relay:   "",
		},
	}

	return mozApp
}

func (m *MozApp) InitUser() error {
	mozToken := m.App.Preferences().String("MOZ_TOKEN")

	if mozToken == "" {
		res, err := m.Client.Login()
		if err != nil {
			return fmt.Errorf("unable perform Login err:%s", err)
		}

		newMozToken := res.Token
		m.App.Preferences().SetString("MOZ_TOKEN", newMozToken)
		mozToken = newMozToken

		m.User = &res.User
		return nil
	} else {
		user, err := m.Client.GetUser(mozToken)
		if err != nil {
			return fmt.Errorf("unable perform GetUser err:%s", err)
		}

		m.User = user
		return nil
	}
}

func (m *MozApp) CheckDevice() error {
	mozToken := m.App.Preferences().String("MOZ_TOKEN")
	currPubKey := m.App.Preferences().String("PUB_KEY")

	found := false
	if currPubKey != "" {
		for _, d := range m.User.Devices {
			if d.Pubkey == currPubKey {
				found = true
				break
			}
		}
	}

	if !found {
		log.Println("Cannot find a matching public key")
	}

	if !found && len(m.User.Devices) < 5 {
		newPubBytes, newPrivBytes, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("error generating key err:%s", err)
		}

		newPubKey := base64.StdEncoding.EncodeToString(newPubBytes)
		newPrivKey := base64.StdEncoding.EncodeToString(newPrivBytes)

		_, _ = m.Client.UploadDevice(newPubKey, mozToken)

		m.App.Preferences().SetString("PRIV_KEY", newPrivKey)
		m.App.Preferences().SetString("PUB_KEY", newPubKey)
	} else if !found && len(m.User.Devices) >= 5 {
		return fmt.Errorf("you need to remove some devices because Mozilla VPN only supports up to 5 public keys")
	}

	return nil
}

func (m MozApp) GetKeys() (string, string) {
	return m.App.Preferences().String("PRIV_KEY"), m.App.Preferences().String("PUB_KEY")
}

func (m *MozApp) InitUi() error {
	// _, pubKey := m.GetKeys()

	// deviceList := widget.NewList(
	// 	func() int {
	// 		return len(m.User.Devices)
	// 	},
	// 	func() fyne.CanvasObject {
	// 		name := widget.NewLabel("")
	// 		// uniqueIdStr := widget.NewLabel("")
	// 		pubKey := widget.NewLabel("")
	// 		ipv4 := widget.NewLabel("")
	// 		ipv6 := widget.NewLabel("")
	// 		createdAt := widget.NewLabel("")

	// 		background := canvas.NewRectangle(color.RGBA{R: 255, G: 255, B: 255, A: 255})
	// 		content := container.NewStack(
	// 			background,
	// 			container.NewVBox(
	// 				name,
	// 				pubKey,
	// 				ipv4,
	// 				ipv6,
	// 				createdAt,
	// 			))
	// 		return content
	// 	},
	// 	func(i widget.ListItemID, o fyne.CanvasObject) {
	// 		background := o.(*fyne.Container).Objects[0].(*canvas.Rectangle)
	// 		container := o.(*fyne.Container).Objects[1].(*fyne.Container)

	// 		if i >= len(m.User.Devices) {
	// 			return
	// 		}

	// 		nameLabel := container.Objects[0].(*widget.Label)
	// 		// uniqueIdLabel := container.Objects[1].(*widget.Label)
	// 		pubKeyLabel := container.Objects[1].(*widget.Label)
	// 		ipv4Label := container.Objects[2].(*widget.Label)
	// 		ipv6Label := container.Objects[3].(*widget.Label)
	// 		createdAtLabel := container.Objects[4].(*widget.Label)

	// 		deviceName := m.User.Devices[i].Name
	// 		deviceUniqueId := m.User.Devices[i].UniqueID
	// 		devicePubKey := m.User.Devices[i].Pubkey
	// 		deviceIpv4 := m.User.Devices[i].IPv4Address
	// 		deviceIpv6 := m.User.Devices[i].IPv6Address
	// 		deviceCreatedAt := m.User.Devices[i].CreatedAt.String()

	// 		if deviceUniqueId != nil && *deviceUniqueId != "" {
	// 			nameLabel.SetText(fmt.Sprintf("%s (%s)", deviceName, *deviceUniqueId))
	// 		} else {
	// 			nameLabel.SetText(deviceName)
	// 		}
	// 		pubKeyLabel.SetText(devicePubKey)
	// 		ipv4Label.SetText(deviceIpv4)
	// 		ipv6Label.SetText(deviceIpv6)
	// 		createdAtLabel.SetText(deviceCreatedAt)

	// 		if pubKey == devicePubKey {
	// 			background.FillColor = color.RGBA{R: 200, G: 225, B: 200, A: 255}
	// 		} else {
	// 			background.FillColor = color.RGBA{R: 255, G: 255, B: 255, A: 255}
	// 		}
	// 		background.Refresh()
	// 	})

	// relayList := widget.NewList(
	// 	func() int {
	// 		if m.relayList == nil {
	// 			return 0
	// 		}
	// 		return len(m.relayList)
	// 	},
	// 	func() fyne.CanvasObject {
	// 		countryName := widget.NewLabel("")
	// 		countryCode := widget.NewLabel("")

	// 		cityName := widget.NewLabel("")
	// 		cityCode := widget.NewLabel("")
	// 		cityLongitude := widget.NewLabel("")
	// 		cityLatitude := widget.NewLabel("")

	// 		relayHostname := widget.NewLabel("")
	// 		relayIpv4Addr := widget.NewLabel("")
	// 		relayIpv6Addr := widget.NewLabel("")
	// 		relayPubkey := widget.NewLabel("")
	// 		relayMultihopPort := widget.NewLabel("")

	// 		content := container.NewVBox(
	// 			countryName,
	// 			countryCode,

	// 			cityName,
	// 			cityCode,
	// 			cityLongitude,
	// 			cityLatitude,
	// 			relayHostname,

	// 			relayIpv4Addr,
	// 			relayIpv6Addr,
	// 			relayPubkey,
	// 			relayMultihopPort,
	// 		)
	// 		return content
	// 	},
	// 	func(i widget.ListItemID, o fyne.CanvasObject) {
	// 		// background := o.(*fyne.Container).Objects[0].(*canvas.Rectangle)
	// 		container := o.(*fyne.Container)

	// 		if m.relayList == nil {
	// 			return
	// 		}
	// 		total := len(m.relayList)

	// 		if i >= total {
	// 			return
	// 		}

	// 		labelCountryName := container.Objects[0].(*widget.Label)
	// 		labelCountryCode := container.Objects[1].(*widget.Label)

	// 		labelCityName := container.Objects[2].(*widget.Label)
	// 		labelCityCode := container.Objects[3].(*widget.Label)
	// 		labelCityLongitude := container.Objects[4].(*widget.Label)
	// 		labelCityLatitude := container.Objects[5].(*widget.Label)

	// 		labelRelayHostname := container.Objects[6].(*widget.Label)
	// 		labelRelayIpv4Addr := container.Objects[7].(*widget.Label)
	// 		labelRelayIpv6Addr := container.Objects[8].(*widget.Label)
	// 		labelRelayPubkey := container.Objects[9].(*widget.Label)
	// 		labelRelayMultihopPort := container.Objects[10].(*widget.Label)

	// 		countryName := m.relayList[i].CountryName
	// 		countryCode := m.relayList[i].CountryCode

	// 		cityName := m.relayList[i].CityName
	// 		cityCode := m.relayList[i].CityCode
	// 		cityLongitude := m.relayList[i].CityLongitude
	// 		cityLatitude := m.relayList[i].CityLatitude

	// 		relayHostname := m.relayList[i].RelayHostname
	// 		relayIpv4AddrIn := m.relayList[i].RelayIpV4AddrIn
	// 		relayIpv6AddrIn := m.relayList[i].RelayIpV4AddrIn
	// 		relayPubkey := m.relayList[i].RelayPubKey
	// 		relayMultihopPort := m.relayList[i].RelayMultihopPort

	// 		labelCountryName.SetText(countryName)
	// 		labelCountryCode.SetText(countryCode)

	// 		labelCityName.SetText(cityName)
	// 		labelCityCode.SetText(cityCode)
	// 		labelCityLongitude.SetText(fmt.Sprintf("%f", cityLongitude))
	// 		labelCityLatitude.SetText(fmt.Sprintf("%f", cityLatitude))

	// 		labelRelayHostname.SetText(relayHostname)
	// 		labelRelayIpv4Addr.SetText(relayIpv4AddrIn)
	// 		labelRelayIpv6Addr.SetText(relayIpv6AddrIn)
	// 		labelRelayPubkey.SetText(relayPubkey)
	// 		labelRelayMultihopPort.SetText(fmt.Sprintf("%d", relayMultihopPort))
	// 	})

	selectRelay := widget.NewSelect([]string{}, func(value string) {
		log.Println("Select relay", value)
		m.selectState.Relay = value
	})
	selectCity := widget.NewSelect([]string{}, func(value string) {
		log.Println("Select city", value)
		m.selectState.City = value
		for _, c1 := range m.relayList.Countries {
			if c1.Name == m.selectState.Country {
				for _, c2 := range c1.Cities {
					if c2.Name == m.selectState.City {
						relayList := make([]string, 0, len(c2.Relays))
						for _, r := range c2.Relays {
							relayList = append(relayList, r.Hostname)
						}
						fmt.Println("relayList", relayList)
						selectRelay.SetOptions(relayList)
						break
					}
				}
				break
			}
		}
		selectRelay.SetSelected("")
		selectRelay.Refresh()
	})
	countryList := make([]string, 0, len(m.relayList.Countries))
	for _, c := range m.relayList.Countries {
		countryList = append(countryList, c.Name)
	}
	selectCountry := widget.NewSelect(countryList, func(value string) {
		log.Println("Select country", value)
		m.selectState.Country = value
		for _, c1 := range m.relayList.Countries {
			if c1.Name == m.selectState.Country {
				cityList := make([]string, 0, len(c1.Cities))
				for _, c2 := range c1.Cities {
					cityList = append(cityList, c2.Name)
				}
				fmt.Println("cityList", cityList)
				selectCity.SetOptions(cityList)
				break
			}
		}
		selectCity.ClearSelected()
		selectRelay.ClearSelected()
		selectRelay.SetOptions([]string{})
	})
	serverContainer := container.New(layout.NewVBoxLayout(),
		selectCountry,
		selectCity,
		selectRelay)

	stateLabel := widget.NewLabel("Disconnected")
	connectButton := widget.NewButton("Connect", nil)
	connectButton.OnTapped = func() {
		m.connected = !m.connected
		if m.connected {
			stateLabel.SetText("Connected")
			connectButton.SetText("Disconnect")
		} else {
			stateLabel.SetText("Disconnected")
			connectButton.SetText("Connect")
		}
	}

	// _ = deviceList
	// _ = relayList

	// tabs := container.NewAppTabs(
	// 	container.NewTabItemWithIcon("Home", theme.HomeIcon(), widget.NewLabel("Home")),
	// 	container.NewTabItemWithIcon("Servers", theme.ComputerIcon(), serverContainer),
	// 	container.NewTabItemWithIcon("Devices", theme.ComputerIcon(), deviceList),
	// )

	topContainer := container.New(layout.NewVBoxLayout(),
		serverContainer,
		stateLabel,
		connectButton,
	)

	m.Window.SetContent(topContainer)
	m.Window.ShowAndRun()
	return nil
}

func (m *MozApp) GetCurrentDevice() *Device {
	if m.User == nil {
		return nil
	}

	pubKey := m.App.Preferences().String("PUB_KEY")

	if pubKey == "" {
		return nil
	}

	for _, d := range m.User.Devices {
		if d.Pubkey == pubKey {
			return &d
		}
	}

	return nil
}
