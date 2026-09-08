package main

import (
	"csqtt-vpn/updater"
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if updater.RunHelper() {
		return
	}
	app := NewApp()

	err := wails.Run(&options.App{
		Title: "CSQTT VPN",
		// Высота 860 не помещалась ни на 1366×768, ни на 1080p при масштабе 150 %
		// (там рабочая область — те самые 720 логических px, что стояли в MinHeight).
		// Компоновка со схлопывающимся доком и вкладками укладывается в 560, а
		// ширина 720 нужна журналу: диагностика печатает route print и ipconfig /all.
		Width:     720,
		Height:    560,
		MinWidth:  560,
		MinHeight: 460,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 11, G: 13, B: 18, A: 1},
		OnStartup:        app.startup,
		// Закрытие окна обязано откатить маршруты, DNS и NRPT-правило: последнее
		// живёт в реестре и переживает перезагрузку, оставляя систему без DNS.
		OnBeforeClose: app.beforeClose,
		Bind:          []interface{}{app},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			Theme:                windows.Dark, // светлая рамка над тёмным UI выглядела чужеродно
			// Ctrl+колесо — привычный жест на Windows, но окно рассчитано по высоте
			// точно, и случайный зум ломает раскладку.
			ZoomFactor:           1.0,
			IsZoomControlEnabled: false,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
