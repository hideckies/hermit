package stdout

import (
	"fmt"

	"github.com/fatih/color"
)

// Credit: https://patorjk.com/software/taag/#p=display&f=Calvin%20S&t=HERMIT
const BANNER = `
      ╦ ╦╔═╗╦═╗╔╦╗╦╔╦╗
      ╠═╣║╣ ╠╦╝║║║║ ║ 
      ╩ ╩╚═╝╩╚═╩ ╩╩ ╩ 
     =================
     COMMAND & CONTROL
     DEVELOPED BY HDKS
`

const BANNER_CLIENT = `
      ╦ ╦╔═╗╦═╗╔╦╗╦╔╦╗
      ╠═╣║╣ ╠╦╝║║║║ ║ 
      ╩ ╩╚═╝╩╚═╩ ╩╩ ╩ 
      ================
      ╔═╗╦  ╦╔═╗╔╗╔╔╦╗
      ║  ║  ║║╣ ║║║ ║ 
      ╚═╝╩═╝╩╚═╝╝╚╝ ╩ 
`

const BANNER_LISTENER = `
         ╦ ╦╔═╗╦═╗╔╦╗╦╔╦╗
         ╠═╣║╣ ╠╦╝║║║║ ║ 
         ╩ ╩╚═╝╩╚═╩ ╩╩ ╩ 
      ======================
      ╦  ╦╔═╗╔╦╗╔═╗╔╗╔╔═╗╦═╗
      ║  ║╚═╗ ║ ║╣ ║║║║╣ ╠╦╝
      ╩═╝╩╚═╝ ╩ ╚═╝╝╚╝╚═╝╩╚═ 
`

const BANNER_PAYLOAD = ` 
         ╦ ╦╔═╗╦═╗╔╦╗╦╔╦╗
         ╠═╣║╣ ╠╦╝║║║║ ║ 
         ╩ ╩╚═╝╩╚═╩ ╩╩ ╩ 
      =====================
      ╔═╗╔═╗╦ ╦╦  ╔═╗╔═╗╔╦╗
      ╠═╝╠═╣╚╦╝║  ║ ║╠═╣ ║║
      ╩  ╩ ╩ ╩ ╩═╝╚═╝╩ ╩═╩╝
`

func PrintBanner() {
	fmt.Printf("\n%s\n\n", color.HiYellowString(BANNER))
}

func PrintBannerListener() {
	fmt.Printf("\n%s\n\n", color.HiCyanString(BANNER_LISTENER))
}

func PrintBannerPayload() {
	fmt.Printf("\n%s\n\n", color.HiRedString(BANNER_PAYLOAD))
}

func PrintBannerClient() {
	fmt.Printf("\n%s\n\n", color.HiGreenString(BANNER_CLIENT))
}
