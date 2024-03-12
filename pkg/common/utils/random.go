package utils

import (
	"math/rand"
	"strings"
)

var animalNames = []string{
	"aardvark", "alphabeetle", "aquafox", "ayeaye",
	"betafox", "blazewolf",
	"capybara", "caracal", "chihyena", "crimsontiger",
	"dawneagle", "deltaraven", "echidna", "echopanda", "epsilonhorse", "etadove",
	"fennec", "frigatebird", "frostlynx",
	"gammawhale", "gerenuk", "gharial", "glowrabbit", "goblinshark",
	"halolion", "hoatzin", "honeybadger", "infernobear", "iotakoala", "jadefalcon",
	"kakapo", "kappaleopard", "kingcobra", "kiteserpent", "komododragon",
	"lambdamoose", "lemur", "liger", "lunarpeacock",
	"manatee", "mantaray", "mantisshrimp", "maraboustork", "muowl", "mysticshark",
	"narwhal", "nebuladeer", "numbat", "nupenguin",
	"omegasalamander", "omicronrat", "orbitgorilla",
	"pacovisca", "pangolin", "phidragon", "pisquirrel", "platypus", "psigiraffe", "pulsezebra",
	"quokka", "rhoturtle", "rodent", "quartzotter", "riftswan",
	"saigaantelope", "seahorse", "sigmavulture", "sloth", "solardolphin",
	"tapir", "tardigrade", "tauwalrus", "terrawolf",
	"thetajaguar", "tibetanfox", "toucan", "tuatara",
	"umbracat", "upsiloncrab", "vaquita", "vortexelephant",
	"waterdeer", "whisperraccoon", "wolf", "wolverine",
	"xenonhippo", "xiquail", "yak", "yieldhawk",
	"zebu", "zenithbison", "zetacheetah",
}

var humanNames = []string{
	"aaliyah", "abigail", "aiden", "alessandro", "alexander", "alice",
	"alistair", "ally", "amara",
	"amelia", "artemis", "arthur", "aspen", "atlas", "aurora", "ava",
	"benjamin", "blair", "bob", "brian", "bruce",
	"camila", "chad", "charlotte", "clementine", "coral",
	"daniel", "david", "darcy", "dimitri",
	"eleanor", "elena", "elijah", "elizabeth", "eloise", "elvis",
	"emery", "emily", "emma", "ethan", "evelyn",
	"fernand", "finley", "forest", "foster", "fred", "freya",
	"gabriel", "greg", "harper", "helen", "henry", "hera",
	"indigo", "isabella", "jackson", "jacob", "jasper", "james", "juniper", "john",
	"jonathan", "joseph", "joshua", "julia",
	"kai", "kate", "kelly", "kiran", "leo", "liam", "logan",
	"loki", "lucas", "luke", "luna", "lyra",
	"madison", "maeve", "maria", "mario", "marlowe",
	"mateo", "matt", "matthew", "mia", "michael", "montgomery", "morrigan",
	"noah", "nova", "odin", "olivia", "owen", "paul", "penelope", "peter",
	"raina", "remy", "rick", "riley", "river", "roman", "rowan",
	"sage", "scarlett", "sean", "siobhan", "skye", "sophia", "stella", "stephan", "theodore",
	"vincent", "violet", "vivian", "wilder", "william", "wren", "xiomara",
	"zachary", "zhen", "zoey",
}

var roleNames = []string{
	"agentsmith", "alchemist", "analyst", "architect", "blackhat", "brainiac", "bughunter",
	"chameleon", "cipher", "conductor", "conjurer", "consultant", "cracker",
	"crusader", "cryptomancer", "cyberpunk",
	"datadruid", "defender", "detective", "doxxer",
	"ember", "enchanter", "enigma", "excavator", "exorcist", "fantasista",
	"ghost", "greyhat", "guardian",
	"hacker", "hashbreaker", "hunter", "innovator", "jet",
	"kappa", "kitsune", "knight",
	"mage", "magician", "maker", "maverick", "mirage", "mitigator", "morpheus",
	"negotiator", "neo", "nethunter", "ninja", "niobi", "nightingale", "nomad",
	"oracle", "pentester", "phisher", "phoenix", "phreak",
	"raven", "redhat", "researcher", "resolver", "responder",
	"samurai", "scriptkiddie", "sentinel", "shaman", "sharlock",
	"shinobi", "shogun", "slayer",
	"sniffer", "sorceress", "specialist", "spectre", "sting", "strategist", "switch",
	"tank", "technician", "tester", "threathunter", "translator", "trinity", "unicorn",
	"warlock", "weaver", "whisper", "whitehat", "whiterabbit", "witch", "wizard",
	"Wrangler", "zeroday",
}

func GenerateRandomInt(min int, max int) int {
	return rand.Intn(max-min) + min
}

func GenerateRandomPort() uint16 {
	randomPort := GenerateRandomInt(49152, 65535)
	return uint16(randomPort)
}

func generateRandomName(names []string, uppercase bool, prefix string) string {
	idx := rand.Intn(len(names))
	if uppercase {
		return strings.ToUpper(names[idx])
	}

	if prefix == "" {
		return names[idx]
	} else {
		return prefix + "-" + names[idx]
	}
}

func GenerateRandomAnimalName(uppercase bool, prefix string) string {
	return generateRandomName(animalNames, uppercase, prefix)
}

func GenerateRandomHumanName(uppercase bool, prefix string) string {
	return generateRandomName(humanNames, uppercase, prefix)
}

func GenerateRandomRoleName(uppercase bool, prefix string) string {
	return generateRandomName(roleNames, uppercase, prefix)
}

func GetRandomElemString(list []string) string {
	randIdx := rand.Intn(len(list))
	return list[randIdx]
}
