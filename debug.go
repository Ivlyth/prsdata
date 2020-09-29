package main

import (
	"encoding/json"
	"fmt"
)

func dumpConfig() {

	bytes, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		terminate()
	}
	fmt.Println("---------------------------- config dump: ")
	fmt.Println(string(bytes))

	bytes, err = json.MarshalIndent(pcapTool, "", "    ")
	if err != nil {
		terminate()
	}
	fmt.Println("---------------------------- pcap tool dump: ")
	fmt.Println(string(bytes))

	bytes, err = json.MarshalIndent(modifiers, "", "    ")
	if err != nil {
		terminate()
	}
	fmt.Println("---------------------------- modifiers dump: ")
	fmt.Println(string(bytes))

	bytes, err = json.MarshalIndent(finders, "", "    ")
	if err != nil {
		terminate()
	}
	fmt.Println("---------------------------- finders dump: ")
	fmt.Println(string(bytes))

	bytes, err = json.MarshalIndent(jobs, "", "    ")
	if err != nil {
		terminate()
	}
	fmt.Println("---------------------------- jobs dump: ")
	fmt.Println(string(bytes))
}
