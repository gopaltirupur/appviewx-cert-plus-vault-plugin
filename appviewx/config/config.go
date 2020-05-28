package config

import (
	"encoding/json"
)

type Config struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	IsHTTPS  bool   `json:"is_https"`
	UserName string `json:"user_name"`
	Password string `json:"password"`
}

func (config *Config) GenerateResponseData() map[string]interface{} {
	output := map[string]interface{}{}

	configMarshalled, _ := json.Marshal(config)

	json.Unmarshal(configMarshalled, &output)

	return output
}

// func init() {

// 	ConfigInstance.IP = "192.168.96.218"
// 	ConfigInstance.Port = "5300"
// 	ConfigInstance.IsHttps = true
// 	ConfigInstance.UserName = "admin"
// 	ConfigInstance.Password = "AppViewX@123"
// 	// workingDirectory, _ := os.Getwd()
// 	// log.Println(workingDirectory)

// 	// file, err := os.Open(configPath + "/config.json")
// 	// if err != nil {
// 	// 	// log.Println("Error in opening the file")
// 	// }
// 	// defer file.Close()

// 	// output, err := ioutil.ReadAll(file)
// 	// if err != nil {
// 	// 	log.Println("Error in reading the content")
// 	// }
// 	// // log.Println(string(output))
// 	// json.Unmarshal(output, &Config)
// }
