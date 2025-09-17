package config

import (
	"crypto/tls"
	"log"
	"net/http"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
)

var ES *elasticsearch.Client

func ConnectionToElastic() *elasticsearch.Client {
	cfg := elasticsearch.Config{
		Addresses: []string{
			"https://192.168.200.103:9200",
		},
		Username: "sector",
		Password: "s3ct0r-x0ps",
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // ⛔️ hanya untuk dev/testing
			},
		},
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create Elasticsearch client: %s", err)
	}

	// Cek koneksi
	res, err := client.Info()
	if err != nil {
		log.Fatalf("Failed to connect to Elasticsearch: %s", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Elasticsearch returned error: %s", res.String())
	}

	log.Println("🚀 Connected Successfully to Elasticsearch")
	ES = client
	return client
}
