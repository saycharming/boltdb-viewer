package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var db *bolt.DB

func main() {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	// Construct the full path to your BoltDB file
	dbPath := filepath.Join(homeDir, "path", "direct")

	// Open the BoltDB file
	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatalf("Failed to open BoltDB file at %s: %v", dbPath, err)
	}
	defer db.Close()

	// Set up HTTP endpoints
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/bucket", bucketHandler)

	fmt.Println("BoltDB viewer running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// homeHandler lists all top-level buckets in your BoltDB file.
func homeHandler(w http.ResponseWriter, r *http.Request) {
	var buckets []string
	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			buckets = append(buckets, string(name))
			return nil
		})
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buckets)
}

// bucketHandler returns all key-value pairs for the specified bucket.
func bucketHandler(w http.ResponseWriter, r *http.Request) {
	bucketName := r.URL.Query().Get("name")
	if bucketName == "" {
		http.Error(w, "bucket name is required as query parameter 'name'", http.StatusBadRequest)
		return
	}

	var kvPairs []map[string]string
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bucketName)
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			kvPairs = append(kvPairs, map[string]string{
				"key":   string(k),
				"value": string(v),
			})
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(kvPairs)
}
