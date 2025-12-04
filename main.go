package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
)

const (
	keySize   = 32 // AES-256
	blockSize = aes.BlockSize
)

var encryptionKey []byte
var serverFlag string

type ChallengeResponse struct {
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type DecryptRequest struct {
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func init() {
	encryptionKey = make([]byte, keySize)
	if _, err := rand.Read(encryptionKey); err != nil {
		log.Fatal("Failed to generate encryption key:", err)
	}
}

func generateRandomFlag() string {
	flag := make([]byte, 40)
	if _, err := rand.Read(flag); err != nil {
		log.Fatal("Failed to generate flag:", err)
	}
	return fmt.Sprintf("flag{%s}", base64.URLEncoding.EncodeToString(flag))
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

func encrypt(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	paddedPlaintext := pkcs7Pad(plaintext, blockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return iv, ciphertext, nil
}

func decrypt(iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length is not a multiple of block size")
	}

	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d bytes", blockSize)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flagBytes := []byte(serverFlag)

	iv, ciphertext, err := encrypt(flagBytes)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := ChallengeResponse{
		IV:         base64.StdEncoding.EncodeToString(iv),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON"})
		return
	}

	iv, err := base64.StdEncoding.DecodeString(req.IV)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid IV encoding"})
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid ciphertext encoding"})
		return
	}

	_, err = decrypt(iv, ciphertext)
	if err != nil {
		if err.Error() == "invalid padding" || err.Error() == "invalid padding length" || err.Error() == "empty data" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Padding error"})
			return
		}

		// Other decryption errors
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Decryption error"})
		return
	}

	// Success
	w.WriteHeader(http.StatusOK)
}

func main() {
	ip := flag.String("ip", "127.0.0.1", "IP address to bind to")
	port := flag.String("port", "8000", "Port to listen on")
	flag.Parse()

	serverFlag = generateRandomFlag()
	fmt.Printf("Generated flag: %s\n", serverFlag)

	http.HandleFunc("/challenge", challengeHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	addr := fmt.Sprintf("%s:%s", *ip, *port)
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
