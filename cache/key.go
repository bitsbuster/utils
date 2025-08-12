package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// Función para generar un hash SHA-256 de un string largo
func GenerateCacheKey(input string) string {
	hash := sha256.New()                   // Crear un nuevo hash SHA-256
	hash.Write([]byte(input))              // Escribir los datos al hash
	hashedBytes := hash.Sum(nil)           // Obtener el hash resultante
	return hex.EncodeToString(hashedBytes) // Convertir el hash a string hexadecimal
}
