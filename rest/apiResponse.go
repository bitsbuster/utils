package rest

import (
	"encoding/json"
	"net/http"
	"time"
)

// Meta contains additional metadatadata
type Meta struct {
	Timestamp  string      `json:"timestamp"`
	RequestID  string      `json:"requestId,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Pagination contains pagination information
type Pagination struct {
	Page       uint32 `json:"page"`
	PageSize   uint32 `json:"pageSize"`
	TotalPages uint32 `json:"totalPages"`
	TotalItems uint32 `json:"totalItems"`
}

// APIResponse es la estructura común para todas las respuestas
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Errors  interface{} `json:"errors,omitempty"`
	Meta    Meta        `json:"meta"`
}

// SendResponse envía una respuesta JSON con la estructura común
func SendResponse(w http.ResponseWriter, statusCode int, success bool, message string, data interface{}, errors interface{}, pagination *Pagination) {
	response := APIResponse{
		Success: success,
		Message: message,
		Data:    data,
		Errors:  errors,
		Meta: Meta{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			RequestID:  "", // Puedes integrarlo con un middleware que genere IDs
			Pagination: pagination,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}
