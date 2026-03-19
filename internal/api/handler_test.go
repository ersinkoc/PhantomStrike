package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock Services
type MockMissionRepo struct {
	mock.Mock
}

func (m *MockMissionRepo) Create(mission *Mission) error {
	args := m.Called(mission)
	return args.Error(0)
}

func (m *MockMissionRepo) GetByID(id string) (*Mission, error) {
	args := m.Called(id)
	return args.Get(0).(*Mission), args.Error(1)
}

func TestHealthCheck(t *testing.T) {
	handler := NewHandler(nil, nil, nil)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	handler.handleHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "healthy", resp["status"])
}

func TestCreateMission(t *testing.T) {
	mockRepo := new(MockMissionRepo)
	handler := NewHandler(nil, mockRepo, nil)

	payload := map[string]interface{}{
		"name":   "Test Mission",
		"target": "http://test.com",
		"mode":   "passive",
		"depth":  "quick",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/v1/missions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Mock expectations
	mockRepo.On("Create", mock.AnythingOfType("*Mission")).Return(nil)

	handler.handleCreateMission(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockRepo.AssertExpectations(t)
}
