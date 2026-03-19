package repository

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type MissionRepoTestSuite struct {
	suite.Suite
	repo *MissionRepository
}

func (s *MissionRepoTestSuite) SetupTest() {
	// Use in-memory SQLite for unit tests
	db, err := InitTestDB()
	if err != nil {
		s.T().Fatal(err)
	}
	s.repo = NewMissionRepository(db)
}

func (s *MissionRepoTestSuite) TearDownTest() {
	// Cleanup
}

func (s *MissionRepoTestSuite) TestCreateMission() {
	mission := &Mission{
		Name:        "Test Mission",
		Description: "Test Description",
		Status:      "pending",
		Mode:        "passive",
		Depth:       "quick",
		Target:      map[string]interface{}{"host": "test.com"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := s.repo.Create(mission)
	s.NoError(err)
	s.NotEmpty(mission.ID)
}

func (s *MissionRepoTestSuite) TestGetByID() {
	// Create first
	mission := &Mission{
		Name:   "Get Test",
		Status: "pending",
		Mode:   "passive",
		Depth:  "quick",
	}
	s.repo.Create(mission)

	// Get
	found, err := s.repo.GetByID(mission.ID)
	s.NoError(err)
	s.Equal(mission.Name, found.Name)
}

func (s *MissionRepoTestSuite) TestUpdateStatus() {
	mission := &Mission{
		Name:   "Update Test",
		Status: "pending",
		Mode:   "passive",
		Depth:  "quick",
	}
	s.repo.Create(mission)

	// Update
	err := s.repo.UpdateStatus(mission.ID, "running")
	s.NoError(err)

	// Verify
	found, _ := s.repo.GetByID(mission.ID)
	s.Equal("running", found.Status)
}

func TestMissionRepoTestSuite(t *testing.T) {
	suite.Run(t, new(MissionRepoTestSuite))
}

// Simple unit tests without DB
func TestMissionValidation(t *testing.T) {
	tests := []struct {
		name    string
		mission *Mission
		wantErr bool
	}{
		{
			name: "valid mission",
			mission: &Mission{
				Name:   "Test",
				Mode:   "passive",
				Depth:  "quick",
				Target: map[string]interface{}{"host": "test.com"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			mission: &Mission{
				Mode:  "passive",
				Depth: "quick",
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			mission: &Mission{
				Name:  "Test",
				Mode:  "invalid",
				Depth: "quick",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMission(tt.mission)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
