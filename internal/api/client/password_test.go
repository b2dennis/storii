package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestSetPassword(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		data           models.SetPasswordC2S
		serverResponse string
		serverStatus   int
		expectError    bool
		expectedResult models.SetPasswordS2C
	}{
		{
			name:  "successful password set",
			token: "valid-token",
			data: models.SetPasswordC2S{
				Name:  "test-password",
				Value: "encrypted-value",
			},
			serverResponse: `{"data": {"newPassword": {"name": "test-password"}}}`,
			serverStatus:   201,
			expectError:    false,
			expectedResult: models.SetPasswordS2C{
				NewPassword: models.S2CPassword{Name: "test-password"},
			},
		},
		{
			name:           "server error",
			token:          "valid-token",
			serverStatus:   500,
			serverResponse: `{"error": "Internal server error"}`,
			expectError:    true,
		},
		{
			name:           "unauthorized",
			token:          "invalid-token",
			serverStatus:   401,
			serverResponse: `{"error": "Unauthorized"}`,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Contains(t, r.URL.Path, constants.PasswordRouteSet)

				if tt.token != "" {
					assert.Equal(t, "Bearer "+tt.token, r.Header.Get("Authorization"))
				}

				var requestData models.SetPasswordC2S
				err := json.NewDecoder(r.Body).Decode(&requestData)
				assert.NoError(t, err)
				assert.Equal(t, tt.data, requestData)

				w.WriteHeader(tt.serverStatus)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			config := models.ClientConfig{
				Remote: server.URL,
				Token:  tt.token,
			}

			result, err := SetPassword(config, tt.data)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
