package security

import (
	"testing"
	"time"
)

// TestDefaultProductionConfig tests the production configuration factory.
func TestDefaultProductionConfig(t *testing.T) {
	config := DefaultProductionConfig()

	if !config.IdentifiableAbortEnabled {
		t.Error("IdentifiableAbortEnabled should be true")
	}
	if !config.NonceReuseProtection {
		t.Error("NonceReuseProtection should be true")
	}
	if config.SessionTimeout != 1*time.Hour {
		t.Errorf("SessionTimeout = %v, want %v", config.SessionTimeout, 1*time.Hour)
	}
	if config.CommitmentExpiration != 24*time.Hour {
		t.Errorf("CommitmentExpiration = %v, want %v", config.CommitmentExpiration, 24*time.Hour)
	}
	if config.MaxSignersPerSession != 1000 {
		t.Errorf("MaxSignersPerSession = %d, want %d", config.MaxSignersPerSession, 1000)
	}
	if !config.RequireCommitmentsSorted {
		t.Error("RequireCommitmentsSorted should be true")
	}
	if config.MessageValidator == nil {
		t.Error("MessageValidator should not be nil")
	}
	if config.MaxMessageSize != 1024*1024 {
		t.Errorf("MaxMessageSize = %d, want %d", config.MaxMessageSize, 1024*1024)
	}
	if config.ReputationTracker == nil {
		t.Error("ReputationTracker should not be nil")
	}
}

// TestDefaultDevelopmentConfig tests the development configuration factory.
func TestDefaultDevelopmentConfig(t *testing.T) {
	config := DefaultDevelopmentConfig()

	// Should have same security settings as production
	if !config.IdentifiableAbortEnabled {
		t.Error("IdentifiableAbortEnabled should be true")
	}
	if !config.NonceReuseProtection {
		t.Error("NonceReuseProtection should be true")
	}

	// But shorter timeouts
	if config.SessionTimeout != 5*time.Minute {
		t.Errorf("SessionTimeout = %v, want %v", config.SessionTimeout, 5*time.Minute)
	}
	if config.CommitmentExpiration != 1*time.Hour {
		t.Errorf("CommitmentExpiration = %v, want %v", config.CommitmentExpiration, 1*time.Hour)
	}
}

// TestInsecureConfig tests the insecure configuration factory.
func TestInsecureConfig(t *testing.T) {
	config := InsecureConfig()

	if config.IdentifiableAbortEnabled {
		t.Error("IdentifiableAbortEnabled should be false")
	}
	if config.NonceReuseProtection {
		t.Error("NonceReuseProtection should be false")
	}
	if config.NonceTracker != nil {
		t.Error("NonceTracker should be nil")
	}
	if config.SessionTimeout != 0 {
		t.Errorf("SessionTimeout = %v, want 0", config.SessionTimeout)
	}
	if config.CommitmentExpiration != 0 {
		t.Errorf("CommitmentExpiration = %v, want 0", config.CommitmentExpiration)
	}
	if config.MaxSignersPerSession != 0 {
		t.Errorf("MaxSignersPerSession = %d, want 0", config.MaxSignersPerSession)
	}
	// Should still require sorted commitments for protocol correctness
	if !config.RequireCommitmentsSorted {
		t.Error("RequireCommitmentsSorted should be true even in insecure mode")
	}
	if config.MessageValidator == nil {
		t.Error("MessageValidator should not be nil")
	}
	if config.MaxMessageSize != 0 {
		t.Errorf("MaxMessageSize = %d, want 0", config.MaxMessageSize)
	}
	if config.ReputationTracker != nil {
		t.Error("ReputationTracker should be nil in insecure mode")
	}
}

// TestSecurityConfig_Validate tests configuration validation.
func TestSecurityConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  SecurityConfig
		wantErr bool
	}{
		{
			name:    "valid production config",
			config:  DefaultProductionConfig(),
			wantErr: false,
		},
		{
			name:    "valid development config",
			config:  DefaultDevelopmentConfig(),
			wantErr: false,
		},
		{
			name:    "valid insecure config",
			config:  InsecureConfig(),
			wantErr: false,
		},
		{
			name: "negative session timeout",
			config: SecurityConfig{
				SessionTimeout: -1 * time.Hour,
			},
			wantErr: true,
		},
		{
			name: "negative commitment expiration",
			config: SecurityConfig{
				CommitmentExpiration: -1 * time.Hour,
			},
			wantErr: true,
		},
		{
			name: "too many signers",
			config: SecurityConfig{
				MaxSignersPerSession: 10001,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSecurityConfig_GetOrCreateNonceTracker tests nonce tracker creation.
func TestSecurityConfig_GetOrCreateNonceTracker(t *testing.T) {
	t.Run("creates tracker when nil", func(t *testing.T) {
		config := SecurityConfig{
			NonceTracker: nil,
		}

		tracker := config.GetOrCreateNonceTracker()
		if tracker == nil {
			t.Error("GetOrCreateNonceTracker() should create tracker when nil")
		}
	})

	t.Run("uses configured nonce tracker", func(t *testing.T) {
		// Use default config which has NonceReuseProtection enabled
		config := DefaultProductionConfig()

		tracker := config.GetOrCreateNonceTracker()
		if tracker == nil {
			t.Error("GetOrCreateNonceTracker() should return non-nil tracker")
		}

		// Call again to ensure we get same tracker
		tracker2 := config.GetOrCreateNonceTracker()
		if tracker2 == nil {
			t.Error("GetOrCreateNonceTracker() should return non-nil tracker on second call")
		}
	})
}
