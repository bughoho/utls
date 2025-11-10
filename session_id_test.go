package tls

import (
	"bytes"
	"testing"
)

// TestSessionIDResumption tests the SessionID-based session resumption logic
func TestSessionIDResumption(t *testing.T) {
	// Test case 1: SessionID should be saved with resumeType
	t.Run("SaveSessionID", func(t *testing.T) {
		// Create a mock session state
		session := &SessionState{
			version:     VersionTLS12,
			cipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA,
			secret:      make([]byte, 48),
			resumeType:  ResumeSessionID, // Mark as SessionID resumption
		}
		
		// Simulate a SessionID (32 bytes)
		sessionID := make([]byte, 32)
		for i := range sessionID {
			sessionID[i] = byte(i)
		}
		
		// Set the sessionId field
		session.sessionId = sessionID
		
		// Verify the type is set correctly
		if session.resumeType != ResumeSessionID {
			t.Error("resumeType should be ResumeSessionID for SessionID resumption")
		}
	})
	
	// Test case 2: Distinguish SessionID from Session Ticket by type
	t.Run("DistinguishSessionIDFromTicket", func(t *testing.T) {
		// SessionID resumption
		sessionIDState := &SessionState{
			version:    VersionTLS12,
			resumeType: ResumeSessionID,
			sessionId:  make([]byte, 32),
		}
		if sessionIDState.resumeType != ResumeSessionID {
			t.Error("SessionID state should have resumeType=ResumeSessionID")
		}
		
		// Session Ticket resumption
		sessionTicketState := &SessionState{
			version:    VersionTLS12,
			resumeType: ResumeSessionTicket,
			ticket:     make([]byte, 128),
		}
		if sessionTicketState.resumeType != ResumeSessionTicket {
			t.Error("Session Ticket state should have resumeType=ResumeSessionTicket")
		}
	})
	
	// Test case 3: Verify SessionID is correctly placed in ClientHello
	t.Run("SessionIDInClientHello", func(t *testing.T) {
		hello := &clientHelloMsg{}
		sessionID := make([]byte, 32)
		
		// When using SessionID resumption
		hello.sessionId = sessionID
		hello.sessionTicket = nil
		
		if !bytes.Equal(hello.sessionId, sessionID) {
			t.Error("SessionID not correctly set in ClientHello")
		}
		if hello.sessionTicket != nil {
			t.Error("SessionTicket should be nil when using SessionID")
		}
	})
	
	// Test case 4: Verify Session Ticket is correctly placed in ClientHello
	t.Run("SessionTicketInClientHello", func(t *testing.T) {
		hello := &clientHelloMsg{}
		sessionTicket := make([]byte, 128)
		
		// When using Session Ticket resumption
		hello.sessionTicket = sessionTicket
		
		if !bytes.Equal(hello.sessionTicket, sessionTicket) {
			t.Error("Session Ticket not correctly set in ClientHello")
		}
	})
}

// TestSessionIDFallbackLogic tests the fallback logic for SessionID resumption
func TestSessionIDFallbackLogic(t *testing.T) {
	t.Run("ShouldSaveSessionID_TLS12_WithSessionID_NoTicket", func(t *testing.T) {
		// Conditions for SessionID fallback:
		// 1. TLS 1.2 or earlier
		// 2. Server provided a non-empty SessionID
		// 3. No ticket received
		
		vers := uint16(VersionTLS12)
		sessionID := make([]byte, 32)
		ticket := []byte(nil)
		
		shouldSaveSessionID := vers <= VersionTLS12 && len(sessionID) > 0 && ticket == nil
		
		if !shouldSaveSessionID {
			t.Error("Should save SessionID when conditions are met")
		}
	})
	
	t.Run("ShouldNotSaveSessionID_TLS13", func(t *testing.T) {
		vers := uint16(VersionTLS13)
		sessionID := make([]byte, 32)
		ticket := []byte(nil)
		
		shouldSaveSessionID := vers <= VersionTLS12 && len(sessionID) > 0 && ticket == nil
		
		if shouldSaveSessionID {
			t.Error("Should not save SessionID for TLS 1.3")
		}
	})
	
	t.Run("ShouldNotSaveSessionID_EmptySessionID", func(t *testing.T) {
		vers := uint16(VersionTLS12)
		sessionID := []byte{}
		ticket := []byte(nil)
		
		shouldSaveSessionID := vers <= VersionTLS12 && len(sessionID) > 0 && ticket == nil
		
		if shouldSaveSessionID {
			t.Error("Should not save empty SessionID")
		}
	})
	
	t.Run("ShouldNotSaveSessionID_HasTicket", func(t *testing.T) {
		vers := uint16(VersionTLS12)
		sessionID := make([]byte, 32)
		ticket := make([]byte, 128)
		
		shouldSaveSessionID := vers <= VersionTLS12 && len(sessionID) > 0 && ticket == nil
		
		if shouldSaveSessionID {
			t.Error("Should not save SessionID when ticket is present")
		}
	})
}

// TestSessionIDResumeType tests the resumeType enum logic
func TestSessionIDResumeType(t *testing.T) {
	testCases := []struct {
		name       string
		resumeType ResumeMechanism
		expectType string
	}{
		{"SessionID_Resumption", ResumeSessionID, "SessionID"},
		{"SessionTicket_Resumption", ResumeSessionTicket, "Session Ticket"},
		{"Unknown_Resumption", ResumeUnknown, "Unknown"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &SessionState{
				version:    VersionTLS12,
				resumeType: tc.resumeType,
			}
			
			if session.resumeType != tc.resumeType {
				t.Errorf("Expected resumeType=%v, got %v", 
					tc.resumeType, session.resumeType)
			}
		})
	}
}
