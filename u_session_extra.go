package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SessionExtraFieldID defines the unique identifier for extension fields
type SessionExtraFieldID uint16

const (
	// SessionExtraUTLSData is the field ID for uTLS session data (resumeType + sessionId)
	SessionExtraUTLSData SessionExtraFieldID = 0x7001
)

// SessionExtraVersion is the version number for extension fields
const SessionExtraVersion uint8 = 0x01

// UTLSSessionData encapsulates uTLS-specific session resumption data
type UTLSSessionData struct {
	ResumeType ResumeMechanism
	SessionID  []byte
}

// SessionExtraField represents an extension field
type SessionExtraField struct {
	ID      SessionExtraFieldID
	Version uint8
	Data    []byte
}

// marshalUTLSSessionData serializes UTLSSessionData to bytes.
// Format:
//
//	uint8 resume_type
//	uint16 session_id_length
//	opaque session_id<0..2^16-1>
func marshalUTLSSessionData(data *UTLSSessionData) []byte {
	if data == nil || (data.ResumeType == ResumeUnknown && len(data.SessionID) == 0) {
		return nil
	}

	// calculate length: resume_type(1) + session_id_length(2) + session_id
	totalLen := 1 + 2 + len(data.SessionID)
	result := make([]byte, totalLen)
	offset := 0

	// write resume type
	result[offset] = uint8(data.ResumeType)
	offset++

	// write session ID length
	binary.BigEndian.PutUint16(result[offset:], uint16(len(data.SessionID)))
	offset += 2

	// write session ID
	if len(data.SessionID) > 0 {
		copy(result[offset:], data.SessionID)
	}

	return result
}

// unmarshalUTLSSessionData deserializes UTLSSessionData from bytes
func unmarshalUTLSSessionData(data []byte) (*UTLSSessionData, error) {
	if len(data) < 3 {
		return nil, errors.New("invalid UTLS session data: too short")
	}

	offset := 0

	// read resume type
	resumeType := ResumeMechanism(data[offset])
	offset++

	// read session ID length
	sessionIDLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// check data length
	if offset+int(sessionIDLen) > len(data) {
		return nil, errors.New("invalid UTLS session data: session ID incomplete")
	}

	// read session ID
	var sessionID []byte
	if sessionIDLen > 0 {
		sessionID = make([]byte, sessionIDLen)
		copy(sessionID, data[offset:offset+int(sessionIDLen)])
	}

	return &UTLSSessionData{
		ResumeType: resumeType,
		SessionID:  sessionID,
	}, nil
}

// marshalSessionExtra serializes extension data to the Extra field.
// Format:
//
//	uint8 version
//	uint16 field_count
//	SessionExtraField fields<0..2^16-1>
//
// SessionExtraField:
//
//	uint16 field_id
//	uint8 field_version
//	uint16 data_length
//	opaque data<0..2^16-1>
func marshalSessionExtra(data *UTLSSessionData) []byte {
	if data == nil || (data.ResumeType == ResumeUnknown && len(data.SessionID) == 0) {
		return nil // no extension data
	}

	// marshal UTLS data
	utlsDataBytes := marshalUTLSSessionData(data)
	if utlsDataBytes == nil {
		return nil
	}

	// create single field with UTLS data
	field := SessionExtraField{
		ID:      SessionExtraUTLSData,
		Version: SessionExtraVersion,
		Data:    utlsDataBytes,
	}

	// calculate total length: version(1) + field_count(2) + field
	totalLen := 1 + 2 + 2 + 1 + 2 + len(field.Data) // version + count + id + version + length + data

	result := make([]byte, totalLen)
	offset := 0

	// write version number
	result[offset] = SessionExtraVersion
	offset++

	// write field count (always 1)
	binary.BigEndian.PutUint16(result[offset:], 1)
	offset += 2

	// write field ID
	binary.BigEndian.PutUint16(result[offset:], uint16(field.ID))
	offset += 2

	// write field version
	result[offset] = field.Version
	offset++

	// write data length
	binary.BigEndian.PutUint16(result[offset:], uint16(len(field.Data)))
	offset += 2

	// write data content
	copy(result[offset:], field.Data)

	return result
}

// unmarshalSessionExtra deserializes extension data from the Extra field
func unmarshalSessionExtra(extraData []byte) (*UTLSSessionData, error) {
	if len(extraData) == 0 {
		return nil, nil // no extension data
	}

	if len(extraData) < 3 {
		return nil, errors.New("invalid extra data: too short")
	}

	offset := 0

	// read version number
	version := extraData[offset]
	offset++

	if version != SessionExtraVersion {
		// version mismatch, might be future version or other data, ignore
		return nil, nil
	}

	// read field count
	if offset+2 > len(extraData) {
		return nil, errors.New("invalid extra data: cannot read field count")
	}
	fieldCount := binary.BigEndian.Uint16(extraData[offset:])
	offset += 2

	// read each field
	for i := uint16(0); i < fieldCount; i++ {
		if offset+5 > len(extraData) { // id(2) + version(1) + length(2)
			return nil, fmt.Errorf("invalid extra data: field %d header incomplete", i)
		}

		// read field ID
		fieldID := SessionExtraFieldID(binary.BigEndian.Uint16(extraData[offset:]))
		offset += 2

		// read field version
		fieldVersion := extraData[offset]
		offset++

		// read data length
		dataLength := binary.BigEndian.Uint16(extraData[offset:])
		offset += 2

		// check data length
		if offset+int(dataLength) > len(extraData) {
			return nil, fmt.Errorf("invalid extra data: field %d data incomplete", i)
		}

		// read data
		fieldData := extraData[offset : offset+int(dataLength)]
		offset += int(dataLength)

		// handle known fields
		if fieldVersion == SessionExtraVersion {
			switch fieldID {
			case SessionExtraUTLSData:
				// unmarshal UTLS session data
				return unmarshalUTLSSessionData(fieldData)
			}
			// ignore unknown field IDs for forward compatibility
		}
		// ignore fields with unknown versions for backward compatibility
	}

	return nil, nil
}

// HasSessionExtra checks if SessionState contains extension data
func HasSessionExtra(s *SessionState) bool {
	if len(s.Extra) == 0 {
		return false
	}

	// find our extension data: iterate through all Extra entries to find ones starting with our version
	for _, extraItem := range s.Extra {
		if len(extraItem) >= 1 && extraItem[0] == SessionExtraVersion {
			return true
		}
	}

	return false
}

// GetSessionExtraFields retrieves extension fields from SessionState
func GetSessionExtraFields(s *SessionState) *UTLSSessionData {
	if !HasSessionExtra(s) {
		return nil
	}

	// find our extension data
	for _, extraItem := range s.Extra {
		if len(extraItem) >= 1 && extraItem[0] == SessionExtraVersion {
			utlsData, err := unmarshalSessionExtra(extraItem)
			if err != nil {
				// parsing failed, continue to next item
				continue
			}
			return utlsData
		}
	}

	return nil
}

// SetSessionExtraFields sets extension fields in SessionState
func SetSessionExtraFields(s *SessionState, data *UTLSSessionData) {
	extraData := marshalSessionExtra(data)
	if extraData == nil {
		// no data to save, clear existing extension data
		ClearSessionExtraFields(s)
		return
	}

	// remove existing extension data (if any)
	ClearSessionExtraFields(s)

	// add new extension data
	s.Extra = append(s.Extra, extraData)
}

// ClearSessionExtraFields clears extension fields from SessionState
func ClearSessionExtraFields(s *SessionState) {
	// remove all extension data starting with our version number
	var newExtra [][]byte
	for _, extraItem := range s.Extra {
		if len(extraItem) == 0 || extraItem[0] != SessionExtraVersion {
			// keep extension data that is not ours
			newExtra = append(newExtra, extraItem)
		}
	}
	s.Extra = newExtra
}
