package cloud

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"os"
	"sync"
	"testing"
)

func TestRevocationRequestResponseCloud_ToLog(t *testing.T) {
	t.Run("SUBMITTED", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "SUBMITTED",
			ID:         "myId",
			Thumbprint: "myThumbprint",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.NoError(t, err)
		assert.Contains(t, output, fmt.Sprintf(RevocationSubmittedFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint))
	})
	t.Run("FAILED", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "FAILED",
			ID:         "myId",
			Thumbprint: "myThumbprint",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.Empty(t, output)
		assert.NotNil(t, err)
		assert.EqualError(t, err, fmt.Errorf(RevocationFailedFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint).Error())
	})
	t.Run("FAILED with error", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "FAILED",
			ID:         "myId",
			Thumbprint: "myThumbprint",
			Error:      errors.New("some error"),
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.Empty(t, output)
		assert.NotNil(t, err)
		assert.EqualError(t, err, fmt.Errorf(RevocationFailedWithErrorFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint, revocationResponse.Error).Error())
	})
	t.Run("PENDING_APPROVAL", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "PENDING_APPROVAL",
			ID:         "myId",
			Thumbprint: "myThumbprint",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.NoError(t, err)
		assert.Contains(t, output, fmt.Sprintf(RevocationApprovalPendingFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint))
	})
	t.Run("PENDING_FINAL_APPROVAL", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "PENDING_FINAL_APPROVAL",
			ID:         "myId",
			Thumbprint: "myThumbprint",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.NoError(t, err)
		assert.Contains(t, output, fmt.Sprintf(RevocationApprovalPendingFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint))
	})
	t.Run("REJECTED_APPROVAL", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:     "REJECTED_APPROVAL",
			ID:         "myId",
			Thumbprint: "myThumbprint",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.NoError(t, err)
		assert.Contains(t, output, fmt.Sprintf(RevocationRejectedFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint))
	})
	t.Run("REJECTED_APPROVAL with reason", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			Status:          "REJECTED_APPROVAL",
			ID:              "myId",
			Thumbprint:      "myThumbprint",
			RejectionReason: "some reason",
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.NoError(t, err)
		assert.Contains(t, output, fmt.Sprintf(RevocationRejectedWithReasonFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint, revocationResponse.RejectionReason))
	})
	t.Run("no status", func(t *testing.T) {
		revocationResponse := &RevocationRequestResponseCloud{
			ID:         "myId",
			Thumbprint: "myThumbprint",
			Error:      errors.New("some error"),
		}

		output, err := getOutputFromToLog(revocationResponse)
		assert.Empty(t, output)
		assert.NotNil(t, err)
		assert.EqualError(t, err, fmt.Errorf(RevocationFailedWithErrorFormattedMessage, revocationResponse.ID, revocationResponse.Thumbprint, revocationResponse.Error).Error())
	})
}

func getOutputFromToLog(rev *RevocationRequestResponseCloud) (string, error) {
	// 1. Redirect os.Stdout
	origStderr := os.Stderr
	reader, writer, _ := os.Pipe()
	os.Stderr = writer
	log.SetOutput(writer)

	outputChan := make(chan string)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var buf bytes.Buffer
		wg.Done()
		_, _ = io.Copy(&buf, reader)
		outputChan <- buf.String()
	}()
	wg.Wait()

	// 2. Execute the code under test
	err := rev.ToLog(log.Default())

	// 3. Restore os.Stdout
	_ = writer.Close()
	os.Stderr = origStderr
	return <-outputChan, err
}
