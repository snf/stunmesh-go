package entity_test

import (
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/entity"
)

func TestPeerId_EndpointKey(t *testing.T) {
	devicePublicKey := []byte{0}
	peerPublicKey := []byte{1}

	peerId := entity.NewPeerId(devicePublicKey, peerPublicKey)
	endpointKey := peerId.EndpointKey()

	expected := "b3384f16283d28558bf8d231cdd8a22fbb4bb982"
	if endpointKey != expected {
		t.Errorf("Expected %s, got %s", expected, endpointKey)
	}
}

func TestPeerId_RemoteEndpointKey(t *testing.T) {
	devicePublicKey := []byte{0}
	peerPublicKey := []byte{1}

	peerId := entity.NewPeerId(devicePublicKey, peerPublicKey)
	remoteEndpointKey := peerId.RemoteEndpointKey()

	expected := "355e04c1ce320c35f6ca08590911e6bf8bffa850"
	if remoteEndpointKey != expected {
		t.Errorf("Expected %s, got %s", expected, remoteEndpointKey)
	}
}

func TestPeerId_Comparable(t *testing.T) {
	pid := entity.NewPeerId([]byte{0}, []byte{1})
	pid2 := entity.NewPeerId([]byte{0}, []byte{1})

	store := make(map[entity.PeerId]int)
	store[pid] = 1
	store[pid2] = 2

	if store[pid] != 2 {
		t.Errorf("Expected 2, got %d", store[pid])
	}
}
