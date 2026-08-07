package app

import (
	"context"
	"fmt"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport"
)

// attachmentTypeID maps the config attachment_type string to the wire id
// (docs/attachment-protocol.md §G.1). The engine defines NGINX_ATT_ID (0)
// but no Caddy id, so "nginx" — the only supported value — maps to 0.
func attachmentTypeID(typ string) uint8 {
	if typ == "nginx" {
		return 0
	}
	return 0
}

// registrationFrame builds the phase-1 registration frame (§G.1):
// [attachment_type][worker_id+1][workers_amount][family_name_size][family_name].
// The nginx reference sends worker_id+1 (ngx_cp_initializer.c:569-750).
func registrationFrame(cfg config.EngineConfig) []byte {
	b := make([]byte, 0, 4+len(cfg.FamilyName))
	b = append(b, attachmentTypeID(cfg.AttachmentType))
	b = append(b, uint8(cfg.WorkerID+1))
	b = append(b, uint8(cfg.Workers))
	b = append(b, uint8(len(cfg.FamilyName)))
	b = append(b, cfg.FamilyName...)
	return b
}

// commFrame builds the phase-2 comm frame (§G.2):
// [uid_size][uid][nano_user_id u32][nano_group_id u32][target_core i32],
// little-endian ids. user and group ids are zero (the reference reads them
// from the process, which this attachment has no equivalent of). target_core
// is -1: paired affinity is disabled (ngx_cp_initializer.c:430,447). The uid
// is cfg.UniqueID() — the engine validates it against its own instance-aware
// unique id (instance_awareness.cc:48-58, family_instance) and closes the
// comm socket without an ack on mismatch (nginx_attachment.cc
// getUidFromSocket), so the plain family name is not enough.
func commFrame(cfg config.EngineConfig) []byte {
	return (protocol.CommData{
		UID:        cfg.UniqueID(),
		UserID:     0,
		GroupID:    0,
		TargetCore: -1,
	}).Encode()
}

// register runs phase 1 of the handshake over conn (docs/attachment-protocol.md
// §G.1): it sends the registration frame and reads back the verdict signal
// path the engine assigned. The registration socket is one-shot: the C
// reference closes it right after the reply (ngx_cp_initializer.c:747), so the
// caller must close conn once the path is returned. Phase 2 (sendComm) runs
// over a fresh connection to that path. This client is written once and shared
// by every dialer; only the underlying channel differs.
func register(ctx context.Context, conn transport.EngineConn, cfg config.EngineConfig) (string, error) {
	if err := conn.Send(ctx, registrationFrame(cfg)); err != nil {
		return "", fmt.Errorf("app: registration send: %w", err)
	}
	path, err := recvSignalPath(ctx, conn)
	if err != nil {
		return "", fmt.Errorf("app: registration reply: %w", err)
	}
	return path, nil
}

// sendComm runs phase 2 of the handshake over conn (§G.2): it sends the comm
// frame and reads a 1-byte ack. Unlike the registration socket, this conn
// stays open: the C reference keeps comm_socket open for the attachment's
// lifetime (isIpcReady requires comm_socket > 0, ngx_cp_initializer.c:1068).
func sendComm(ctx context.Context, conn transport.EngineConn, cfg config.EngineConfig) error {
	if err := conn.Send(ctx, commFrame(cfg)); err != nil {
		return fmt.Errorf("app: comm send: %w", err)
	}
	if err := recvAck(ctx, conn); err != nil {
		return fmt.Errorf("app: comm ack: %w", err)
	}
	return nil
}

// recvSignalPath reads the phase-1 reply: [path_length][path].
func recvSignalPath(ctx context.Context, conn transport.EngineConn) (string, error) {
	payload, err := conn.Recv(ctx)
	if err != nil {
		return "", err
	}
	if len(payload) < 1 {
		return "", fmt.Errorf("app: empty registration reply")
	}
	n := int(payload[0])
	if len(payload) < 1+n {
		return "", fmt.Errorf("app: truncated registration reply")
	}
	return string(payload[1 : 1+n]), nil
}

// recvAck reads the phase-2 1-byte ack.
func recvAck(ctx context.Context, conn transport.EngineConn) error {
	payload, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return fmt.Errorf("app: empty comm ack")
	}
	return nil
}
