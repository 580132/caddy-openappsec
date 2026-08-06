package app

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/yourname/caddy-openappsec/internal/config"
	"github.com/yourname/caddy-openappsec/internal/transport"
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
// [uid_size][uid][nano_user_id u32][nano_group_id u32], little-endian ids.
// The family name stands in for the nano library's container id; user and
// group ids are zero (the reference reads them from the process, which this
// attachment has no equivalent of).
func commFrame(cfg config.EngineConfig) []byte {
	uid := cfg.FamilyName
	b := make([]byte, 0, 1+len(uid)+8)
	b = append(b, uint8(len(uid)))
	b = append(b, uid...)
	b = binary.LittleEndian.AppendUint32(b, 0) // nano_user_id
	b = binary.LittleEndian.AppendUint32(b, 0) // nano_group_id
	return b
}

// handshake runs the two-phase registration over conn (docs/attachment-protocol.md
// §G.1, §G.2). Phase 1 sends the registration frame and reads back the verdict
// signal path; phase 2 sends the comm frame and reads a 1-byte ack. It returns
// the verdict signal path the engine assigned. This client is written once and
// shared by every dialer; only the underlying channel differs.
func handshake(ctx context.Context, conn transport.EngineConn, cfg config.EngineConfig) (string, error) {
	if err := conn.Send(ctx, registrationFrame(cfg)); err != nil {
		return "", fmt.Errorf("app: registration send: %w", err)
	}
	path, err := recvSignalPath(ctx, conn)
	if err != nil {
		return "", fmt.Errorf("app: registration reply: %w", err)
	}
	if err := conn.Send(ctx, commFrame(cfg)); err != nil {
		return "", fmt.Errorf("app: comm send: %w", err)
	}
	if err := recvAck(ctx, conn); err != nil {
		return "", fmt.Errorf("app: comm ack: %w", err)
	}
	return path, nil
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
