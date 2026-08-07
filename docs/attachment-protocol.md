# openappsec Attachment Wire Protocol

Decision-complete, byte-level contract for implementing a Caddy HTTP attachment that
interoperates with the openappsec nano service. Every claim is self-checked against the
pinned source tree (SHA `2f46293b32c58d5be250aa6d3bac0e4ba9260738`, local clone at
`C:\Users\MSI-NB\AppData\Local\Temp\opencode\attachment-src`).

Status legend:
- `RESOLVED` — confirmed against source, cite `path:line`.
- `[INFERRED]` — derived from surrounding code; reason given. Must be re-verified before shipping.

---

## A. Scope & Source of Truth

| Item | Value |
|---|---|
| Repo | `github.com/openappsec/attachment` |
| Pinned SHA | `2f46293b77` (detached HEAD verified) |
| Reference attachment | `attachments/nginx/ngx_module/*` (C) |
| Reference library | `attachments/nano_attachment/*` (C) |
| Shared headers | `core/include/attachments/*.h` |
| Shmem core | `core/shmem_ipc_2/*` |

The Caddy attachment must mirror the **nginx attachment** behavior (it is the canonical
sender). The `nano_attachment` library is the reference for the *receiver* side of verdicts
and for the registration/comm handshake.

---

## B. Constants (RESOLVED)

From `core/include/attachments/nano_attachment_common.h`:

| Constant | Value | Line |
|---|---|---|
| `MAX_NGINX_UID_LEN` | 32 | 21 |
| `MAX_SHARED_MEM_PATH_LEN` | 128 | 22 |
| `NUM_OF_NGINX_IPC_ELEMENTS` | 200 | 23 |
| `NUM_OF_NGINX_IPC_ELEMENTS_ASYNC` | 2000 | 25 |
| `DEFAULT_KEEP_ALIVE_INTERVAL_MSEC` | 300000 | 26 |
| `SHARED_MEM_PATH` | `/dev/shm/` | 27 |
| `SHARED_REGISTRATION_SIGNAL_PATH` | `/dev/shm/check-point/cp-nano-attachment-registration` | 28 |
| `SHARED_KEEP_ALIVE_PATH` | `/dev/shm/check-point/cp-nano-attachment-registration-expiration-socket` | 29 |
| `SHARED_VERDICT_SIGNAL_PATH` | `/dev/shm/check-point/cp-nano-http-transaction-handler` | 30 |
| `SHARED_ATTACHMENT_CONF_PATH` | `/dev/shm/cp_nano_http_attachment_conf` | 31 |
| `DEFAULT_STATIC_RESOURCES_PATH` | `/dev/shm/static_resources` | 32 |
| `INJECT_POS_IRRELEVANT` | -1 | 33 |
| `CORRUPTED_SESSION_ID` | 0 | 34 |
| `METRIC_PERIODIC_TIMEOUT` | 600 | 35 |
| `MAX_CONTAINER_ID_LEN` | 12 | 36 |
| `CONTAINER_ID_FILE_PATH` | `/proc/self/cgroup` | 37 |
| `RESPONSE_PAGE_PARTS` | 4 | 38 |
| `UUID_SIZE` | 64 | 39 |
| `CUSTOM_RESPONSE_TITLE_SIZE` | 64 | 40 |
| `CUSTOM_RESPONSE_BODY_SIZE` | 128 | 41 |
| `REDIRECT_RESPONSE_LOCATION_SIZE` | 512 | 42 |

From `core/shmem_ipc_2/shared_ring_queue.h`:

| Constant | Value | Line |
|---|---|---|
| `SHARED_MEMORY_SEGMENT_ENTRY_SIZE` | 4096 | 26 |
| `SHARED_MEMORY_SEGMENT_ENTRY_SIZE_BC` | 1024 | 27 |
| `MAX_ONE_WAY_QUEUE_NAME_LENGTH` | 64 | 28 |
| `CORRUPTED_SHMEM_ERROR` | -2 | 29 |

From `attachments/nano_attachment/nano_attachment_io.c`:

| Constant | Value | Line |
|---|---|---|
| `MAX_HEADER_BULK_SIZE` | 10 | 16 |
| `RESPONSE_CODE_COUNT` | 3 | 17 |
| `CONTENT_LENGTH_COUNT` | 3 | 18 |
| `HEADER_DATA_COUNT` | 4 | 19 |
| `BODY_DATA_COUNT` | 5 | 20 |
| `END_TRANSACTION_DATA_COUNT` | 2 | 21 |
| `DELAYED_VERDICT_DATA_COUNT` | 2 | 22 |

---

## C. Enums (RESOLVED)

### C.1 `AttachmentDataType` — `nano_attachment_common.h:176-190`
```
REQUEST_START            = 0
REQUEST_HEADER           = 1
REQUEST_BODY             = 2
REQUEST_END              = 3
RESPONSE_CODE            = 4
RESPONSE_HEADER          = 5
RESPONSE_BODY            = 6
RESPONSE_END             = 7
CONTENT_LENGTH           = 8
METRIC_DATA_FROM_PLUGIN  = 9
REQUEST_DELAYED_VERDICT  = 10
COUNT                    = 11
```

### C.2 `HttpChunkType` — `nano_attachment_common.h:192-207`
```c
HTTP_REQUEST_FILTER   = 0
HTTP_REQUEST_METADATA = 1
HTTP_REQUEST_HEADER   = 2
HTTP_REQUEST_BODY     = 3
HTTP_REQUEST_END      = 4
HTTP_RESPONSE_HEADER  = 5
HTTP_RESPONSE_BODY    = 6
HTTP_RESPONSE_END     = 7
HOLD_DATA             = 8
```

### C.3 `ServiceVerdict` — `nano_attachment_common.h:209-224`
```c
TRAFFIC_VERDICT_INSPECT         = 0
TRAFFIC_VERDICT_ACCEPT          = 1
TRAFFIC_VERDICT_DROP            = 2
TRAFFIC_VERDICT_INJECT          = 3
TRAFFIC_VERDICT_IRRELEVANT      = 4
TRAFFIC_VERDICT_RECONF          = 5
TRAFFIC_VERDICT_DELAYED         = 6
LIMIT_RESPONSE_HEADERS          = 7
TRAFFIC_VERDICT_CUSTOM_RESPONSE = 8
```

### C.4 `AttachmentVerdict` — `nano_attachment_common.h:226-237`
```c
ATTACHMENT_VERDICT_INSPECT = 0
ATTACHMENT_VERDICT_ACCEPT  = 1
ATTACHMENT_VERDICT_DROP    = 2
ATTACHMENT_VERDICT_INJECT  = 3
ATTACHMENT_VERDICT_DELAYED = 4
```

### C.5 `HttpModificationType` — `nano_attachment_common.h:239-248`
```c
APPEND  = 0
INJECT  = 1
REPLACE = 2
```

### C.6 `HttpMetaDataType` — `nano_attachment_common.h:325-353`
```c
HTTP_PROTOCOL_SIZE   = 0
HTTP_PROTOCOL_DATA   = 1
HTTP_METHOD_SIZE     = 2
HTTP_METHOD_DATA     = 3
HOST_NAME_SIZE       = 4
HOST_NAME_DATA       = 5
LISTENING_ADDR_SIZE  = 6
LISTENING_ADDR_DATA  = 7
LISTENING_PORT       = 8
URI_SIZE             = 9
URI_DATA             = 10
CLIENT_ADDR_SIZE     = 11
CLIENT_ADDR_DATA     = 12
CLIENT_PORT          = 13
PARSED_HOST_SIZE     = 14
PARSED_HOST_DATA     = 15
PARSED_URI_SIZE      = 16
PARSED_URI_DATA      = 17
WAF_TAG_SIZE         = 18
WAF_TAG_DATA         = 19
META_DATA_COUNT      = 20
```

### C.7 `HttpHeaderDataType` — `nano_attachment_common.h:355-367`
```c
HEADER_KEY_SIZE = 0
HEADER_KEY_DATA = 1
HEADER_VAL_SIZE = 2
HEADER_VAL_DATA = 3
HEADER_DATA_COUNT = 4
```

### C.8 `NanoWebResponseType` — `nano_attachment_common.h:44-57`
```c
CUSTOM_WEB_RESPONSE           = 0
CUSTOM_WEB_BLOCK_PAGE_RESPONSE= 1
RESPONSE_CODE_ONLY            = 2
REDIRECT_WEB_RESPONSE         = 3
CUSTOM_RESPONSE_WITH_HEADERS  = 4
NO_WEB_RESPONSE               = 5
```

### C.9 `NanoHttpInspectionMode` — `nano_attachment_common.h:59-70`
```c
NON_BLOCKING_THREAD = 0
BLOCKING_THREAD     = 1
NO_THREAD           = 2
INSPECTION_MODE_COUNT = 3
```

### C.10 `NanoCommunicationResult` — `nano_attachment_common.h:72-85`
```c
NANO_OK            = 0
NANO_ERROR         = 1
NANO_ABORT         = 2
NANO_AGAIN         = 3
NANO_HTTP_FORBIDDEN= 4
NANO_DECLINED      = 5
NANO_TIMEOUT       = 6
```

### C.11 `CompressionType` — `core/include/attachments/compression_utils.h:41-48`
```c
NO_COMPRESSION      = 0
GZIP                = 1
ZLIB                = 2
BROTLI              = 3
UNKNOWN_COMPRESSION = NO_COMPRESSION  // 0
```

---

## D. Shared-Memory Ring Queue

### D.1 Queue naming — `core/shmem_ipc_2/shmem_ipc.c:108`
```
queue_name = "__cp_nano_%s_shared_memory_%s__"
```
- `%s` #1 = direction: `"rx"` or `"tx"` (derived from `isTowardsOwner(is_owner, is_tx_queue)`).
- `%s` #2 = the attachment's unique id (the `name` argument to `initIpc`). The
  service passes `inst_awareness->getUniqueID()` = `<family>_<instance>`
  (`nginx_attachment.cc:537-538`), and the nginx attachment passes its
  `unique_id` (`ngx_cp_initializer.c:886-887,999`) — the same string sent in
  the phase-2 comm frame (§G.2). This module therefore derives the name from
  `config.EngineConfig.UniqueID()` (`internal/transport/linux/ring_linux.go`),
  never the bare family name.
- Shmem file path: `/dev/shm/<queue_name>` (`shmem_ipc.c:137`).
- Owner `chmod`s the file to `0666` (`shmem_ipc.c:142`).

Each attachment creates **two** one-way queues: `rx_queue` (reads verdicts) and `tx_queue`
(writes requests). The service opens the same two files with opposite owner/tx flags.

### D.2 `SharedRingQueue` struct — `shared_ring_queue.h:50-60` (packed)
```c
typedef struct __attribute__((__packed__)) SharedRingQueue {
    char     shared_location_name[64];  // offset 0
    int32_t  owner_fd;                  // offset 64
    int32_t  user_fd;                   // offset 68
    int32_t  size_of_memory;            // offset 72
    uint16_t write_pos;                 // offset 76
    uint16_t read_pos;                  // offset 78
    uint16_t num_of_data_segments;      // offset 80
    DataSegment mgmt_segment;           // offset 82 (4096 bytes)
    DataSegment data_segment[0];        // offset 4178
} SharedRingQueue;
```
`DataSegment { char data[4096]; }` (`shared_ring_queue.h:42-44`).
`DataSegmentBC { char data[1024]; }` (`shared_ring_queue.h:46-48`).

### D.3 Management segment semantics — `shared_ring_queue.c:29-33`
`mgmt_segment.data` is treated as a `uint16_t` array indexed by data-segment index. Each
entry holds the **size of the message** stored starting at that segment, or a magic:
```c
empty_buff_mgmt_magic = 0xfffe   // segment is free
skip_buff_mgmt_magic  = 0xfffd   // segment is a continuation of previous message
max_write_size        = 0xfffc   // upper bound on a single message size
```
`max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t) = 2048` (`shared_ring_queue.c:34`).

### D.4 Ring operations
- `pushBuffersToQueue` (`shared_ring_queue.c:500-618`): concatenates `num_of_input_buffers`
  buffers into one logical message spanning consecutive segments. Computes total size,
  checks `max_write_size` (returns `-2` if exceeded), checks free space (returns `-3`),
  writes `mgmt[write_pos] = total_size`, copies buffers, marks continuation segments with
  `skip_buff_mgmt_magic`.
- `peekToQueue` (`shared_ring_queue.c:433-498`): reads `mgmt[read_pos]`; if `empty` magic
  returns empty; if `skip` magic advances; else returns pointer to the message.
- `popFromQueue` (`shared_ring_queue.c:633-695`): frees the message's segments by writing
  `empty_buff_mgmt_magic`.
- `isLargerDataSegmentSupported()` (`shared_ring_queue.c:40`): true if env
  `EFFECTIVE_SHM_SEGMENT_SIZE` > 1024; `g_effective_segment_size` = 4096 or 1024
  (`shared_ring_queue.c:93`).

---

## E. Message Framing (Wire Format)

### E.1 Fragment identifiers — `ngx_cp_io.c:838-847`
Every message begins with two fixed fragments:
```c
fragment[0] = data_type      (uint16_t)   // AttachmentDataType
fragment[1] = cur_request_id (uint32_t)   // session_id
```
`set_fragment_elem` (`ngx_cp_io.c:823-828`) just records `(ptr, size)`; the actual bytes are
concatenated in order into the ring queue message.

### E.2 REQUEST_START (metadata) — `ngx_cp_io.c:867-1028`
`META_DATA_COUNT + 2 = 22` fragments. Layout (index → content):
```
[0]  uint16_t data_type = REQUEST_START (0)
[1]  uint32_t session_id
[2]  uint16_t http_protocol.len
[3]  http_protocol.data (len bytes)
[4]  uint16_t method_name.len
[5]  method_name.data
[6]  uint16_t host.len
[7]  host.data
[8]  uint16_t listening_ip.len
[9]  listening_ip.data
[10] uint16_t listening_port
[11] uint16_t unparsed_uri.len
[12] unparsed_uri.data
[13] uint16_t client_ip.len
[14] client_ip.data
[15] uint16_t client_port
[16] uint16_t parsed_host.len
[17] parsed_host.data
[18] uint16_t parsed_uri.len
[19] parsed_uri.data
[20] uint16_t waf_tag.len
[21] waf_tag.data
```
Notes:
- `listening_port` and `client_port` are sent via `htons()` (`ngx_cp_io.c:970,983`) — **network
  byte order**. `[INFERRED]` the intaker expects network order for these two fields.
- `parsed_host` = nginx `$host` variable (falls back to `Host` header) (`ngx_cp_io.c:929-936`).
- `parsed_uri` = `request->uri` if non-empty else `unparsed_uri` (`ngx_cp_io.c:938-944`).
- `waf_tag` empty → sends `len=0` + empty data (`ngx_cp_io.c:998-1002`).

### E.3 REQUEST_END / RESPONSE_END — `ngx_cp_io.c:1030-1059`
`END_TRANSACTION_DATA_COUNT = 2` fragments:
```
0: uint16_t data_type (REQUEST_END=3 | RESPONSE_END=7)
1: uint32_t session_id
```

### E.4 REQUEST_DELAYED_VERDICT — `ngx_cp_io.c:1061-1083`
`DELAYED_VERDICT_DATA_COUNT = 2` fragments:
```
0: uint16_t data_type = REQUEST_DELAYED_VERDICT (10)
1: uint32_t session_id
```

### E.5 RESPONSE_CODE — `ngx_cp_io.c:1085-1106`
`RESPONSE_CODE_COUNT = 3` fragments:
```
0: uint16_t data_type = RESPONSE_CODE (4)
1: uint32_t session_id
2: uint16_t response_code
```

### E.6 CONTENT_LENGTH — `ngx_cp_io.c:1108-1130`
`CONTENT_LENGTH_COUNT = 3` fragments:
```
0: uint16_t data_type = CONTENT_LENGTH (8)
1: uint32_t session_id
2: uint64_t content_length
```

### E.7 HEADER bulk — `ngx_cp_io.c:1139-1310`, `nano_attachment_io.c:1733-1819`
`HEADER_DATA_COUNT * num_headers + 4` fragments:
```
0: uint16_t data_type = REQUEST_HEADER (1) | RESPONSE_HEADER (5)
1: uint32_t session_id
2: uint8_t  is_last_part
3: uint8_t  bulk_part_index
then per header i (pos = i*4 + 4):
  pos+0: uint16_t key.len
  pos+1: key.data
  pos+2: uint16_t value.len
  pos+3: value.data
```
- `MAX_HEADER_BULK_SIZE = 10` headers per bulk (`nano_attachment_io.c:16`).
- Empty response header list → sends one bulk with a single empty header
  (`ngx_cp_io.c:1199-1221`).

### E.8 BODY — `ngx_cp_io.c:1312-1429`, `nano_attachment_io.c:1918-2005`
`BODY_DATA_COUNT = 5` fragments:
```
0: uint16_t data_type = REQUEST_BODY (2) | RESPONSE_BODY (6)
1: uint32_t session_id
2: uint8_t  is_last_chunk
3: uint8_t  part_count
4: body data (buf->last - buf->pos bytes)
```
- `part_count` for RESPONSE_BODY is the running part number; for REQUEST_BODY it is 0
  (`ngx_cp_io.c:1353`).
- nginx processes at most 1 response-body chunk per call (`max_chunks_to_process`,
  `ngx_cp_io.c:1338`).

### E.9 METRIC — `ngx_cp_io.c:1431-1451`
Single fragment = `NanoHttpMetricData`:
```
0: uint16_t data_type = METRIC_DATA_FROM_PLUGIN (9)
8: uint64_t data[METRIC_TYPES_COUNT]
```
`METRIC_TYPES_COUNT` = number of `AttachmentMetricType` entries
(`nano_attachment_common.h:104-169`). Sent with `session_id = 0`.

---

## F. Verdict Reply (service → attachment)

### F.1 `HttpReplyFromService` — `nano_attachment_common.h:470-475` (packed)
```c
typedef struct __attribute__((__packed__)) HttpReplyFromService {
    uint16_t verdict;              // offset 0  (ServiceVerdict)
    SessionID session_id;          // offset 2  (uint32_t)
    uint8_t  modification_count;   // offset 6
    HttpModifyData modify_data[0]; // offset 7
} HttpReplyFromService;
```
`SessionID` is `uint32_t` (`[INFERRED]` from usage; `CORRUPTED_SESSION_ID = 0`).

### F.2 `HttpModifyData` union — `nano_attachment_common.h:464-468`
```c
typedef union __attribute__((__packed__)) HttpModifyData {
    HttpInjectData inject_data[0];
    HttpWebResponseData web_response_data[0];
    HttpCustomResponseData custom_response_data[0];
} HttpModifyData;
```

### F.3 `HttpInjectData` — `nano_attachment_common.h:250-257` (packed)
```c
typedef struct __attribute__((__packed__)) HttpInjectData {
    NanoHttpCpInjectPos injection_pos;  // int64_t, offset 0
    HttpModificationType mod_type;      // int32_t, offset 8
    uint16_t injection_size;            // offset 12
    uint8_t  is_header;                 // offset 14
    uint8_t  orig_buff_index;           // offset 15
    char data[0];                       // offset 16
} HttpInjectData;
```
`NanoHttpCpInjectPos` is `int64_t` (`[INFERRED]`). `INJECT_POS_IRRELEVANT = -1`.

### F.4 `HttpWebResponseData` — `nano_attachment_common.h:259-278` (packed)
```c
typedef struct __attribute__((__packed__)) HttpWebResponseData {
    uint8_t web_response_type;   // offset 0 (NanoWebResponseType)
    uint8_t uuid_size;           // offset 1
    union {
        struct { uint16_t response_code; uint8_t title_size; uint8_t body_size; char data[0]; } custom_response_data;
        struct { uint8_t unused_dummy; uint8_t add_event_id; uint16_t redirect_location_size; char redirect_location[0]; } redirect_data;
    } response_data;             // offset 2
} HttpWebResponseData;
```

### F.5 `HttpCustomResponseData` — `nano_attachment_common.h:281-287` (packed)
```c
typedef struct __attribute__((__packed__)) HttpCustomResponseData {
    uint16_t response_code;   // offset 0
    uint16_t body_size;       // offset 2
    uint8_t  headers_count;   // offset 4
    char data[0];             // offset 5
} HttpCustomResponseData;
// data layout: [HttpHeaderPackedData1][HttpHeaderPackedData2]...[body_data]
```

### F.6 `HttpHeaderPackedData` — `nano_attachment_common.h:429-433` (packed)
```c
typedef struct __attribute__((__packed__)) HttpHeaderPackedData {
    uint16_t key_size;    // offset 0
    uint16_t value_size;  // offset 2
    char data[0];         // offset 4  (key then value)
} HttpHeaderPackedData;
```

### F.7 Verdict handling — `nano_attachment_io.c:996-1240` (`service_reply_receiver`)
Loop until `remaining_messages_to_reply == 0`:
- `TRAFFIC_VERDICT_RECONF` (5): broadcast; does **not** decrement counter.
- `TRAFFIC_VERDICT_ACCEPT` (1): done.
- `TRAFFIC_VERDICT_DROP` (2): build web response; return `NANO_HTTP_FORBIDDEN`.
- `TRAFFIC_VERDICT_CUSTOM_RESPONSE` (8): build custom response.
- `TRAFFIC_VERDICT_INJECT` (3): append `HttpInjectData` to modifications.
- `INSPECT`/`IRRELEVANT`/`DELAYED`/`LIMIT_RESPONSE_HEADERS`: continue.

---

## G. Registration & Communication Handshake

### G.1 Phase 1 — Registration socket (server: `SHARED_REGISTRATION_SIGNAL_PATH`)
nginx side (`ngx_cp_initializer.c:569-750`):
```
send: [uint8_t attachment_type = NGINX_ATT_ID (0)]
      [uint8_t worker_id = ngx_worker + 1]
      [uint8_t workers_amount]
      [uint8_t family_name_size]
      [family_name bytes]            (docker id)
recv: [uint8_t path_length]
      [path bytes]                   -> shared_verdict_signal_path
```
- On `connect()` returning `ENOENT` (no service), fall back to `SHARED_VERDICT_SIGNAL_PATH`
  and return OK (`ngx_cp_initializer.c:615-618`).

nano library (`nano_initializer.c:534-614`) sends the same shape but with `container_id`
instead of `family_name`:
```
[uint8_t attachment_type][uint8_t worker_id+1][uint8_t workers_amount][uint8_t container_id_size][container_id bytes]
```
then reads `[path_length][path]` (`nano_initializer.c:628-653`).

### G.2 Phase 2 — Comm socket (server: `shared_verdict_signal_path`)
The registration socket is closed after phase 1 (`ngx_cp_initializer.c:747`,
`nano_initializer.c:646-650`); phase 2 runs on a **fresh connection** to the
returned `shared_verdict_signal_path`, which stays open as the live
request/verdict connection.
nano library (`nano_initializer.c:279-334`, `send_comm_data_to_comm_socket`):
```
[uint8_t uid_size]
[unique_id bytes]
[uint32_t nano_user_id]
[uint32_t nano_group_id]
[int32_t target_core]
```
then reads a 1-byte ack (`nano_initializer.c:392-398`). `target_core` is the
paired-core affinity hint (`ngx_cp_initializer.c:430-452`); the attachment
sends `-1` (unpaired) or the worker's target core.

`unique_id` is the attachment's instance-aware identity: `<family>_<worker_id+1>`
(`ngx_cp_initializer.c:798-804`), i.e. the container/family name joined with the
1-based worker id. The engine validates it against its own unique id
(`instance_awareness.cc:48-58`, `family_instance`) and **closes the comm socket
without an ack on mismatch** (`nginx_attachment.cc getUidFromSocket`), so the
plain family name alone is not accepted. This module sends
`config.EngineConfig.UniqueID()` = `<family_name>_<worker_id+1>` — the same
string it later uses as the shared-memory queue name (§D.1), so the two wire
identities cannot drift.

### G.2b Comm-socket signaling (per request)

The comm socket is **not** a one-shot handshake channel. After the phase-2 ack
it stays open for the attachment's lifetime (`isIpcReady` requires
`comm_socket > 0`, `ngx_cp_initializer.c:1067-1069`) and carries a 4-byte
doorbell in each direction per chunk:

1. Attachment writes the request/response chunk to the shared-memory ring.
2. Attachment writes the chunk's 4-byte little-endian `session_id` to the comm
   socket (`ngx_cp_io.c:72-114` `signal_to_service`).
3. The engine's inspection file routine fires on comm-socket data, reads the
   signaled session id, **then** drains the ring for that session
   (`nginx_attachment.cc:594-658` `handleInspection` → `handleRequestFromQueue`;
   ring data for other sessions is popped and ignored).
4. After handling, the engine writes the verdict to the ring and echoes the
   handled `session_id` back on the comm socket (`nginx_attachment.cc:664-695`).
5. The attachment reads the 4-byte echo, matching it against the session it is
   waiting on (`ngx_cp_io.c:128-221` `wait_for_service`), then reads the verdict
   from the ring.

The protocol is per-session: only **one** inspection session may be in flight
per comm socket, so the attachment serializes sessions on the socket. This
module implements the signal in `Send` (ring push + 4-byte session-id write)
and the echo wait in `Recv` (4-byte read before each ring pop), and serializes
sessions per connection (`internal/app/conn.go` flow lock on the linux shm
transport).

### G.4 Request transaction sequence

A complete inspection session streams the full request transaction, not just
the metadata:

```
[REQUEST_START]     metadata block (protocol, method, host, addrs, ports, URIs, waf_tag)
[REQUEST_HEADER]+   one or more header bulks (key/value pairs)
[REQUEST_BODY]+     body chunks (is_last_chunk on the final one)
[REQUEST_END]       data_type + session_id
```

Each frame is a separate ring message, individually signaled on the comm
socket (§G.2b). The engine replies with an intermediate INSPECT verdict after
REQUEST_START/HEADER/BODY, and produces the **terminal** verdict (ACCEPT,
DROP, CUSTOM_RESPONSE, or IRRELEVANT) at REQUEST_END: `inspectEndRequest()`
(`nginx_attachment.cc:1112-1114`) → `EndRequestEvent` → WAAP
`waf2Transaction.end_request()` (`waap_component_impl.cc:330-350`). An
attachment that sends REQUEST_START and never ends the transaction will never
receive a final verdict, so attack traffic is never blocked and no detection
log is produced. This module streams the full sequence in
`internal/app/conn.go SendRequest` (REQUEST_START → REQUEST_HEADER bulk →
REQUEST_BODY chunk → REQUEST_END) and the verdict waiter
(`internal/app/policy.go await`) skips intermediate INSPECT verdicts, returning
only the terminal one.

### G.3 Keep-alive — `nano_attachment.c:497-543`, `ngx_http_cp_attachment_module.c:349-467`
Connect to `SHARED_KEEP_ALIVE_PATH`, then:
```
[uint8_t worker_id]
[uint8_t family_name_size / container_id_size]
[family_name / container_id bytes]
```
- nginx sends `worker_id` (uint8_t) + `family_name_size` + `family_name`
  (`ngx_http_cp_attachment_module.c:424-466`).
- nano sends `worker_id` + `container_id_size` + `container_id`
  (`nano_attachment.c:497-543`).
- `worker_id` field type is `uint8_t` (`nano_initializer.h:52`).
- Interval default `DEFAULT_KEEP_ALIVE_INTERVAL_MSEC = 300000` ms.

---

## H. Session Lifecycle (nginx reference)

- `init_cp_session_data` (`ngx_cp_hooks.c:64-105`): `session_id = (session_id << 1) | 1`
  (odd, per-worker static counter); `verdict = TRAFFIC_VERDICT_INSPECT`;
  `was_request_fully_inspected = 0`.
- Request header filter (`ngx_cp_hooks.c:560-717`): registration check, `isIpcReady`,
  `handle_shmem_corruption`, static-resource check, spawn `req_header_handler_thread`,
  `DELAYED` → `hold_verdict`, `CUSTOM_RESPONSE` → custom response,
  `finalize_request_headers_hook`.
- Request body filter (`ngx_cp_hooks.c:720-871`): spawn `req_body_filter_thread`.
- Response header filter core (`ngx_cp_hooks.c:1004-1150`): spawn `res_header_filter_thread`;
  on `NGX_HTTP_FORBIDDEN` → `finalize_rejected_request`.
- Response body filter core (`ngx_cp_hooks.c:1159-1689`): decompress → send `RESPONSE_BODY`
  → recompress; on `DROP` → `NGX_HTTP_FORBIDDEN`.
- Timeout: `was_transaction_timedout` (uses `req_max_proccessing_ms_time`,
  `res_max_proccessing_ms_time`).
- `is_brotli_inspection_enabled` gates brotli decompression.

### H.1 Config defaults — `ngx_cp_utils.c:96-125`
| Key | Default | Line |
|---|---|---|
| `fail_open_timeout` | 50 | 99 |
| `fail_mode_hold_verdict` | NGX_OK (hold) | 100 |
| `req_max_proccessing_ms_time` | 3000 | 103 |
| `res_max_proccessing_ms_time` | 3000 | 104 |
| `keep_alive_interval_msec` | macro (300000) | 105 |
| `min_retries_for_verdict` | 3 | 115 |
| `max_retries_for_verdict` | 15 | 116 |
| `hold_verdict_retries` | 3 | 117 |
| `hold_verdict_polling_time` | 1 | 118 |
| `body_size_trigger` | 200000 | 119 |
| `decompression_pool_size` | 262144 | 122 |
| `recompression_pool_size` | 16384 | 123 |
| `is_brotli_inspection_enabled` | 0 | 124 |

---

## J. Compression

- `CompressionType` enum (C.11). No DEFLATE.
- Decompression/recompression pools sized by `decompression_pool_size` /
  `recompression_pool_size`.
- Brotli inspection gated by `is_brotli_inspection_enabled`.
- The verdict does **not** carry a compression type; the attachment detects the response
  `Content-Encoding` header and decompresses before sending `RESPONSE_BODY`, then
  recompresses after the verdict.

---

## K. Discrepancies / [INFERRED] Items (must verify)

1. **Port byte order**: nginx sends `listening_port`/`client_port` via `htons()`
   (`ngx_cp_io.c:970,983`). The nano library sends `metadata->listening_port` /
   `metadata->client_port` raw (`nano_attachment_io.c:1514-1543`). The intaker must be
   consistent. `[INFERRED]` — verify which the service expects.
2. **Metadata fragment count**: nginx always sends `META_DATA_COUNT + 2 = 22` fragments
   (parsed_host/parsed_uri/waf_tag always present). The nano library sends
   `meta_data_count + 2` where `meta_data_count = META_DATA_COUNT - 4 = 16`, adding
   `+2` each for parsed_host and parsed_uri only when non-empty (`nano_attachment_io.c:1431,
   1545-1581`). So nano sends 18–22 fragments. The receiver must tolerate variable count.
   `[INFERRED]` — verify the intaker's parser.
3. `SessionID` type is `uint32_t` (`[INFERRED]` from `HttpReplyFromService` layout and
   `set_fragments_identifiers` using `uint32_t`).
4. `NanoHttpCpInjectPos` is `int64_t` (`[INFERRED]` from `HttpInjectData` packing).
5. `worker_id` in keep-alive is `uint8_t` (confirmed `nano_initializer.h:52`).

---

## Byte Fixtures

All fixtures assume little-endian host, `session_id = 0x00000001`.

### Fixture 1 — REQUEST_START (minimal, empty waf_tag)
```
00 00            data_type = REQUEST_START (0)
01 00 00 00      session_id = 1
00 00            http_protocol.len = 0
00 00            method.len = 0
00 00            host.len = 0
00 00            listening_ip.len = 0
00 00            listening_port = 0
00 00            unparsed_uri.len = 0
00 00            client_ip.len = 0
00 00            client_port = 0
00 00            parsed_host.len = 0
00 00            parsed_uri.len = 0
00 00            waf_tag.len = 0
```

### Fixture 2 — REQUEST_END
```
03 00            data_type = REQUEST_END (3)
01 00 00 00      session_id = 1
```

### Fixture 3 — RESPONSE_CODE
```
04 00            data_type = RESPONSE_CODE (4)
01 00 00 00      session_id = 1
C8 00            response_code = 200
```

### Fixture 4 — CONTENT_LENGTH
```
08 00            data_type = CONTENT_LENGTH (8)
01 00 00 00      session_id = 1
05 00 00 00 00 00 00 00   content_length = 5
```

### Fixture 5 — REQUEST_HEADER bulk (1 header: "Host: example.com")
```
01 00            data_type = REQUEST_HEADER (1)
01 00 00 00      session_id = 1
01               is_last_part = 1
00               bulk_part_index = 0
04 00            key.len = 4
48 6F 73 74      "Host"
0B 00            value.len = 11
65 78 61 6D 70 6C 65 2E 63 6F 6D   "example.com"
```

### Fixture 6 — REQUEST_BODY (5 bytes "hello", last chunk)
```
02 00            data_type = REQUEST_BODY (2)
01 00 00 00      session_id = 1
01               is_last_chunk = 1
00               part_count = 0
68 65 6C 6C 6F   "hello"
```

### Fixture 7 — Verdict reply (ACCEPT)
```
01 00            verdict = TRAFFIC_VERDICT_ACCEPT (1)
01 00 00 00      session_id = 1
00               modification_count = 0
```

### Fixture 8 — Verdict reply (DROP + custom web response)
```
02 00            verdict = TRAFFIC_VERDICT_DROP (2)
01 00 00 00      session_id = 1
01               modification_count = 1
00               web_response_type = CUSTOM_WEB_RESPONSE (0)
00               uuid_size = 0
C8 01            response_code = 200
00               title_size = 0
00               body_size = 0
```