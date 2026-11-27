# bip377

A C99 codec for [BIP 377](https://github.com/bitcoin/bips/pull/2353), the signing message encoding between a coordinator and a signer. It implements the signer's side: it decodes requests and encodes responses.

The library does not allocate, holds no state and depends on nothing but the C library's `string.h`. It has no knowledge of the transport: a message is a byte string, however it was carried.

The draft implemented is the one at `pythcoiner/bips@90d2106`. Message `TYPE` `0x06` is reserved there, so a request carrying it is unreadable.

## API

`include/bip377.h` is the whole interface.

- `bip377_is_message` tells whether bytes begin with `MAGIC`.
- `bip377_request_header` reads the header of a request, or reports the request as unreadable and yields the header of the reply it gets (`TYPE` `0x00`, `REQUEST_ID` `0x0000`).
- `bip377_request_decode` validates a request and builds its tree in a block the caller provides. Called with no block it measures the block the message needs. The tree owns copies, so the message can be released once it returns.
- `bip377_response_encode` validates a response and writes it to a buffer the caller provides. Called with no buffer it measures.
- `bip377_strerror` describes a status code.

```c
size_t needed;
if (bip377_request_decode(msg, len, NULL, 0, &needed, NULL) != BIP377_OK)
  return; /* answer ERROR 0x03, or 0x06 for an unknown FORM */
void *mem = malloc(needed);
const bip377_request *request;
bip377_request_decode(msg, len, mem, needed, NULL, &request);
/* ... act on request->body ... */
free(mem);
```

A decoded request needs at most a few dozen bytes per byte of message, so a caller that bounds the message bounds the block.

## Tests

`make run` runs two programs; `make run DEBUG=1` runs them under ASan and UBSan.

- `test/test_vectors` checks the BIP's test vectors, copied unchanged into `test/vectors/`: request vectors decode to the fields their description gives, response vectors are rebuilt and encode to the same bytes, malformed requests are refused for their reason. Vectors that are malformed responses need a response decoder and are counted as skipped.
- `test/test_api` covers the calling contract, every response the encoder refuses, and every truncation and single-byte change of the valid request vectors.

To follow a newer draft, replace the files in `test/vectors/` with the BIP's. `test_vectors` fails on any vector it has no case for.
