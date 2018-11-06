# Low-Level Logging API
The low-level logging API provides functions that allow SDK clients to securely log sequences of arbitrary byte strings. This API is intended to be a stable base on top of which a future high-level logging API may be added (such an API would support simple string messages and metadata logging with a discoverable JSON-like format to facilitate the human-readable display of the data in a generalized secure logging service). To this end, only a minimal set of structs and functions are exposed publicly in the header to avoid breaking changes in the future and the attributes object is made opaque.

## Usage
### Configuration
Clients of the low-level logging API initialize the logger with ```TcpsLogOpen()``` and destruct with ```TcpsLogClose()```. Logging categories are added with ```TcpsLogAddCategory()```. Transports for the logging data are set via ```TcpsLogSetLocalTransport()``` and ```TcpsLogSetRemoteTransport()```. 

### Logging

Once the logger has been configured with all requisite categories and transports, it may be used with ```TcpsLogWrite()``` and ```TcpsLogFlush()```

* ```TcpsLogWrite()``` requires that at least one transport has been set. If the local transport has been set, a single log event containing the logged byte string is written to the local store. If only the remote transport has been set, a block containing the single log event is sent to the remote store.
* ```TcpsLogFlush()``` requires that both transports have been set. It reads all entries residing in the given category's local store, generates a log block, sends the log block to the remote store, and clears the local store.
