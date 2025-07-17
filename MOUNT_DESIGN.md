# Skiff Mount Command Design

## Overview

The skiff mount command provides FUSE-based mounting of OCI container images as read-only filesystems. Due to namespace conflicts between FUSE mounting and container storage access, the implementation uses a two-process architecture with abstract Unix domain socket communication.

## Problem Statement

### Namespace Conflict Issue

Container storage (overlay filesystems) requires:
- **User namespace** (`CLONE_NEWUSER`) - for privilege escalation
- **Mount namespace** (`CLONE_NEWNS`) - for overlay mount operations

FUSE mounting conflicts with:
- **Mount namespace** - prevents FUSE from creating mounts correctly
- **User namespace isolation** - can interfere with FUSE kernel communication

The `unshare.MaybeReexecUsingUserNamespace(true)` function creates both namespaces together and cannot be separated.

### Memory Efficiency Requirements

Container images can contain large files and many layers. Loading entire filesystem content into memory would be inefficient and potentially cause OOM conditions. A lazy-loading approach is required.

## Solution Architecture

### Two-Process Design

```
┌─────────────────────────┐    Unix Socket      ┌────────────────────────────┐
│   Parent Process        │◄───────────────────►│   Child Process            │
│   (FUSE Mount)          │ /tmp/skiff-mount-*  │   (Container Storage)      │
├─────────────────────────┤                     ├────────────────────────────┤
│ • No user namespace     │                     │ • User + mount namespace   │
│ • FUSE filesystem       │                     │ • Container storage access │
│ • LazyRegularFile nodes │                     │ • Layer processing         │
│ • On-demand file reads  │                     │ • Merged filesystem index  │
└─────────────────────────┘                     └────────────────────────────┘
```

### Process Responsibilities

#### Parent Process (Main)
- **Environment**: Runs without user namespace to avoid FUSE conflicts
- **FUSE Management**: Creates and manages FUSE mount using go-fuse library
- **Filesystem Tree**: Builds directory structure with LazyRegularFile nodes
- **On-Demand Loading**: Requests file data from child process when accessed
- **User Interface**: Handles mount/unmount operations

#### Child Process (Helper)
- **Environment**: Runs with user+mount namespace for container storage access
- **Storage Access**: Uses containers/storage library to access OCI images
- **Layer Processing**: Processes tar layers and builds merged filesystem index
- **Data Serving**: Serves file content on-demand via Unix socket
- **Overlay Logic**: Handles layer overlay semantics (upper layers override lower)

## Communication Protocol

### Transport Layer
- **Method**: File-based Unix Domain Sockets
- **Address**: `/tmp/skiff-mount-{pid}.sock`
- **Benefits**:
  - High performance (Unix domain sockets)
  - Reliable cross-process communication
  - Bidirectional communication
  - Simple cleanup on process termination
- **Note**: Originally designed to use abstract Unix sockets (`@skiff-mount-ipc-{pid}`), but changed to file-based sockets during implementation for improved reliability in subprocess communication.

### Message Protocol

```go
type MessageType string
const (
    RequestFileIndex MessageType = "file_index"    // Get merged filesystem index
    RequestFileData  MessageType = "file_data"     // Get file content
    RequestComplete  MessageType = "complete"      // Signal completion
    ResponseIndex    MessageType = "index"         // Return filesystem index
    ResponseData     MessageType = "data"          // Return file data
    ResponseError    MessageType = "error"         // Return error
)

type IPCMessage struct {
    Type     MessageType `json:"type"`
    Path     string      `json:"path,omitempty"`     // File path for data requests
    Offset   int64       `json:"offset,omitempty"`   // Byte offset for partial reads
    Size     int         `json:"size,omitempty"`     // Bytes to read
    Data     []byte      `json:"data,omitempty"`     // File content or index data
    Error    string      `json:"error,omitempty"`    // Error message
}

type FileMetadata struct {
    Path    string `json:"path"`    // Full path: "/usr/bin/busybox"
    Size    int64  `json:"size"`    // File size in bytes
    Mode    uint32 `json:"mode"`    // File permissions
    ModTime int64  `json:"mtime"`   // Modification time
    IsDir   bool   `json:"is_dir"`  // Directory flag
}

type FilesystemIndex struct {
    Files map[string]FileMetadata `json:"files"` // path -> metadata
}
```

## Implementation Details

### Go-FUSE Integration

The implementation uses the high-level `fs` package from go-fuse rather than the low-level `fuse` package:

**Rationale:**
- **Simplified Implementation**: Automatic inode management reduces boilerplate
- **Built-in Caching**: Kernel caching integration beneficial for lazy-loaded content
- **Thread Safety**: Built-in synchronization for node operations
- **Custom ReadResult Support**: Can implement lazy loading via custom ReadResult

**Key Interfaces:**
```go
type LazyRegularFile struct {
    fs.Inode
    socketClient *UnixSocketClient
    path         string  // File path in merged filesystem
    size         int64   // File size from metadata
}

// Required FUSE interfaces
var _ = (fs.NodeOpener)((*LazyRegularFile)(nil))     // Open file
var _ = (fs.NodeReader)((*LazyRegularFile)(nil))     // Read file content
var _ = (fs.NodeGetattrer)((*LazyRegularFile)(nil))  // Get file attributes
```

### Layer Processing and Merging

Container images consist of multiple tar layers that must be merged using overlay semantics:

1. **Layer Order**: Layers processed from base to top ✅ **IMPLEMENTED**
2. **File Overrides**: Upper layers override files from lower layers ✅ **IMPLEMENTED** 
3. **Whiteouts**: Special entries that delete files from lower layers ⚠️ **NOT YET IMPLEMENTED**
4. **Directory Merging**: Directories from all layers are combined ✅ **IMPLEMENTED**

```go
// NOTE: This is the PLANNED implementation. Current implementation in buildLayerIndex()
// function does not yet include whiteout handling or separate layer data caching.

type LayerProcessor struct {
    index     *FilesystemIndex
    layerData map[string]map[string][]byte // layerID -> path -> data
}

func (p *LayerProcessor) ProcessLayer(layerID string, tarStream io.Reader) error {
    tr := tar.NewReader(tarStream)

    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }

        // Handle overlay semantics
        if isWhiteout(hdr.Name) {              // ⚠️ NOT YET IMPLEMENTED
            p.deleteFile(getWhiteoutTarget(hdr.Name))
            continue
        }

        // Read and cache file data
        data, err := io.ReadAll(tr)
        if err != nil {
            return err
        }

        // Update merged index (overwrites previous layers)
        p.index.Files[hdr.Name] = FileMetadata{
            Path:    hdr.Name,
            Size:    hdr.Size,
            Mode:    uint32(hdr.Mode),
            ModTime: hdr.ModTime.Unix(),
            IsDir:   hdr.Typeflag == tar.TypeDir,
        }

        // Cache file data for serving                // ⚠️ SIMPLIFIED IN CURRENT IMPLEMENTATION
        if p.layerData[layerID] == nil {             // Current implementation re-reads from 
            p.layerData[layerID] = make(map[string][]byte) // layers on-demand instead of caching
        }
        p.layerData[layerID][hdr.Name] = data
    }

    return nil
}
```

### File Access Flow

```
1. User access: ls /usr/bin/
   ↓
2. FUSE calls: LazyRegularFile.Lookup()
   ↓
3. Return cached directory entries from index
   ↓
4. User access: cat /usr/bin/busybox
   ↓
5. FUSE calls: LazyRegularFile.Read(offset, size)
   ↓
6. Socket request: RequestFileData{path: "/usr/bin/busybox", offset: 0, size: 4096}
   ↓
7. Child process: Lookup file in layer cache
   ↓
8. Socket response: ResponseData{data: [...]}
   ↓
9. FUSE response: Return data to kernel
   ↓
10. User receives: File content
```

## Performance Considerations

### Lazy Loading Benefits
- **Memory Efficiency**: Only accessed files are loaded into memory
- **Fast Mount Time**: No need to extract entire image before mounting
- **Scalable**: Works with images of any size
- **Cache Friendly**: Kernel VFS caching reduces redundant requests

### Socket Performance
- **High Throughput**: Unix domain sockets provide high performance communication
- **Low Latency**: Local socket communication with minimal overhead
- **Zero Copy**: Potential for splice() operations in future optimizations ⚠️ **NOT YET IMPLEMENTED**

### Caching Strategy
- **Child Process**: ⚠️ **SIMPLIFIED** - Current implementation re-reads layer data on each request instead of caching in memory
- **Kernel VFS**: Caches frequently accessed file content ✅ **IMPLEMENTED**
- **FUSE Layer**: ⚠️ **BASIC** - Uses default timeouts, not yet configurable

## Error Handling

### Communication Errors
- **Socket Disconnection**: ⚠️ **BASIC** - Return EIO to FUSE, no reconnection logic yet
- **Protocol Errors**: ✅ **IMPLEMENTED** - Log and return appropriate FUSE error codes
- **Timeout Handling**: ⚠️ **NOT YET IMPLEMENTED** - No configurable timeouts for socket operations

### Storage Errors
- **Layer Access Failures**: ✅ **IMPLEMENTED** - Skip failed layers, continue with available layers
- **Decompression Errors**: ✅ **IMPLEMENTED** - Skip corrupted layers, log warnings
- **Permission Errors**: ⚠️ **BASIC** - Basic error returns, not comprehensive permission handling

## Security Considerations

### Namespace Isolation
- **Parent Process**: ✅ **IMPLEMENTED** - Runs with minimal privileges
- **Child Process**: ✅ **IMPLEMENTED** - Isolated in user namespace, limited blast radius
- **Socket Security**: ⚠️ **CHANGED** - File-based sockets in /tmp, less secure than abstract sockets

### Input Validation
- **Path Traversal**: ⚠️ **BASIC** - Some path validation, could be more comprehensive
- **Size Limits**: ⚠️ **NOT YET IMPLEMENTED** - No maximum read size enforcement
- **Protocol Validation**: ✅ **IMPLEMENTED** - JSON unmarshaling provides basic validation

## Future Optimizations

### Zero-Copy Operations ⚠️ **NOT YET IMPLEMENTED**
- **splice() System Call**: Direct kernel-to-kernel data transfer
- **SharedReadResult**: Custom ReadResult that shares memory between processes

### Persistent Caching ⚠️ **NOT YET IMPLEMENTED**
- **Disk Cache**: Cache frequently accessed files to disk
- **Layer Indexing**: Pre-build filesystem indexes for common images

### Parallel Processing ⚠️ **NOT YET IMPLEMENTED**
- **Concurrent Layer Processing**: Process multiple layers simultaneously
- **Streaming Decompression**: Stream layer data without full buffering

### Missing Core Features ⚠️ **TO BE IMPLEMENTED**
- **Whiteout Handling**: Support for `.wh.*` files in container layers
- **Memory Caching**: Cache decompressed layer data in mount helper process
- **Socket Reconnection**: Automatic reconnection on communication failures
- **Configurable Timeouts**: Tunable timeouts for socket operations
- **Enhanced Security**: Size limits, comprehensive path validation
- **Symlink Support**: Proper handling of symbolic links from container layers

## Testing Strategy

### Unit Tests
- **Socket Communication**: Mock socket for protocol testing
- **Layer Processing**: Test overlay semantics with synthetic layers
- **FUSE Operations**: Test file operations with fake data

### Integration Tests
- **End-to-End**: Mount real images and verify filesystem behavior
- **Performance**: Benchmark large file access and directory traversal
- **Error Scenarios**: Test network failures, corrupted layers, etc.

### Compatibility Testing
- **Image Formats**: Test with various OCI image formats
- **Layer Types**: Test with different compression algorithms
- **Platform Support**: Verify behavior across different Linux distributions
