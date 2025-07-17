package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/types"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/urfave/cli/v3"

	skiff "github.com/dcermak/skiff/pkg"
)

// Communication protocol types
type MessageType string

const (
	RequestFileIndex MessageType = "file_index"
	RequestFileData  MessageType = "file_data"
	RequestComplete  MessageType = "complete"
	ResponseIndex    MessageType = "index"
	ResponseData     MessageType = "data"
	ResponseError    MessageType = "error"
)

type IPCMessage struct {
	Type   MessageType `json:"type"`
	Path   string      `json:"path,omitempty"`
	Offset int64       `json:"offset,omitempty"`
	Size   int         `json:"size,omitempty"`
	Data   []byte      `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type FileMetadata struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModTime int64  `json:"mtime"`
	IsDir   bool   `json:"is_dir"`
}

type FilesystemIndex struct {
	Files map[string]FileMetadata `json:"files"`
}

// LazyRegularFile fetches file data on-demand from the mount helper
type LazyRegularFile struct {
	fs.Inode
	metadata FileMetadata
	client   *UnixSocketClient
}

var _ = (fs.NodeOpener)((*LazyRegularFile)(nil))
var _ = (fs.NodeGetattrer)((*LazyRegularFile)(nil))

func (f *LazyRegularFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = f.metadata.Mode
	out.Size = uint64(f.metadata.Size)
	out.Mtime = uint64(f.metadata.ModTime)
	out.Atime = uint64(f.metadata.ModTime)
	out.Ctime = uint64(f.metadata.ModTime)
	return 0
}

func (f *LazyRegularFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return &LazyFileHandle{
		file:   f,
		client: f.client,
	}, 0, 0
}

// LazyFileHandle handles read operations by fetching data on-demand
type LazyFileHandle struct {
	file   *LazyRegularFile
	client *UnixSocketClient
}

var _ = (fs.FileReader)((*LazyFileHandle)(nil))

func (fh *LazyFileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	// Request file data from mount helper
	msg := IPCMessage{
		Type:   RequestFileData,
		Path:   fh.file.metadata.Path,
		Offset: off,
		Size:   len(dest),
	}

	err := fh.client.SendMessage(msg)
	if err != nil {
		log.Printf("failed to send file data request: %v", err)
		return nil, syscall.EIO
	}

	response, err := fh.client.ReceiveMessage()
	if err != nil {
		log.Printf("failed to receive file data response: %v", err)
		return nil, syscall.EIO
	}

	if response.Type == ResponseError {
		log.Printf("mount helper error: %s", response.Error)
		return nil, syscall.EIO
	}

	if response.Type != ResponseData {
		log.Printf("unexpected response type: %s", response.Type)
		return nil, syscall.EIO
	}

	return fuse.ReadResultData(response.Data), 0
}

var mountCommand = cli.Command{
	Name:  "mount",
	Usage: "Mount an OCI image as a FUSE filesystem",
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image", UsageText: "Container image ref"},
		&cli.StringArg{Name: "mountpoint", UsageText: "Directory to mount the image"},
	},
	// Note: No Before: setupNamespaceForStorage - we try to mount without user namespace
	Action: func(ctx context.Context, c *cli.Command) error {
		image := c.StringArg("image")
		if image == "" {
			return fmt.Errorf("image URL is required")
		}

		mountpoint := c.StringArg("mountpoint")
		if mountpoint == "" {
			return fmt.Errorf("mountpoint is required")
		}

		sysCtx := types.SystemContext{}
		return mountImage(image, mountpoint, ctx, &sysCtx)
	},
}

var mountHelperCommand = cli.Command{
	Name:   "mount-helper",
	Usage:  "Internal helper for mount command (runs in user namespace)",
	Hidden: true,
	Arguments: []cli.Argument{
		&cli.StringArg{Name: "image", UsageText: "Container image ref"},
		&cli.StringArg{Name: "socket", UsageText: "Unix socket path for communication"},
	},
	Before: setupNamespaceForStorage,
	Action: func(ctx context.Context, c *cli.Command) error {
		image := c.StringArg("image")
		if image == "" {
			return fmt.Errorf("image URL is required")
		}

		socketPath := c.StringArg("socket")
		if socketPath == "" {
			return fmt.Errorf("socket path is required")
		}

		sysCtx := types.SystemContext{}
		return runMountHelper(image, socketPath, ctx, &sysCtx)
	},
}

// HeaderToFileInfo fills a fuse.Attr struct from a tar.Header.
func HeaderToFileInfo(out *fuse.Attr, h *tar.Header) {
	out.Mode = uint32(h.Mode)
	out.Size = uint64(h.Size)
	out.Uid = uint32(h.Uid)
	out.Gid = uint32(h.Gid)
	out.SetTimes(&h.AccessTime, &h.ModTime, &h.ChangeTime)
}

// lazyImageRoot builds filesystem from index received from mount helper
type lazyImageRoot struct {
	fs.Inode
	client *UnixSocketClient
	index  *FilesystemIndex
}

var _ = (fs.NodeOnAdder)((*lazyImageRoot)(nil))

func (r *lazyImageRoot) OnAdd(ctx context.Context) {
	// Build filesystem tree from the index
	for path, metadata := range r.index.Files {
		r.addFileToTree(ctx, path, metadata)
	}
}

func (r *lazyImageRoot) addFileToTree(ctx context.Context, path string, metadata FileMetadata) {
	// Clean path and split into components
	cleanPath := filepath.Clean(path)
	if cleanPath == "/" || cleanPath == "." {
		return
	}

	// Remove leading slash
	if strings.HasPrefix(cleanPath, "/") {
		cleanPath = cleanPath[1:]
	}

	parts := strings.Split(cleanPath, "/")
	if len(parts) == 0 {
		return
	}

	// Navigate/create directory structure
	current := &r.Inode
	for _, comp := range parts[:len(parts)-1] {
		if len(comp) == 0 {
			continue
		}

		child := current.GetChild(comp)
		if child == nil {
			child = current.NewPersistentInode(ctx,
				&fs.Inode{},
				fs.StableAttr{Mode: fuse.S_IFDIR})
			current.AddChild(comp, child, true)
		}
		current = child
	}

	// Add the final component
	filename := parts[len(parts)-1]
	if metadata.IsDir {
		// Directory
		child := current.GetChild(filename)
		if child == nil {
			child = current.NewPersistentInode(ctx,
				&fs.Inode{},
				fs.StableAttr{Mode: fuse.S_IFDIR})
			current.AddChild(filename, child, true)
		}
	} else {
		// Regular file - use LazyRegularFile
		lazyFile := &LazyRegularFile{
			metadata: metadata,
			client:   r.client,
		}
		child := current.NewPersistentInode(ctx, lazyFile, fs.StableAttr{})
		current.AddChild(filename, child, true)
	}
}

func mountImage(uri string, mountpoint string, ctx context.Context, sysCtx *types.SystemContext) error {
	// Create Unix socket for communication
	socketPath := fmt.Sprintf("/tmp/skiff-mount-%d.sock", os.Getpid())

	// Start mount helper process with user namespace
	log.Printf("Starting mount helper: %s mount-helper %s %s", os.Args[0], uri, socketPath)
	helperCmd := exec.Command(os.Args[0], "mount-helper", uri, socketPath)
	helperCmd.Stdout = os.Stdout
	helperCmd.Stderr = os.Stderr
	// Inherit environment to ensure storage access works
	helperCmd.Env = os.Environ()
	// Set working directory to ensure same context
	helperCmd.Dir, _ = os.Getwd()

	err := helperCmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start mount helper: %w", err)
	}

	// Ensure helper cleanup
	defer func() {
		helperCmd.Process.Kill()
		helperCmd.Wait()
	}()

	// Give helper time to start listening
	time.Sleep(1 * time.Second)

	// Check if helper process is still running
	if helperCmd.ProcessState != nil && helperCmd.ProcessState.Exited() {
		return fmt.Errorf("mount helper process exited early: %v", helperCmd.ProcessState)
	}

	// Connect to mount helper
	client, err := NewUnixSocketClient(socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to mount helper: %w", err)
	}
	defer client.Close()

	// Request filesystem index
	err = client.SendMessage(IPCMessage{Type: RequestFileIndex})
	if err != nil {
		return fmt.Errorf("failed to request filesystem index: %w", err)
	}

	response, err := client.ReceiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive filesystem index: %w", err)
	}

	if response.Type == ResponseError {
		return fmt.Errorf("mount helper error: %s", response.Error)
	}

	if response.Type != ResponseIndex {
		return fmt.Errorf("unexpected response type: %s", response.Type)
	}

	// Parse filesystem index
	var index FilesystemIndex
	err = json.Unmarshal(response.Data, &index)
	if err != nil {
		return fmt.Errorf("failed to parse filesystem index: %w", err)
	}

	// Create lazy filesystem root
	root := &lazyImageRoot{
		client: client,
		index:  &index,
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:      false,
			AllowOther: false,
			FsName:     "skiff-" + uri,
		},
	}

	server, err := fs.Mount(mountpoint, root, opts)
	if err != nil {
		return fmt.Errorf("failed to mount filesystem: %w", err)
	}

	fmt.Printf("Mounted %s at %s\n", uri, mountpoint)
	fmt.Println("Press Ctrl+C to unmount")

	server.Wait()
	return nil
}

// UnixSocketClient handles communication over abstract Unix domain sockets
type UnixSocketClient struct {
	conn net.Conn
}

func NewUnixSocketClient(socketPath string) (*UnixSocketClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to socket %s: %w", socketPath, err)
	}
	return &UnixSocketClient{conn: conn}, nil
}

func (c *UnixSocketClient) SendMessage(msg IPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Send message length first, then message
	length := int32(len(data))
	lengthBytes := (*(*[4]byte)(unsafe.Pointer(&length)))[:]

	_, err = c.conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

func (c *UnixSocketClient) ReceiveMessage() (*IPCMessage, error) {
	// Read message length first
	lengthBytes := make([]byte, 4)
	_, err := io.ReadFull(c.conn, lengthBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := *(*int32)(unsafe.Pointer(&lengthBytes[0]))

	// Read message
	data := make([]byte, length)
	_, err = io.ReadFull(c.conn, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	var msg IPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return &msg, nil
}

func (c *UnixSocketClient) Close() error {
	return c.conn.Close()
}

// runMountHelper runs in the child process with user namespace access
func runMountHelper(uri string, socketPath string, ctx context.Context, sysCtx *types.SystemContext) error {
	// Set up Unix socket server first so parent can connect immediately
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	log.Printf("Mount helper listening on socket: %s", socketPath)

	// Get the image and process layers to build filesystem index
	img, _, err := skiff.ImageAndLayersFromURI(ctx, sysCtx, uri)
	if err != nil {
		return fmt.Errorf("failed to get image: %w", err)
	}

	imgSrc, err := img.Reference().NewImageSource(ctx, sysCtx)
	if err != nil {
		return fmt.Errorf("failed to create image source: %w", err)
	}
	defer imgSrc.Close()

	// Build merged filesystem index
	index := FilesystemIndex{Files: make(map[string]FileMetadata)}

	layerInfos := img.LayerInfos()
	log.Printf("Processing %d layers for image %s", len(layerInfos), uri)

	for i, layer := range layerInfos {
		log.Printf("Processing layer %d/%d: %s", i+1, len(layerInfos), layer.Digest)
		blob, _, err := imgSrc.GetBlob(ctx, layer, none.NoCache)
		if err != nil {
			log.Printf("failed to get blob for layer %s: %v", layer.Digest, err)
			continue
		}

		uncompressedStream, _, err := compression.AutoDecompress(blob)
		if err != nil {
			blob.Close()
			log.Printf("auto-decompressing layer %s: %v", layer.Digest, err)
			continue
		}

		err = buildLayerIndex(uncompressedStream, &index)
		uncompressedStream.Close()
		blob.Close()
		if err != nil {
			log.Printf("failed to build layer index for %s: %v", layer.Digest, err)
		} else {
			log.Printf("Successfully processed layer %s", layer.Digest)
		}
	}

	log.Printf("Filesystem index contains %d files", len(index.Files))

	// Handle connections with the built index
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, &index, img, imgSrc, ctx, sysCtx)
	}
}

// buildLayerIndex processes a layer and adds files to the merged index
func buildLayerIndex(stream io.Reader, index *FilesystemIndex) error {
	tr := tar.NewReader(stream)

	var longName *string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		// Handle long filenames
		if hdr.Typeflag == 'L' {
			buf := bytes.NewBuffer(make([]byte, 0, hdr.Size))
			io.Copy(buf, tr)
			s := buf.String()
			longName = &s
			continue
		}

		if longName != nil {
			hdr.Name = *longName
			longName = nil
		}

		path := filepath.Clean("/" + hdr.Name)

		// Add to index (later layers override earlier ones)
		index.Files[path] = FileMetadata{
			Path:    path,
			Size:    hdr.Size,
			Mode:    uint32(hdr.Mode),
			ModTime: hdr.ModTime.Unix(),
			IsDir:   hdr.Typeflag == tar.TypeDir,
		}

		// Skip to next entry (don't read data here, just build index)
		if hdr.Size > 0 {
			io.Copy(io.Discard, tr)
		}
	}

	return nil
}

// handleConnection handles requests from the parent process
func handleConnection(conn net.Conn, index *FilesystemIndex, img types.Image, imgSrc types.ImageSource, ctx context.Context, sysCtx *types.SystemContext) {
	defer conn.Close()

	client := &UnixSocketClient{conn: conn}

	for {
		msg, err := client.ReceiveMessage()
		if err != nil {
			log.Printf("failed to receive message: %v", err)
			return
		}

		switch msg.Type {
		case RequestFileIndex:
			// Send the complete filesystem index
			indexData, err := json.Marshal(index)
			if err != nil {
				client.SendMessage(IPCMessage{
					Type:  ResponseError,
					Error: fmt.Sprintf("failed to marshal index: %v", err),
				})
				continue
			}

			client.SendMessage(IPCMessage{
				Type: ResponseIndex,
				Data: indexData,
			})

		case RequestFileData:
			// Find and return file data
			fileData, err := getFileData(msg.Path, msg.Offset, msg.Size, img, imgSrc, ctx, sysCtx)
			if err != nil {
				client.SendMessage(IPCMessage{
					Type:  ResponseError,
					Error: fmt.Sprintf("failed to get file data: %v", err),
				})
				continue
			}

			client.SendMessage(IPCMessage{
				Type: ResponseData,
				Data: fileData,
			})

		case RequestComplete:
			return
		}
	}
}

// getFileData retrieves file data from the image layers
func getFileData(path string, offset int64, size int, img types.Image, imgSrc types.ImageSource, ctx context.Context, sysCtx *types.SystemContext) ([]byte, error) {
	layerInfos := img.LayerInfos()

	// Search through layers in reverse order (top layer first)
	for i := len(layerInfos) - 1; i >= 0; i-- {
		layer := layerInfos[i]

		blob, _, err := imgSrc.GetBlob(ctx, layer, none.NoCache)
		if err != nil {
			continue
		}

		uncompressedStream, _, err := compression.AutoDecompress(blob)
		if err != nil {
			blob.Close()
			continue
		}

		data, found, err := extractFileFromLayer(uncompressedStream, path, offset, size)
		uncompressedStream.Close()
		blob.Close()

		if err != nil {
			continue
		}
		if found {
			return data, nil
		}
	}

	return nil, fmt.Errorf("file not found: %s", path)
}

// extractFileFromLayer searches for a file in a layer and returns its data
func extractFileFromLayer(stream io.Reader, targetPath string, offset int64, size int) ([]byte, bool, error) {
	tr := tar.NewReader(stream)

	var longName *string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}

		// Handle long filenames
		if hdr.Typeflag == 'L' {
			buf := bytes.NewBuffer(make([]byte, 0, hdr.Size))
			io.Copy(buf, tr)
			s := buf.String()
			longName = &s
			continue
		}

		if longName != nil {
			hdr.Name = *longName
			longName = nil
		}

		path := filepath.Clean("/" + hdr.Name)
		if (path == targetPath) && (hdr.Typeflag == tar.TypeReg) {
			// Found the file, read the requested portion
			if offset > 0 {
				io.CopyN(io.Discard, tr, offset)
			}

			readSize := size
			if size == 0 || int64(size) > hdr.Size-offset {
				readSize = int(hdr.Size - offset)
			}

			data := make([]byte, readSize)
			_, err := io.ReadFull(tr, data)
			if err != nil && err != io.EOF {
				return nil, false, err
			}

			return data, true, nil
		}

		// Skip this file
		if hdr.Size > 0 {
			io.Copy(io.Discard, tr)
		}
	}

	return nil, false, nil
}
