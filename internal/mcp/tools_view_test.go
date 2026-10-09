package mcp

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sealjay/mcp-whatsapp/internal/client"
)

func writeMedia(t *testing.T, data []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "chat", "msg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "photo.jpg")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func errText(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestViewImage_ReturnsImageAndDeletesCopy(t *testing.T) {
	data := pngBytes(t)
	p := writeMedia(t, data)
	res := viewImageResult(client.DownloadResult{Success: true, MediaType: "image", Path: p})
	if res.IsError {
		t.Fatalf("unexpected error: %s", errText(res))
	}
	if len(res.Content) != 2 {
		t.Fatalf("want text+image, got %d blocks", len(res.Content))
	}
	img, ok := res.Content[1].(mcp.ImageContent)
	if !ok {
		t.Fatalf("second block is %T", res.Content[1])
	}
	if img.MIMEType != "image/png" {
		t.Errorf("mime %q", img.MIMEType)
	}
	if got, _ := base64.StdEncoding.DecodeString(img.Data); !bytes.Equal(got, data) {
		t.Error("image bytes differ")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("decrypted copy left on disk: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Errorf("empty message directory left behind: %v", err)
	}
}

func TestViewImage_DocumentThatIsAnImage(t *testing.T) {
	p := writeMedia(t, pngBytes(t))
	if res := viewImageResult(client.DownloadResult{Success: true, MediaType: "document", Path: p}); res.IsError {
		t.Fatalf("image document rejected: %s", errText(res))
	}
}

func TestViewImage_Rejections(t *testing.T) {
	cases := []struct {
		name  string
		r     func(t *testing.T) client.DownloadResult
		wants string
	}{
		{"download failed", func(*testing.T) client.DownloadResult {
			return client.DownloadResult{Success: false, Message: "failed to download media: 404"}
		}, "could not fetch"},
		{"video", func(t *testing.T) client.DownloadResult {
			return client.DownloadResult{Success: true, MediaType: "video", Path: writeMedia(t, []byte("x"))}
		}, "not an image"},
		{"pdf document", func(t *testing.T) client.DownloadResult {
			return client.DownloadResult{Success: true, MediaType: "document", Path: writeMedia(t, []byte("%PDF-1.4\n..."))}
		}, "unsupported format"},
		{"too large", func(t *testing.T) client.DownloadResult {
			big := append(pngBytes(t), make([]byte, viewImageMaxBytes)...)
			return client.DownloadResult{Success: true, MediaType: "image", Path: writeMedia(t, big)}
		}, "too large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.r(t)
			res := viewImageResult(r)
			if !res.IsError || !strings.Contains(errText(res), c.wants) {
				t.Fatalf("want error containing %q, got %+v", c.wants, res)
			}
			if r.Path != "" {
				if _, err := os.Stat(r.Path); !os.IsNotExist(err) {
					t.Errorf("file left on disk after rejection")
				}
			}
		})
	}
}

func TestRestrictedServer_ViewImageOnlyWhenAllowed(t *testing.T) {
	without := NewRestrictedServer(nil, nil, testPolicy(t, `"list_messages"`), nil)
	if without.MCP().GetTool("view_image") != nil {
		t.Fatal("view_image exposed without being in the policy")
	}
	with := NewRestrictedServer(nil, nil, testPolicy(t, `"list_messages","view_image"`), nil)
	tool := with.MCP().GetTool("view_image")
	if tool == nil {
		t.Fatal("view_image missing although allowed")
	}
	if ro := tool.Tool.Annotations.ReadOnlyHint; ro == nil || !*ro {
		t.Error("view_image not marked read-only")
	}
	if p := tool.Tool.InputSchema.Properties; p["output_path"] != nil {
		t.Error("view_image must not accept a path")
	}
	if with.MCP().GetTool("download_media") != nil {
		t.Error("download_media exposed")
	}
}
