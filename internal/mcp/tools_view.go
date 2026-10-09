package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sealjay/mcp-whatsapp/internal/client"
)

// viewImageMaxBytes caps the image handed to the model. WhatsApp compresses
// photos well below this; the cap keeps the base64 payload under the 5 MB
// per-image limit Claude applies.
const viewImageMaxBytes = 3_500_000

// viewableImageTypes are the formats Claude can read.
var viewableImageTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// -- view_image ---------------------------------------------------------------
//
// view_image is this fork's read-only replacement for download_media: it
// returns an image so the model can read it (invitations, timetables,
// notices) and keeps nothing behind. It takes no path argument, writes
// nowhere the caller chooses, and deletes the decrypted copy as soon as it
// has been read. Like every other read, it sends nothing to WhatsApp that
// another person can see (no read receipt, no notification).

type viewImageArgs struct {
	MessageID string `json:"message_id"`
	ChatJID   string `json:"chat_jid"`
}

func (s *Server) registerViewImage() {
	tool := mcp.NewTool("view_image",
		mcp.WithDescription("Show the picture attached to a WhatsApp message so you can read it (invitations, timetables, school notices, screenshots). Works for photos and for documents that are images; PDFs, videos and voice notes are not supported. Read-only: nothing is sent, the sender is not notified, and no copy is kept on the server. Find candidates with list_messages: media lines look like `[image - Message ID: <id> - Chat JID: <jid>]`; pass those two values. Very old media may no longer be available from WhatsApp."),
		mcp.WithString("message_id", mcp.Required(), mcp.Description("the Message ID from list_messages")),
		mcp.WithString("chat_jid", mcp.Required(), mcp.Description(jidDesc)),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a viewImageArgs) (*mcp.CallToolResult, error) {
		if a.MessageID == "" || a.ChatJID == "" {
			return mcp.NewToolResultError("message_id and chat_jid are required"), nil
		}
		if s.client == nil {
			return mcp.NewToolResultError("WhatsApp client unavailable"), nil
		}
		return viewImageResult(s.client.Download(ctx, a.MessageID, a.ChatJID, "")), nil
	}))
}

// viewImageResult turns a Download result into an image tool result and
// removes the decrypted file (and its now-empty message directory) whatever
// the outcome.
func viewImageResult(r client.DownloadResult) *mcp.CallToolResult {
	if r.Success && r.Path != "" {
		defer func() {
			_ = os.Remove(r.Path)
			_ = os.Remove(filepath.Dir(r.Path)) // only succeeds if empty
		}()
	}
	if !r.Success {
		return mcp.NewToolResultError("could not fetch the image: " + r.Message)
	}
	if r.MediaType != "image" && r.MediaType != "document" {
		return mcp.NewToolResultError(fmt.Sprintf("this message has %s media, not an image", r.MediaType))
	}
	info, err := os.Stat(r.Path)
	if err != nil {
		return mcp.NewToolResultError("could not read the image")
	}
	if info.Size() > viewImageMaxBytes {
		return mcp.NewToolResultError(fmt.Sprintf("image is too large to show (%d KB)", info.Size()/1024))
	}
	data, err := os.ReadFile(r.Path)
	if err != nil {
		return mcp.NewToolResultError("could not read the image")
	}
	mimeType := sniffResourceMIME(data, r.MediaType)
	if !viewableImageTypes[mimeType] {
		return mcp.NewToolResultError(fmt.Sprintf("unsupported format %s (only photos and image files can be shown)", mimeType))
	}
	return &mcp.CallToolResult{Content: []mcp.Content{
		mcp.NewTextContent(fmt.Sprintf("%s, %d KB", mimeType, len(data)/1024)),
		mcp.NewImageContent(base64.StdEncoding.EncodeToString(data), mimeType),
	}}
}
