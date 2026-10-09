package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/security"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

// runPairCode pairs by phone number + linking code, for when the only screen
// you have is the phone that owns the WhatsApp account.
func runPairCode(storeDir string, redactor *security.Redactor, args []string) int {
	fs := flag.NewFlagSet("pair-code", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: whatsapp-mcp [-store DIR] pair-code <phone, international digits, e.g. 972501234567>")
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	lock, err := store.TryLock(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v (stop the serve service first)\n", err)
		return 1
	}
	defer lock.Release()

	st, err := store.Open(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		return 1
	}
	defer st.Close()

	c, err := client.New(ctx, client.Config{
		StoreDir: storeDir,
		Store:    st,
		Logger:   client.NewStderrLogger("Client", "INFO", true),
		Redactor: redactor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client: %v\n", err)
		return 1
	}
	defer c.Disconnect()

	err = c.PairCode(ctx, fs.Arg(0), func(code string) {
		fmt.Printf("\nLinking code: %s\n\n", code)
		fmt.Println("On your phone: WhatsApp > Linked devices > Link a device >")
		fmt.Println("'Link with phone number instead', then type the code. WhatsApp may")
		fmt.Println("also show a notification you can tap. You have about 2 minutes.")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pairing failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Paired. Start the service again.")
	return 0
}
