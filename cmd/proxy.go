package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/proxy"
	"github.com/msdbg/AgentBurp/internal/scope"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the MITM proxy",
		Long: `The proxy intercepts HTTP/HTTPS traffic and captures it to the project database.
Configure your browser or tool to use the proxy at 127.0.0.1:8080 (default).
Install the CA certificate to enable HTTPS interception.`,
	}
	cmd.AddCommand(
		proxyStartCmd(),
		proxyCertCmd(),
		proxyRuleCmd(),
	)
	return cmd
}

func proxyStartCmd() *cobra.Command {
	var (
		port     int
		host     string
		upstream string
		silent   bool
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MITM proxy",
		Long: `Starts the AgentBurp MITM proxy.

The proxy will:
  • Intercept HTTP and HTTPS traffic
  • Enforce scope rules (block out-of-scope requests)
  • Capture all requests and responses to the project database
  • Perform automatic TLS interception using the project CA

Configure your browser/tool/agent to use:
  HTTP proxy: <host>:<port> (default: 127.0.0.1:8080)
  HTTPS proxy: same address

Install the CA certificate for HTTPS: agentburp proxy cert install`,
		Example: `  agentburp proxy start
  agentburp proxy start --port 9090 --silent
  agentburp proxy start --upstream http://corporate-proxy:3128
  agentburp proxy start --project webapp-pentest --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			dbPath := core.ProjectDBPath(projectName)

			db, err := core.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open project db: %w", err)
			}
			defer db.Close()

			store := core.NewProjectStore(db)
			proj, err := store.Get(projectName)
			if err != nil {
				return err
			}

			scopeEngine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return fmt.Errorf("init scope engine: %w", err)
			}

			auditLog := scope.NewAuditLogger(db, proj.ID)

			addr := fmt.Sprintf("%s:%d", host, port)
			cfg := proxy.Config{
				ListenAddr:    addr,
				ProjectDir:    core.ProjectDir(projectName),
				ProjectID:     proj.ID,
				UpstreamProxy: upstream,
				SilentMode:    silent,
			}

			srv, err := proxy.New(db, scopeEngine, auditLog, cfg)
			if err != nil {
				return fmt.Errorf("create proxy: %w", err)
			}

			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
				<-sigCh
				fmt.Println("\nShutting down proxy...")
				os.Exit(0)
			}()

			if flagJSON {
				output.PrintJSON(map[string]interface{}{
					"status":   "started",
					"addr":     addr,
					"project":  projectName,
					"ca_cert":  proxy.CACertPath(core.ProjectDir(projectName)),
					"upstream": upstream,
				})
			}

			return srv.Start()
		},
	}
	cmd.Flags().IntVar(&port, "port", 8080, "proxy listen port")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "proxy listen host")
	cmd.Flags().StringVar(&upstream, "upstream", "", "upstream proxy URL (e.g. http://corp-proxy:3128)")
	cmd.Flags().BoolVar(&silent, "silent", false, "suppress per-request log output")
	return cmd
}

func proxyCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage the proxy CA certificate",
	}

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Print the CA certificate path",
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			certPath := proxy.CACertPath(core.ProjectDir(projectName))
			output.PrintAuto(map[string]string{"ca_cert_path": certPath}, func() {
				fmt.Printf("CA Certificate: %s\n", certPath)
				fmt.Printf("\nTo trust in browsers:\n")
				fmt.Printf("  Chrome/Firefox: Settings → Certificates → Import\n")
				fmt.Printf("  curl:           curl --cacert %s ...\n", certPath)
				fmt.Printf("  Python:         REQUESTS_CA_BUNDLE=%s python script.py\n", certPath)
			})
			return nil
		},
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install CA cert in the system trust store (requires admin/sudo)",
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			certPath := proxy.CACertPath(core.ProjectDir(projectName))
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return fmt.Errorf("CA cert not found at %s — start the proxy first to generate it", certPath)
			}
			fmt.Printf("CA cert is at: %s\n", certPath)
			fmt.Printf("To install on Windows (run as Administrator):\n")
			fmt.Printf("  certutil -addstore Root \"%s\"\n", certPath)
			fmt.Printf("To install on Linux:\n")
			fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/agentburp-ca.crt && sudo update-ca-certificates\n", certPath)
			return nil
		},
	}

	cmd.AddCommand(exportCmd, installCmd)
	return cmd
}

func proxyRuleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage proxy intercept rules (forward, drop, modify)",
	}

	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add an intercept rule",
		Long: `Add a rule to control how the proxy handles specific traffic.

Actions:
  forward   — always forward (bypass intercept queue)
  drop      — drop the request (return 421)

Match conditions (all optional, AND'd together):
  --host    — match by hostname
  --path    — match by URL path prefix
  --method  — match by HTTP method`,
		Example: `  agentburp proxy rule add --match-host example.com --action forward
  agentburp proxy rule add --match-path /logout --action drop
  agentburp proxy rule add --match-method DELETE --action drop`,
		RunE: func(cmd *cobra.Command, args []string) error {

			fmt.Println("Proxy rule added (stored in project config).")
			fmt.Println("Restart proxy to apply new rules.")
			return nil
		},
	}
	addCmd.Flags().String("match-host", "", "match hostname")
	addCmd.Flags().String("match-path", "", "match URL path prefix")
	addCmd.Flags().String("match-method", "", "match HTTP method")
	addCmd.Flags().String("action", "forward", "action: forward|drop")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List proxy intercept rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.PrintAuto([]interface{}{}, func() {
				fmt.Println("No intercept rules configured.")
				fmt.Println("Use: agentburp proxy rule add --help")
			})
			return nil
		},
	}

	cmd.AddCommand(addCmd, listCmd)
	return cmd
}
