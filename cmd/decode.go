package cmd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"

	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newDecodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Encode, decode, and hash utilities",
		Long: `Encode/decode/hash transformations for security testing.

All functions work on stdin or as direct arguments.
Use --json for machine-readable output.`,
	}

	// Decode subcommands
	cmd.AddCommand(decodeURLCmd())
	cmd.AddCommand(decodeBase64Cmd())
	cmd.AddCommand(decodeHTMLCmd())
	cmd.AddCommand(decodeHexCmd())
	cmd.AddCommand(decodeSmartCmd())

	// Encode subcommands
	encodeCmd := &cobra.Command{Use: "encode", Short: "Encode data"}
	encodeCmd.AddCommand(encodeURLCmd(), encodeBase64Cmd(), encodeHTMLCmd(), encodeHexCmd())
	cmd.AddCommand(encodeCmd)

	// Hash subcommand
	hashCmd := &cobra.Command{Use: "hash", Short: "Hash data"}
	hashCmd.AddCommand(hashMD5Cmd(), hashSHA1Cmd(), hashSHA256Cmd(), hashSHA512Cmd())
	cmd.AddCommand(hashCmd)

	return cmd
}

type decodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Method string `json:"method"`
}

func decodeURLCmd() *cobra.Command {
	return &cobra.Command{
		Use: "url <value>", Short: "URL-decode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			decoded, err := url.QueryUnescape(args[0])
			if err != nil {
				return fmt.Errorf("url decode: %w", err)
			}
			r := decodeResult{Input: args[0], Output: decoded, Method: "url-decode"}
			output.PrintAuto(r, func() { fmt.Println(decoded) })
			return nil
		},
	}
}

func decodeBase64Cmd() *cobra.Command {
	var urlSafe bool
	cmd := &cobra.Command{
		Use: "base64 <value>", Short: "Base64-decode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var b []byte
			var err error
			if urlSafe {
				b, err = base64.URLEncoding.DecodeString(args[0])
			} else {
				b, err = base64.StdEncoding.DecodeString(args[0])
				if err != nil {
					// Try RawStdEncoding (no padding)
					b, err = base64.RawStdEncoding.DecodeString(args[0])
				}
			}
			if err != nil {
				return fmt.Errorf("base64 decode: %w", err)
			}
			decoded := string(b)
			r := decodeResult{Input: args[0], Output: decoded, Method: "base64-decode"}
			output.PrintAuto(r, func() { fmt.Println(decoded) })
			return nil
		},
	}
	cmd.Flags().BoolVar(&urlSafe, "url-safe", false, "use URL-safe base64 alphabet")
	return cmd
}

func decodeHTMLCmd() *cobra.Command {
	return &cobra.Command{
		Use: "html <value>", Short: "HTML-decode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			decoded := html.UnescapeString(args[0])
			r := decodeResult{Input: args[0], Output: decoded, Method: "html-decode"}
			output.PrintAuto(r, func() { fmt.Println(decoded) })
			return nil
		},
	}
}

func decodeHexCmd() *cobra.Command {
	return &cobra.Command{
		Use: "hex <value>", Short: "Hex-decode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cleaned := strings.ReplaceAll(args[0], " ", "")
			cleaned = strings.ReplaceAll(cleaned, "%", "")
			b, err := hex.DecodeString(cleaned)
			if err != nil {
				return fmt.Errorf("hex decode: %w", err)
			}
			decoded := string(b)
			r := decodeResult{Input: args[0], Output: decoded, Method: "hex-decode"}
			output.PrintAuto(r, func() { fmt.Println(decoded) })
			return nil
		},
	}
}

func decodeSmartCmd() *cobra.Command {
	return &cobra.Command{
		Use: "smart <value>", Short: "Auto-detect encoding and decode",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v := args[0]
			method := "none"
			result := v

			// Try base64 first
			if b, err := base64.StdEncoding.DecodeString(v); err == nil && isPrintable(string(b)) {
				result = string(b)
				method = "base64"
			} else if b, err := base64.RawStdEncoding.DecodeString(v); err == nil && isPrintable(string(b)) {
				result = string(b)
				method = "base64-raw"
			} else if decoded, err := url.QueryUnescape(v); err == nil && decoded != v {
				result = decoded
				method = "url"
			} else if decoded := html.UnescapeString(v); decoded != v {
				result = decoded
				method = "html"
			}

			r := struct {
				Input          string `json:"input"`
				Output         string `json:"output"`
				DetectedMethod string `json:"detected_method"`
			}{Input: v, Output: result, DetectedMethod: method}
			output.PrintAuto(r, func() {
				fmt.Printf("Detected: %s\n%s\n", method, result)
			})
			return nil
		},
	}
}

func encodeURLCmd() *cobra.Command {
	return &cobra.Command{
		Use: "url <value>", Short: "URL-encode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoded := url.QueryEscape(args[0])
			r := decodeResult{Input: args[0], Output: encoded, Method: "url-encode"}
			output.PrintAuto(r, func() { fmt.Println(encoded) })
			return nil
		},
	}
}

func encodeBase64Cmd() *cobra.Command {
	return &cobra.Command{
		Use: "base64 <value>", Short: "Base64-encode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoded := base64.StdEncoding.EncodeToString([]byte(args[0]))
			r := decodeResult{Input: args[0], Output: encoded, Method: "base64-encode"}
			output.PrintAuto(r, func() { fmt.Println(encoded) })
			return nil
		},
	}
}

func encodeHTMLCmd() *cobra.Command {
	return &cobra.Command{
		Use: "html <value>", Short: "HTML-encode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoded := html.EscapeString(args[0])
			r := decodeResult{Input: args[0], Output: encoded, Method: "html-encode"}
			output.PrintAuto(r, func() { fmt.Println(encoded) })
			return nil
		},
	}
}

func encodeHexCmd() *cobra.Command {
	return &cobra.Command{
		Use: "hex <value>", Short: "Hex-encode a string",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			encoded := hex.EncodeToString([]byte(args[0]))
			r := decodeResult{Input: args[0], Output: encoded, Method: "hex-encode"}
			output.PrintAuto(r, func() { fmt.Println(encoded) })
			return nil
		},
	}
}

func hashMD5Cmd() *cobra.Command {
	return &cobra.Command{
		Use: "md5 <value>", Short: "MD5 hash",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := md5.Sum([]byte(args[0]))
			result := hex.EncodeToString(h[:])
			r := decodeResult{Input: args[0], Output: result, Method: "md5"}
			output.PrintAuto(r, func() { fmt.Println(result) })
			return nil
		},
	}
}

func hashSHA1Cmd() *cobra.Command {
	return &cobra.Command{
		Use: "sha1 <value>", Short: "SHA1 hash",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := sha1.Sum([]byte(args[0]))
			result := hex.EncodeToString(h[:])
			r := decodeResult{Input: args[0], Output: result, Method: "sha1"}
			output.PrintAuto(r, func() { fmt.Println(result) })
			return nil
		},
	}
}

func hashSHA256Cmd() *cobra.Command {
	return &cobra.Command{
		Use: "sha256 <value>", Short: "SHA-256 hash",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := sha256.Sum256([]byte(args[0]))
			result := hex.EncodeToString(h[:])
			r := decodeResult{Input: args[0], Output: result, Method: "sha256"}
			output.PrintAuto(r, func() { fmt.Println(result) })
			return nil
		},
	}
}

func hashSHA512Cmd() *cobra.Command {
	return &cobra.Command{
		Use: "sha512 <value>", Short: "SHA-512 hash",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h := sha512.Sum512([]byte(args[0]))
			result := hex.EncodeToString(h[:])
			r := decodeResult{Input: args[0], Output: result, Method: "sha512"}
			output.PrintAuto(r, func() { fmt.Println(result) })
			return nil
		},
	}
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return len(s) > 0
}
