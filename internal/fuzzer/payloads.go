package fuzzer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type PayloadSet struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

func Wordlist(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	var values []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist: %w", err)
	}
	return values, nil
}

func Numbers(from, to, step int) ([]string, error) {
	if step <= 0 {
		return nil, fmt.Errorf("step must be >= 1")
	}
	var values []string
	if from <= to {
		for n := from; n <= to; n += step {
			values = append(values, strconv.Itoa(n))
		}
	} else {
		for n := from; n >= to; n -= step {
			values = append(values, strconv.Itoa(n))
		}
	}
	return values, nil
}

var MutationPayloads = []string{
	"'",
	"''",
	`"`,
	"\"\"",
	"' OR '1'='1",
	"' OR 1=1--",
	"1 OR 1=1",
	"'; DROP TABLE users;--",
	"1 AND 1=1",
	"1 AND 1=2",
	"<script>alert(1)</script>",
	"<script>alert(document.domain)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"javascript:alert(1)",
	"../",
	"../../",
	"..\\..\\",
	"%00",
	"%0a",
	"%0d",
	"/etc/passwd",
	"C:\\windows\\win.ini",
	"../../etc/passwd",
	"{{7*7}}",
	"${7*7}",
	"<%= 7*7 %>",
	"#{7*7}",
	"__proto__",
	"constructor.prototype",
	"a[0]=1",
	"-1",
	"0",
	"1e9",
	"2147483647",
	"4294967295",
	"9223372036854775807",
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	strings.Repeat("a", 64),
	"true",
	"false",
	"null",
	"undefined",
	"[]",
	"{}",
	"@example.com",
	"file:///etc/passwd",
	"http://evil.com/",
	"//evil.com",
	"admin",
	"Admin",
	"ADMIN",
	"root",
	"debug=true",
	"enabled=true",
	"role=admin",
	"isAdmin=1",
	"status=active",
	"id=1 OR 1=1",
	"1,1",
	"1;2",
	"§§",
	"\x00",
	"\x01",
	"\x7f",
	"\xff",
}

func Mutations() []string {
	return append([]string{}, MutationPayloads...)
}
