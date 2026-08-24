package importer

import (
	"encoding/json"
	"strings"
	"testing"
)

const openapi3YAML = `
openapi: 3.0.3
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        "200":
          description: ok
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                active:
                  type: boolean
      responses:
        "201":
          description: created
  /users/{id}:
    get:
      summary: Get user
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: ok
`

const swagger2JSON = `{
  "swagger": "2.0",
  "info": {"title": "Legacy", "version": "1.0"},
  "host": "legacy.example.com",
  "basePath": "/api",
  "schemes": ["https"],
  "paths": {
    "/pets/{petId}": {
      "get": {
        "summary": "Get pet",
        "parameters": [
          {"name": "petId", "in": "path", "required": true, "type": "integer"}
        ]
      }
    }
  }
}`

func TestParseOpenAPI3(t *testing.T) {
	plan, err := ParseOpenAPI("test.yaml", []byte(openapi3YAML))
	if err != nil {
		t.Fatal(err)
	}
	if plan.BaseURL != "https://api.example.com/v1" {
		t.Errorf("base URL wrong: %s", plan.BaseURL)
	}
	if len(plan.Requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(plan.Requests))
	}
	byMethod := map[string]string{}
	for _, r := range plan.Requests {
		byMethod[r.Method+" "+r.URL] = r.Source
	}
	if _, ok := byMethod["GET https://api.example.com/v1/users?limit=FUZZ"]; !ok {
		t.Errorf("GET users with query param missing: %v", plan.Requests[0].URL)
	}
	if _, ok := byMethod["GET https://api.example.com/v1/users/1"]; !ok {
		t.Error("path param substitution missing")
	}
	for _, r := range plan.Requests {
		if r.Method == "POST" {
			if !strings.Contains(string(r.Body), `"username"`) {
				t.Errorf("request body missing schema fields: %s", r.Body)
			}
		}
	}
}

func TestParseSwagger2(t *testing.T) {
	plan, err := ParseOpenAPI("swagger.json", []byte(swagger2JSON))
	if err != nil {
		t.Fatal(err)
	}
	if plan.BaseURL != "https://legacy.example.com/api" {
		t.Errorf("base URL wrong: %s", plan.BaseURL)
	}
	if len(plan.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(plan.Requests))
	}
	if plan.Requests[0].URL != "https://legacy.example.com/api/pets/1" {
		t.Errorf("swagger path substitution wrong: %s", plan.Requests[0].URL)
	}
}

func TestParseOpenAPIInvalid(t *testing.T) {
	if _, err := ParseOpenAPI("bad.yaml", []byte("openapi: 3.0.0\npaths: {}\n")); err == nil {
		t.Error("empty paths should fail")
	}
	if _, err := ParseOpenAPI("bad.yaml", []byte("not-a-spec: true\n")); err == nil {
		t.Error("unknown spec should fail")
	}
}

const postmanJSON = `{
  "info": {"name": "Demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [
    {
      "name": "Users",
      "item": [
        {
          "name": "List Users",
          "request": {
            "method": "GET",
            "url": {"raw": "http://127.0.0.1:8080/api/users?limit=10"},
            "header": [{"key": "X-Api-Key", "value": "k123"}]
          }
        }
      ]
    },
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "url": {"raw": "http://127.0.0.1:8080/api/login"},
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "body": {
          "mode": "raw",
          "raw": "{\"username\":\"admin\",\"password\":\"s3cret\"}"
        }
      }
    }
  ]
}`

func TestParsePostman(t *testing.T) {
	plan, err := ParsePostman("collection.json", []byte(postmanJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(plan.Requests))
	}
	var list, login RequestSpec
	for _, r := range plan.Requests {
		if strings.HasSuffix(r.URL, "/api/users?limit=10") {
			list = r
		}
		if strings.HasSuffix(r.URL, "/api/login") {
			login = r
		}
	}
	if list.Method != "GET" || len(list.Headers) != 1 || list.Headers[0] != "X-Api-Key: k123" {
		t.Errorf("list request wrong: %+v", list)
	}
	if login.Method != "POST" || !strings.Contains(string(login.Body), "s3cret") {
		t.Errorf("login request wrong: %+v body=%s", login, login.Body)
	}
	if login.Source != "Login" {
		t.Errorf("request source should be item name: %s", login.Source)
	}
}

func TestSetBaseURL(t *testing.T) {
	plan, err := ParsePostman("c.json", []byte(postmanJSON))
	if err != nil {
		t.Fatal(err)
	}
	plan.SetBaseURL("http://target.local")
	if !strings.HasPrefix(plan.Requests[0].URL, "http://target.local") {
		t.Errorf("base URL override failed: %s", plan.Requests[0].URL)
	}
}

func TestPlanJSONRoundtrip(t *testing.T) {
	plan, err := ParseOpenAPI("test.yaml", []byte(openapi3YAML))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "api.example.com") {
		t.Error("plan JSON missing requests")
	}
}
