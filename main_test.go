package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
)

func TestSplitWithEscapes(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		delimiter string
		expected  []string
	}{
		{
			name:      "simple comma split",
			input:     "a,b,c",
			delimiter: ",",
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "escaped comma",
			input:     "a,b\\,c,d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "email with escaped comma",
			input:     "user@domain.com\\,backup,*@example.org",
			delimiter: ",",
			expected:  []string{"user@domain.com,backup", "*@example.org"},
		},
		{
			name:      "glob pattern with escaped comma",
			input:     "admin.*@company\\,inc.*,*@example.com",
			delimiter: ",",
			expected:  []string{"admin.*@company,inc.*", "*@example.com"},
		},
		{
			name:      "empty string",
			input:     "",
			delimiter: ",",
			expected:  []string{},
		},
		{
			name:      "single item",
			input:     "single",
			delimiter: ",",
			expected:  []string{"single"},
		},
		{
			name:      "no escapes needed",
			input:     "user1@example.com,user2@test.org",
			delimiter: ",",
			expected:  []string{"user1@example.com", "user2@test.org"},
		},
		{
			name:      "multiple escaped commas",
			input:     "a\\,b\\,c,d,e\\,f",
			delimiter: ",",
			expected:  []string{"a,b,c", "d", "e,f"},
		},
		{
			name:      "whitespace trimming",
			input:     "a , b\\,c , d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "different delimiter",
			input:     "a;b\\;c;d",
			delimiter: ";",
			expected:  []string{"a", "b;c", "d"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitWithEscapes(tc.input, tc.delimiter)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseAttributeMap(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string][]string{},
		},
		{
			name:  "single key-value pair",
			input: "/groups=admin",
			expected: map[string][]string{
				"/groups": {"admin"},
			},
		},
		{
			name:  "multiple values for same key",
			input: "/groups=admin,/groups=users",
			expected: map[string][]string{
				"/groups": {"admin", "users"},
			},
		},
		{
			name:  "multiple keys",
			input: "/groups=admin,/department=engineering",
			expected: map[string][]string{
				"/groups":     {"admin"},
				"/department": {"engineering"},
			},
		},
		{
			name:  "nested key with JSON pointer",
			input: "/org/team=platform",
			expected: map[string][]string{
				"/org/team": {"platform"},
			},
		},
		{
			name:  "glob pattern value",
			input: "/groups=*-admins,/email=*@example.com",
			expected: map[string][]string{
				"/groups": {"*-admins"},
				"/email":  {"*@example.com"},
			},
		},
		{
			name:  "whitespace trimming",
			input: " /groups = admin , /role = editor ",
			expected: map[string][]string{
				"/groups": {"admin"},
				"/role":   {"editor"},
			},
		},
		{
			name:     "invalid format - no equals sign",
			input:    "invalid",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty key",
			input:    "=value",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty value",
			input:    "/key=",
			expected: map[string][]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAttributeMap(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseHeaderMapping(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single mapping",
			input: "/email:X-Forwarded-Email",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
			},
		},
		{
			name:  "multiple mappings",
			input: "/email:X-Forwarded-Email,/preferred_username:X-Forwarded-User",
			expected: map[string]string{
				"/email":              "X-Forwarded-Email",
				"/preferred_username": "X-Forwarded-User",
			},
		},
		{
			name:  "nested JSON pointer",
			input: "/org/team:X-Forwarded-Team",
			expected: map[string]string{
				"/org/team": "X-Forwarded-Team",
			},
		},
		{
			name:  "whitespace trimming",
			input: " /email : X-Forwarded-Email , /sub : X-Forwarded-Sub ",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
				"/sub":   "X-Forwarded-Sub",
			},
		},
		{
			name:     "no colon - skipped",
			input:    "invalid",
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseHeaderMapping(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestGetEnvWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      string
		expected string
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set",
			key:      "TEST_KEY_NOT_SET",
			def:      "default_value",
			expected: "default_value",
			setEnv:   false,
		},
		{
			name:     "env var set",
			key:      "TEST_KEY_SET",
			def:      "default_value",
			expected: "env_value",
			setEnv:   true,
			envValue: "env_value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestGetEnvBoolWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      bool
		expected bool
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set - default false",
			key:      "TEST_BOOL_NOT_SET",
			def:      false,
			expected: false,
			setEnv:   false,
		},
		{
			name:     "env var not set - default true",
			key:      "TEST_BOOL_NOT_SET2",
			def:      true,
			expected: true,
			setEnv:   false,
		},
		{
			name:     "env var set to 'true'",
			key:      "TEST_BOOL_TRUE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "true",
		},
		{
			name:     "env var set to 'TRUE'",
			key:      "TEST_BOOL_TRUE_UPPER",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "TRUE",
		},
		{
			name:     "env var set to '1'",
			key:      "TEST_BOOL_ONE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "1",
		},
		{
			name:     "env var set to 'false'",
			key:      "TEST_BOOL_FALSE",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "false",
		},
		{
			name:     "env var set to '0'",
			key:      "TEST_BOOL_ZERO",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "0",
		},
		{
			name:     "env var set to other value",
			key:      "TEST_BOOL_OTHER",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "other",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvBoolWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %t, got %t", tc.expected, result)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "trims values",
			input:    " user1@example.com, user2@example.com ",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "keeps empty values",
			input:    "a,,b",
			expected: []string{"a", "", "b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitCSV(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestNewRootCommand_HTTPStreamingOnlyFlag(t *testing.T) {
	t.Setenv("HTTP_STREAMING_ONLY", "")

	var streamingOnly bool
	var receivedTargets []string
	runner := proxyRunnerFunc(func(listen string,
		tlsListen string,
		autoTLS bool,
		tlsHost string,
		tlsDirectoryURL string,
		tlsAcceptTOS bool,
		tlsCertFile string,
		tlsKeyFile string,
		dataPath string,
		repositoryBackend string,
		repositoryDSN string,
		externalURL string,
		googleClientID string,
		googleClientSecret string,
		googleAllowedUsers []string,
		googleAllowedWorkspaces []string,
		githubURL string,
		githubAPIURL string,
		githubClientID string,
		githubClientSecret string,
		githubAllowedUsers []string,
		githubAllowedOrgs []string,
		oidcConfigurationURL string,
		oidcClientID string,
		oidcClientSecret string,
		oidcScopes []string,
		oidcUserIDField string,
		oidcProviderName string,
		oidcAllowedUsers []string,
		oidcAllowedUsersGlob []string,
		oidcAllowedAttributes map[string][]string,
		oidcAllowedAttributesGlob map[string][]string,
		noProviderAutoSelect bool,
		password string,
		passwordHash string,
		trustedProxy []string,
		proxyHeaders []string,
		proxyBearerToken string,
		forwardAuthorizationHeader bool,
		proxyTarget []string,
		httpStreamingOnly bool,
		headerMapping map[string]string,
		headerMappingBase string,
		authorizeServerName string,
		authorizeLogo string,
		authorizeBanner string,
		authorizeFooter string,
		tokenLifespans idp.TokenLifespans,
	) error {
		streamingOnly = httpStreamingOnly
		receivedTargets = proxyTarget
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"--http-streaming-only", "http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !streamingOnly {
		t.Fatalf("expected httpStreamingOnly to be true when flag is set")
	}
	if len(receivedTargets) != 1 || receivedTargets[0] != "http://backend" {
		t.Fatalf("expected proxyTarget to receive CLI args, got %v", receivedTargets)
	}
}

func TestNewRootCommand_HTTPStreamingOnlyFromEnv(t *testing.T) {
	t.Setenv("HTTP_STREAMING_ONLY", "true")

	var streamingOnly bool
	runner := proxyRunnerFunc(func(listen string,
		tlsListen string,
		autoTLS bool,
		tlsHost string,
		tlsDirectoryURL string,
		tlsAcceptTOS bool,
		tlsCertFile string,
		tlsKeyFile string,
		dataPath string,
		repositoryBackend string,
		repositoryDSN string,
		externalURL string,
		googleClientID string,
		googleClientSecret string,
		googleAllowedUsers []string,
		googleAllowedWorkspaces []string,
		githubURL string,
		githubAPIURL string,
		githubClientID string,
		githubClientSecret string,
		githubAllowedUsers []string,
		githubAllowedOrgs []string,
		oidcConfigurationURL string,
		oidcClientID string,
		oidcClientSecret string,
		oidcScopes []string,
		oidcUserIDField string,
		oidcProviderName string,
		oidcAllowedUsers []string,
		oidcAllowedUsersGlob []string,
		oidcAllowedAttributes map[string][]string,
		oidcAllowedAttributesGlob map[string][]string,
		noProviderAutoSelect bool,
		password string,
		passwordHash string,
		trustedProxy []string,
		proxyHeaders []string,
		proxyBearerToken string,
		forwardAuthorizationHeader bool,
		proxyTarget []string,
		httpStreamingOnly bool,
		headerMapping map[string]string,
		headerMappingBase string,
		authorizeServerName string,
		authorizeLogo string,
		authorizeBanner string,
		authorizeFooter string,
		tokenLifespans idp.TokenLifespans,
	) error {
		streamingOnly = httpStreamingOnly
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !streamingOnly {
		t.Fatalf("expected httpStreamingOnly to default to true from env var")
	}
}

func TestNewRootCommand_ForwardAuthorizationFlag(t *testing.T) {
	t.Setenv("PROXY_FORWARD_AUTHORIZATION", "")

	var forwardAuthorization bool
	runner := proxyRunnerFunc(func(listen string,
		tlsListen string,
		autoTLS bool,
		tlsHost string,
		tlsDirectoryURL string,
		tlsAcceptTOS bool,
		tlsCertFile string,
		tlsKeyFile string,
		dataPath string,
		repositoryBackend string,
		repositoryDSN string,
		externalURL string,
		googleClientID string,
		googleClientSecret string,
		googleAllowedUsers []string,
		googleAllowedWorkspaces []string,
		githubURL string,
		githubAPIURL string,
		githubClientID string,
		githubClientSecret string,
		githubAllowedUsers []string,
		githubAllowedOrgs []string,
		oidcConfigurationURL string,
		oidcClientID string,
		oidcClientSecret string,
		oidcScopes []string,
		oidcUserIDField string,
		oidcProviderName string,
		oidcAllowedUsers []string,
		oidcAllowedUsersGlob []string,
		oidcAllowedAttributes map[string][]string,
		oidcAllowedAttributesGlob map[string][]string,
		noProviderAutoSelect bool,
		password string,
		passwordHash string,
		trustedProxy []string,
		proxyHeaders []string,
		proxyBearerToken string,
		forwardAuthorizationHeader bool,
		proxyTarget []string,
		httpStreamingOnly bool,
		headerMapping map[string]string,
		headerMappingBase string,
		authorizeServerName string,
		authorizeLogo string,
		authorizeBanner string,
		authorizeFooter string,
		tokenLifespans idp.TokenLifespans,
	) error {
		forwardAuthorization = forwardAuthorizationHeader
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"--proxy-forward-authorization", "http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !forwardAuthorization {
		t.Fatalf("expected forwardAuthorizationHeader to be true when flag is set")
	}
}

func TestNewRootCommand_ForwardAuthorizationFromEnv(t *testing.T) {
	t.Setenv("PROXY_FORWARD_AUTHORIZATION", "true")

	var forwardAuthorization bool
	runner := proxyRunnerFunc(func(listen string,
		tlsListen string,
		autoTLS bool,
		tlsHost string,
		tlsDirectoryURL string,
		tlsAcceptTOS bool,
		tlsCertFile string,
		tlsKeyFile string,
		dataPath string,
		repositoryBackend string,
		repositoryDSN string,
		externalURL string,
		googleClientID string,
		googleClientSecret string,
		googleAllowedUsers []string,
		googleAllowedWorkspaces []string,
		githubURL string,
		githubAPIURL string,
		githubClientID string,
		githubClientSecret string,
		githubAllowedUsers []string,
		githubAllowedOrgs []string,
		oidcConfigurationURL string,
		oidcClientID string,
		oidcClientSecret string,
		oidcScopes []string,
		oidcUserIDField string,
		oidcProviderName string,
		oidcAllowedUsers []string,
		oidcAllowedUsersGlob []string,
		oidcAllowedAttributes map[string][]string,
		oidcAllowedAttributesGlob map[string][]string,
		noProviderAutoSelect bool,
		password string,
		passwordHash string,
		trustedProxy []string,
		proxyHeaders []string,
		proxyBearerToken string,
		forwardAuthorizationHeader bool,
		proxyTarget []string,
		httpStreamingOnly bool,
		headerMapping map[string]string,
		headerMappingBase string,
		authorizeServerName string,
		authorizeLogo string,
		authorizeBanner string,
		authorizeFooter string,
		tokenLifespans idp.TokenLifespans,
	) error {
		forwardAuthorization = forwardAuthorizationHeader
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !forwardAuthorization {
		t.Fatalf("expected forwardAuthorizationHeader to default to true from env var")
	}
}

func runWithLifespans(t *testing.T, args []string) (idp.TokenLifespans, error) {
	t.Helper()
	var got idp.TokenLifespans
	runner := proxyRunnerFunc(func(listen, tlsListen string, autoTLS bool, tlsHost, tlsDirectoryURL string, tlsAcceptTOS bool,
		tlsCertFile, tlsKeyFile, dataPath, repositoryBackend, repositoryDSN, externalURL, googleClientID, googleClientSecret string,
		googleAllowedUsers, googleAllowedWorkspaces []string, githubURL, githubAPIURL, githubClientID, githubClientSecret string,
		githubAllowedUsers, githubAllowedOrgs []string, oidcConfigurationURL, oidcClientID, oidcClientSecret string, oidcScopes []string,
		oidcUserIDField, oidcProviderName string, oidcAllowedUsers, oidcAllowedUsersGlob []string,
		oidcAllowedAttributes, oidcAllowedAttributesGlob map[string][]string, noProviderAutoSelect bool, password, passwordHash string,
		trustedProxy, proxyHeaders []string, proxyBearerToken string, forwardAuthorizationHeader bool, proxyTarget []string,
		httpStreamingOnly bool, headerMapping map[string]string, headerMappingBase, authorizeServerName, authorizeLogo,
		authorizeBanner, authorizeFooter string, tokenLifespans idp.TokenLifespans,
	) error {
		got = tokenLifespans
		return nil
	})
	cmd := newRootCommand(runner)
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return got, err
}

func TestNewRootCommand_TokenLifespans(t *testing.T) {
	t.Run("defaults match upstream", func(t *testing.T) {
		t.Setenv("ACCESS_TOKEN_LIFESPAN", "")
		t.Setenv("REFRESH_TOKEN_LIFESPAN", "")
		t.Setenv("AUTHORIZE_CODE_LIFESPAN", "")
		got, err := runWithLifespans(t, []string{"http://backend"})
		if err != nil {
			t.Fatal(err)
		}
		want := idp.TokenLifespans{AccessToken: 24 * time.Hour, RefreshToken: 720 * time.Hour, AuthorizeCode: 15 * time.Minute}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("from env", func(t *testing.T) {
		t.Setenv("ACCESS_TOKEN_LIFESPAN", "2m")
		t.Setenv("REFRESH_TOKEN_LIFESPAN", "5m")
		t.Setenv("AUTHORIZE_CODE_LIFESPAN", "30s")
		got, err := runWithLifespans(t, []string{"http://backend"})
		if err != nil {
			t.Fatal(err)
		}
		want := idp.TokenLifespans{AccessToken: 2 * time.Minute, RefreshToken: 5 * time.Minute, AuthorizeCode: 30 * time.Second}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("flags override env", func(t *testing.T) {
		t.Setenv("ACCESS_TOKEN_LIFESPAN", "2m")
		got, err := runWithLifespans(t, []string{"--access-token-lifespan", "1h", "--refresh-token-lifespan", "168h", "http://backend"})
		if err != nil {
			t.Fatal(err)
		}
		if got.AccessToken != time.Hour || got.RefreshToken != 168*time.Hour {
			t.Fatalf("got %+v", got)
		}
	})

	for _, bad := range [][]string{
		{"--access-token-lifespan", "1d"},
		{"--refresh-token-lifespan", "0s"},
		{"--authorize-code-lifespan", "-1m"},
	} {
		t.Run("rejects "+bad[0]+"="+bad[1], func(t *testing.T) {
			if _, err := runWithLifespans(t, append(bad, "http://backend")); err == nil {
				t.Fatalf("expected error for %v", bad)
			}
		})
	}
}
