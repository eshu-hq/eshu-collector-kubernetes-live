// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"os"
	"strings"
	"testing"
)

// TestDockerfileMatchesSeedExpectations pins the Dockerfile lines the seed
// path depends on: the build must copy the static binary to
// /usr/local/bin/collector (the path the IaC seed step calls), and the
// runtime must default to serving one claim over stdio.
func TestDockerfileMatchesSeedExpectations(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"COPY --from=build /out/collector /usr/local/bin/collector",
		`ENTRYPOINT ["/usr/local/bin/collector"]`,
		`CMD ["--sdk-stdio"]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile does not contain %q", want)
		}
	}
}

// TestCIBuildsTheReleaseImage keeps a broken Dockerfile from surfacing only
// at release: the CI workflow must build the image on every branch push and
// pull request.
func TestCIBuildsTheReleaseImage(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "docker build") || !strings.Contains(text, "./Dockerfile") {
		t.Fatal("ci.yml runs no docker build of ./Dockerfile; a broken base digest, COPY path, or ENTRYPOINT surfaces only at release")
	}
}
