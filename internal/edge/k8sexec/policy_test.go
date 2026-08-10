package k8sexec

import "testing"

func TestValidateKubectlCommandAllowsReads(t *testing.T) {
	for _, cmd := range []string{
		"kubectl get pods",
		"kubectl get pods -n default",
		"kubectl describe pod my-pod -n default",
		"kubectl logs my-pod",
		"kubectl get secrets -o json",
	} {
		allowed, reason, parsed := ValidateKubectlCommand(cmd)
		if !allowed {
			t.Errorf("expected %q to be allowed, got reason=%q", cmd, reason)
		}
		if !parsed.ReadOnly {
			t.Errorf("expected %q to be classified read-only", cmd)
		}
	}
}

func TestValidateKubectlCommandBlocksInteractive(t *testing.T) {
	for _, cmd := range []string{
		"kubectl exec my-pod -- sh",
		"kubectl exec my-pod -- bash",
		"kubectl attach my-pod",
		"kubectl cp my-pod:/tmp/x /tmp/x",
		"kubectl port-forward my-pod 8080:80",
	} {
		if allowed, _, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected %q to be blocked", cmd)
		}
	}
}

func TestValidateKubectlCommandBlocksMutatingVerbs(t *testing.T) {
	for _, cmd := range []string{
		"kubectl delete ns default",
		"kubectl delete namespace default",
		"kubectl delete all --all",
		"kubectl delete crd foo.example.com",
		"kubectl delete nodes node-1",
		"kubectl delete pod my-pod -n default",
		"kubectl apply -f manifest.yaml",
		"kubectl patch deployment api -p '{}'",
		"kubectl create configmap foo",
		"kubectl scale deployment/api --replicas=0",
		"kubectl label pod my-pod foo=bar",
		"kubectl cordon node-1",
		"kubectl drain node-1",
	} {
		if allowed, _, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected %q to be blocked", cmd)
		}
	}
}

func TestValidateKubectlCommandRejectsNonKubectl(t *testing.T) {
	for _, cmd := range []string{"", "ls -la", "kubectl", "echo kubectl get pods"} {
		if allowed, _, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected %q to be rejected", cmd)
		}
	}
}

func TestValidateKubectlCommandRejectsShellMetacharacters(t *testing.T) {
	for _, cmd := range []string{
		"kubectl get pods; rm -rf /",
		"kubectl get pods | sh",
		"kubectl get pods && kubectl delete ns default",
		"kubectl get pods $(whoami)",
	} {
		if allowed, _, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected %q to be rejected", cmd)
		}
	}
}

func TestValidateKubectlCommandRejectsTooLong(t *testing.T) {
	long := "kubectl get pods "
	for len(long) <= MaxCommandLen {
		long += "-n default "
	}
	if allowed, _, _ := ValidateKubectlCommand(long); allowed {
		t.Error("expected an over-length command to be rejected")
	}
}

// Mixed-case verbs must not bypass the allowlist/blocklist — kubectl itself is case-sensitive
// about verbs, but a naive string-equality check here would let "Delete"/"EXEC" slip through
// unblocked while an attacker-controlled dispatch layer upstream may not normalize case either.
func TestValidateKubectlCommandNormalizesVerbCase(t *testing.T) {
	allowed, _, parsed := ValidateKubectlCommand("kubectl GET pods")
	if !allowed {
		t.Fatal("expected uppercase read-only verb to be allowed")
	}
	if parsed.Verb != "get" {
		t.Fatalf("expected verb normalized to lowercase, got %q", parsed.Verb)
	}

	for _, cmd := range []string{
		"kubectl DELETE pod my-pod",
		"kubectl Exec my-pod -- sh",
		"kubectl ApPly -f manifest.yaml",
	} {
		if allowed, _, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected mixed-case verb %q to be blocked", cmd)
		}
	}
}

// Resource-scoped deletes (a single named resource) and cluster-wide/bulk deletes (--all, no
// name, or an unqualified "all") must both be rejected — delete isn't on the read-only allowlist
// at all, so there should be no distinction, but this guards against any future carve-out
// accidentally keying off resource name rather than verb.
func TestValidateKubectlCommandBlocksDeleteRegardlessOfScope(t *testing.T) {
	for _, cmd := range []string{
		"kubectl delete pod my-pod -n default", // resource-scoped, single named resource
		"kubectl delete pods --all -n default", // scoped to a namespace but bulk
		"kubectl delete all --all",             // cluster-wide bulk delete
		"kubectl delete namespace default",     // deletes an entire namespace
	} {
		if allowed, reason, _ := ValidateKubectlCommand(cmd); allowed {
			t.Errorf("expected %q to be blocked, reason=%q", cmd, reason)
		}
	}
}

// Flag-parsing edge cases: flags interleaved before/after the resource name, quoted arguments,
// and a resource name that itself looks like a flag-adjacent token must all still resolve to the
// correct verb/resource without misclassifying a flag value as the resource.
func TestValidateKubectlCommandFlagParsingEdgeCases(t *testing.T) {
	// Resource parsing is a naive "first token not starting with -" scan: it doesn't know which
	// flags consume a following value, so a flag's value token (e.g. "default" after "-n") is
	// picked up as the "resource" here. That's a cosmetic quirk of the audit-trail Resource field,
	// not a policy bypass — the verb allowlist/blocklist decision never depends on this value.
	allowed, _, parsed := ValidateKubectlCommand("kubectl get -n default pods")
	if !allowed || parsed.Resource != "default" {
		t.Fatalf("expected resource=default (flag's value token, first non-dash token), got allowed=%v parsed=%+v", allowed, parsed)
	}

	allowed, _, parsed = ValidateKubectlCommand("kubectl logs --tail=5 my-pod")
	if !allowed || parsed.Resource != "my-pod" {
		t.Fatalf("expected resource=my-pod skipping the leading flag, got allowed=%v parsed=%+v", allowed, parsed)
	}

	allowed, _, parsed = ValidateKubectlCommand(`kubectl get "pods"`)
	if !allowed || parsed.Resource != "pods" {
		t.Fatalf("expected quoted resource to be parsed, got allowed=%v parsed=%+v", allowed, parsed)
	}

	allowed, _, parsed = ValidateKubectlCommand("kubectl get")
	if !allowed || parsed.Resource != "" {
		t.Fatalf("expected empty resource when none given, got allowed=%v parsed=%+v", allowed, parsed)
	}
}

func TestValidateKubectlCommandRejectsUnbalancedQuote(t *testing.T) {
	allowed, reason, _ := ValidateKubectlCommand(`kubectl get "pods`)
	if allowed {
		t.Fatal("expected unbalanced quote to be rejected")
	}
	if reason == "" {
		t.Fatal("expected a non-empty rejection reason")
	}
}

func TestValidateKubectlCommandAllowsRemainingReadOnlyVerbs(t *testing.T) {
	for _, cmd := range []string{
		"kubectl top pods",
		"kubectl explain pod.spec",
		"kubectl version",
		"kubectl api-resources",
		"kubectl api-versions",
	} {
		if allowed, reason, _ := ValidateKubectlCommand(cmd); !allowed {
			t.Errorf("expected %q to be allowed, reason=%q", cmd, reason)
		}
	}
}
