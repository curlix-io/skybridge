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
