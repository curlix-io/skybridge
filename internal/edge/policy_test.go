package edge

import "testing"

func TestValidateReadOnlyAWSCommandAllows(t *testing.T) {
	allowed := []string{
		"aws ec2 describe-instances",
		"aws rds describe-db-instances --region us-east-1",
		"aws s3 ls",
		"aws cloudwatch get-metric-data",
		"aws dynamodb scan --table-name foo",
		"aws dynamodb query --table-name foo",
		"aws logs describe-log-groups",
		"aws ec2 describe-instances --filters 'Name=tag:env,Values=prod'",
		"aws iam list-roles --max-items 50",
		"aws cloudtrail lookup-events",
		"aws s3api list-objects-v2 --bucket b",
		"aws ec2 batch-get-image-block-public-access-state",
	}
	for _, c := range allowed {
		ok, reason := ValidateReadOnlyAWSCommand(c)
		if !ok {
			t.Errorf("expected allow: %q -> %s", c, reason)
		}
	}
}

func TestValidateReadOnlyAWSCommandRejects(t *testing.T) {
	rejected := []string{
		"",
		"rm -rf /",
		"aws ec2 run-instances",
		"aws ec2 terminate-instances --instance-ids i-1",
		"aws s3 rm s3://bucket/key",
		"aws s3 cp a b",
		"aws secretsmanager get-secret-value --secret-id x",
		"aws sts get-session-token",
		"aws ssm get-parameter --with-decryption --name p",
		"aws ec2 describe-instances --profile admin",
		"aws ec2 describe-instances --endpoint-url http://evil",
		"aws ec2 describe-instances; rm -rf /",
		"aws ec2 describe-instances | cat",
		"aws ec2 describe-instances && echo hi",
		"aws ec2 describe-instances $(whoami)",
		"aws ec2 describe-instances `id`",
		"echo hi",
		"aws",
		"aws ec2",
	}
	for _, c := range rejected {
		ok, _ := ValidateReadOnlyAWSCommand(c)
		if ok {
			t.Errorf("expected reject: %q", c)
		}
	}
}

func TestValidateRejectsEqualsFormDeniedFlag(t *testing.T) {
	if ok, _ := ValidateReadOnlyAWSCommand("aws ec2 describe-instances --profile=admin"); ok {
		t.Error("--profile=admin should be rejected")
	}
	if ok, _ := ValidateReadOnlyAWSCommand("aws ec2 describe-instances --endpoint-url=http://x"); ok {
		t.Error("--endpoint-url=... should be rejected")
	}
}

func TestValidateSkipsValueFlagsLocatingService(t *testing.T) {
	// --region consumes us-east-1; ec2/describe-instances must still be classified correctly.
	if ok, reason := ValidateReadOnlyAWSCommand("aws --region us-east-1 ec2 describe-instances"); !ok {
		t.Errorf("expected allow with leading global flag: %s", reason)
	}
}

func TestShlexSplit(t *testing.T) {
	toks, err := shlexSplit(`aws ec2 describe-instances --filters 'Name=tag:env,Values=prod'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aws", "ec2", "describe-instances", "--filters", "Name=tag:env,Values=prod"}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens %v", len(toks), toks)
	}
	for i := range want {
		if toks[i] != want[i] {
			t.Fatalf("token %d = %q want %q", i, toks[i], want[i])
		}
	}
}

func TestShlexSplitUnbalanced(t *testing.T) {
	if _, err := shlexSplit(`aws ec2 "oops`); err == nil {
		t.Fatal("expected unbalanced quote error")
	}
}
