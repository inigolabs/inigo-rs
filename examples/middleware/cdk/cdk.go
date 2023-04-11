package main

import (
	"os"
	"strings"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
	"github.com/inigolabs/inigo-router/examples/middleware/cdk/fargate"
	"github.com/inigolabs/inigo-router/examples/middleware/cdk/vpc"
)

type CdkStackProps struct {
	awscdk.StackProps
}

func NewCdkStack(scope constructs.Construct, id string, props *CdkStackProps) awscdk.Stack {
	var sprops awscdk.StackProps
	if props != nil {
		sprops = props.StackProps
	}
	stack := awscdk.NewStack(scope, &id, &sprops)

	availabilityZones, ok := toStringSlice(scope.Node().TryGetContext(jsii.String("inigo-router-vpc-availability-zones")))
	if !ok {
		panic("Failed to get inigo-router-vpc-availability-zones from context")
	}

	fargate.NewFargateService(stack, vpc.NewVpc(stack, availabilityZones))

	return stack
}

func main() {
	defer jsii.Close()

	app := awscdk.NewApp(nil)

	NewCdkStack(app, "InigoRouter", &CdkStackProps{
		awscdk.StackProps{
			Env: env(),
		},
	})

	app.Synth(nil)
}

// env determines the AWS environment (account+region) in which our stack is to
// be deployed. For more information see: https://docs.aws.amazon.com/cdk/latest/guide/environments.html
func env() *awscdk.Environment {
	// If unspecified, this stack will be "environment-agnostic".
	// Account/Region-dependent features and context lookups will not work, but a
	// single synthesized template can be deployed anywhere.
	//---------------------------------------------------------------------------
	// return nil

	// Uncomment if you know exactly what account and region you want to deploy
	// the stack to. This is the recommendation for production stacks.
	//---------------------------------------------------------------------------
	//return &awscdk.Environment{
	//	Account: jsii.String("434947586777"),
	//	Region:  jsii.String("us-east-1"),
	//}

	// Uncomment to specialize this stack for the AWS Account and Region that are
	// implied by the current CLI configuration. This is recommended for dev
	// stacks.
	//---------------------------------------------------------------------------
	return &awscdk.Environment{
		Account: jsii.String(os.Getenv("CDK_DEFAULT_ACCOUNT")),
		Region:  jsii.String(os.Getenv("CDK_DEFAULT_REGION")),
	}
}

// `cdk diff` - try to get values from cdk.context.json file
// `cdk diff --context inigo-router-vpc-availability-zones=us-east-1a,us-east-1b` - override values from cdk.context.json file
func toStringSlice(value any) ([]string, bool) {
	switch value.(type) {
	case string:
		sliceStr, _ := value.(string)
		return strings.Split(sliceStr, ","), true
	case []any:
		sliceAny, _ := value.([]any)
		var slice []string
		for _, val := range sliceAny {
			strVal, ok := val.(string)
			if !ok {
				return nil, false
			}
			slice = append(slice, strVal)
		}
		return slice, true
	}
	return nil, false
}
