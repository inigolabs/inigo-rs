package fargate

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

func newTaskDef(stack awscdk.Stack) (inigoTaskDef awsecs.TaskDefinition) {
	ecsSvcP := awsiam.NewServicePrincipal(jsii.String("ecs-tasks.amazonaws.com"), &awsiam.ServicePrincipalOpts{})

	inigoManagedPolicy := []awsiam.IManagedPolicy{
		awsiam.ManagedPolicy_FromAwsManagedPolicyName(jsii.String("AmazonSQSFullAccess")),
	}
	inigoTaskRole := awsiam.NewRole(stack, jsii.String("inigo-router-edge-r1"), &awsiam.RoleProps{
		InlinePolicies:  nil,
		ManagedPolicies: &inigoManagedPolicy,
		AssumedBy:       ecsSvcP.GrantPrincipal(),
		RoleName:        jsii.String("inigo-router-edge-r1"),
	})

	managedPolicy := []awsiam.IManagedPolicy{awsiam.ManagedPolicy_FromAwsManagedPolicyName(jsii.String("service-role/AmazonECSTaskExecutionRolePolicy"))}
	inigoTaskExecRole := awsiam.NewRole(stack, jsii.String("inigo-router-ecs-task-exec-r1"), &awsiam.RoleProps{
		InlinePolicies:  nil,
		ManagedPolicies: &managedPolicy,
		AssumedBy:       ecsSvcP.GrantPrincipal(),
		RoleName:        jsii.String("inigo-router-ecs-task-exec-r1"),
	})

	inigoTaskDef = awsecs.NewTaskDefinition(stack, jsii.String("inigo-router-task"), &awsecs.TaskDefinitionProps{
		Family:        jsii.String("inigo-router-task"),
		Compatibility: awsecs.Compatibility_FARGATE,
		TaskRole:      inigoTaskRole,
		ExecutionRole: inigoTaskExecRole,
		Cpu:           jsii.String("512"),
		MemoryMiB:     jsii.String("1024"),
		RuntimePlatform: &awsecs.RuntimePlatform{
			CpuArchitecture:       awsecs.CpuArchitecture_X86_64(),
			OperatingSystemFamily: awsecs.OperatingSystemFamily_LINUX(),
		},
		Volumes: &[]*awsecs.Volume{
			{
				Name: jsii.String("scheme"),
			},
		},
		NetworkMode: awsecs.NetworkMode_AWS_VPC,
	})

	return
}
