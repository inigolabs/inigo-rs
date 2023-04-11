package fargate

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/jsii-runtime-go"
)

func NewFargateService(stack awscdk.Stack, vpc awsec2.Vpc) {
	cluster := awsecs.NewCluster(stack, jsii.String("inigo-router-ecs"), &awsecs.ClusterProps{
		ClusterName: jsii.String("inigo-router-ecs"),
		Vpc:         vpc,
	})

	inigoTaskDef := newTaskDef(stack)

	svc := newService(inigoTaskDef)

	sidecar := newSidecar(inigoTaskDef)

	svc.AddContainerDependencies(&awsecs.ContainerDependency{
		Container: sidecar,
		Condition: awsecs.ContainerDependencyCondition_SUCCESS,
	})

	fargateSG := awsec2.NewSecurityGroup(stack, jsii.String("inigo-router-fargate-security-group"), &awsec2.SecurityGroupProps{
		Vpc: vpc,
	})

	fargate := awsecs.NewFargateService(stack, jsii.String("inigo-router-fargate"), &awsecs.FargateServiceProps{
		Cluster:        cluster,
		DesiredCount:   jsii.Number(1),
		ServiceName:    jsii.String("inigo-router-fargate"),
		TaskDefinition: inigoTaskDef,
		AssignPublicIp: jsii.Bool(false),
		VpcSubnets:     &awsec2.SubnetSelection{SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS},
		SecurityGroups: &[]awsec2.ISecurityGroup{fargateSG},
	})

	newLoadBalancer(stack, vpc, fargate)
}
