package fargate

import (
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/jsii-runtime-go"
)

func newService(inigoTaskDef awsecs.TaskDefinition) (svc awsecs.ContainerDefinition) {
	svc = inigoTaskDef.AddContainer(jsii.String("inigo-router-service"), &awsecs.ContainerDefinitionOptions{
		Image: awsecs.ContainerImage_FromRegistry(jsii.String("public.ecr.aws/t6h3u2t6/inigo-router:latest"), &awsecs.RepositoryImageProps{}),
		Environment: &map[string]*string{
			"APOLLO_ROUTER_SUPERGRAPH_PATH": jsii.String("/scheme/inigo/schema.graphql"),
			"APOLLO_ROUTER_CONFIG_PATH":     jsii.String("/scheme/inigo/router.yaml"),
			"INIGO_LIB_PATH":                jsii.String("/inigo-linux-amd64.so"),
		},
		Logging: awsecs.LogDriver_AwsLogs(&awsecs.AwsLogDriverProps{
			StreamPrefix: jsii.String("inigo-router"),
		}),
		PortMappings: &[]*awsecs.PortMapping{
			{
				HostPort:      jsii.Number(80),
				Protocol:      awsecs.Protocol_TCP,
				ContainerPort: jsii.Number(80),
			},
			{
				HostPort:      jsii.Number(8088),
				Protocol:      awsecs.Protocol_TCP,
				ContainerPort: jsii.Number(8088),
			},
		},
		Essential: jsii.Bool(true),
	})

	svc.AddMountPoints(&awsecs.MountPoint{
		ReadOnly:      jsii.Bool(true),
		ContainerPath: jsii.String("/scheme/inigo"),
		SourceVolume:  jsii.String("scheme"),
	})

	return
}
