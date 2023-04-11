package fargate

import (
	"encoding/base64"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/jsii-runtime-go"
)

func newSidecar(inigoTaskDef awsecs.TaskDefinition) (sidecar awsecs.ContainerDefinition) {
	sidecar = inigoTaskDef.AddContainer(jsii.String("inigo-router-sidecar"), &awsecs.ContainerDefinitionOptions{
		Image: awsecs.ContainerImage_FromRegistry(jsii.String("bash"), &awsecs.RepositoryImageProps{}),
		Environment: &map[string]*string{
			"SCHEMA_GRAPHQL": jsii.String(toBase64String("../schema.graphql")),
			"ROUTER_YAML":    jsii.String(toBase64String("../router.yaml")),
		},
		Command: &[]*string{
			jsii.String("echo $SCHEMA_GRAPHQL | base64 -d - | tee /scheme/inigo/schema.graphql && echo $ROUTER_YAML | base64 -d - | tee /scheme/inigo/router.yaml"),
		},
		EntryPoint: &[]*string{jsii.String("sh"), jsii.String("-c")},
		Logging: awsecs.LogDriver_AwsLogs(&awsecs.AwsLogDriverProps{
			StreamPrefix: jsii.String("inigo-router-sidecar"),
		}),
		Essential:              jsii.Bool(false),
		DisableNetworking:      jsii.Bool(false),
		ReadonlyRootFilesystem: jsii.Bool(false),
	})

	sidecar.AddMountPoints(&awsecs.MountPoint{
		ReadOnly:      jsii.Bool(false),
		ContainerPath: jsii.String("/scheme/inigo"),
		SourceVolume:  jsii.String("scheme"),
	})

	return
}

func toBase64String(filename string) string {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic("Failed to read: " + filename)
	}
	if len(data) == 0 {
		panic("File is empty: " + filename)
	}
	sData := base64.StdEncoding.EncodeToString(data)
	return sData
}
