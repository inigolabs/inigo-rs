package fargate

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
)

func newLoadBalancer(stack awscdk.Stack, vpc awsec2.Vpc, fargate awsecs.FargateService) {
	lb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("inigo-router-load-balancer"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{
		Vpc:            vpc,
		InternetFacing: jsii.Bool(true),
	})

	listener := lb.AddListener(jsii.String("inigo-router-listener"), &awselasticloadbalancingv2.BaseApplicationListenerProps{
		Port: jsii.Number(80),
	})

	fargate.RegisterLoadBalancerTargets(&awsecs.EcsTarget{
		ContainerName:    jsii.String("inigo-router-service"),
		ContainerPort:    jsii.Number(80),
		Protocol:         awsecs.Protocol_TCP,
		NewTargetGroupId: jsii.String("inigo-router-ecs-tg"),
		Listener: awsecs.ListenerConfig_ApplicationListener(listener, &awselasticloadbalancingv2.AddApplicationTargetsProps{
			Port:            jsii.Number(80),
			Protocol:        awselasticloadbalancingv2.ApplicationProtocol_HTTP,
			ProtocolVersion: awselasticloadbalancingv2.ApplicationProtocolVersion_HTTP1,
			HealthCheck: &awselasticloadbalancingv2.HealthCheck{
				Protocol:                awselasticloadbalancingv2.Protocol_HTTP,
				Path:                    jsii.String("/"),
				UnhealthyThresholdCount: jsii.Number(2),
				Interval:                awscdk.Duration_Seconds(jsii.Number(30)),
				Timeout:                 awscdk.Duration_Seconds(jsii.Number(15)),
				HealthyHttpCodes:        jsii.String("200-401"),
			},
		}),
	})
}
