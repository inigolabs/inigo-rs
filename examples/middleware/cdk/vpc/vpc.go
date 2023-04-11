package vpc

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/jsii-runtime-go"
)

func NewVpc(stack awscdk.Stack, availabilityZones []string) (vpc awsec2.Vpc) {
	vpc = awsec2.NewVpc(stack, jsii.String("inigo-router-vpc"),
		&awsec2.VpcProps{
			VpcName:           jsii.String("inigo-router-vpc"),
			AvailabilityZones: jsii.Strings(availabilityZones...),
			Cidr:              jsii.String("10.0.0.0/16"),
			NatGateways:       jsii.Number(16),
			SubnetConfiguration: &[]*awsec2.SubnetConfiguration{
				{
					Name:       jsii.String("public"),
					SubnetType: awsec2.SubnetType_PUBLIC,
					CidrMask:   jsii.Number(20),
				},
				{
					Name:       jsii.String("private"),
					SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
					CidrMask:   jsii.Number(20),
				},
			},
		},
	)

	return
}
