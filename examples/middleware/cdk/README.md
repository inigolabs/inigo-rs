# Welcome to your AWS CDK inigo-router project!

This is example project for AWS CDK deployment of inigo-router.

The `cdk.json` file tells the CDK toolkit how to execute your app.

To successfully deploy the cdk, change the router port to 80 in `router.yaml` file:
```yaml
supergraph:
  listen: 0.0.0.0:80
```

## Useful commands

 * `npm install -g aws-cdk` installs the latest version of aws-cdk globally
 * `aws configure`          configures AWS Access Key ID and AWS Secret Access Key
 * `cdk bootstrap`          bootstrap the environment
 * `cdk diff`               compare deployed stack with current state
 * `cdk deploy`             deploy this stack to your default AWS account/region
 * `cdk synth`              emits the synthesized CloudFormation template
 * `go test`                run unit tests
 * `cdk diff --context inigo-router-vpc-availability-zones=us-east-1a,us-east-1b` override values from cdk.context.json file

After deploying the cdk, follow the link to the loadbalancer and you can use its DNS name - `https://us-east-1.console.aws.amazon.com/ec2/home?region=us-east-1#LoadBalancers:search=Inigo`

## Useful tips

AWS CDK Developer Guide - `https://docs.aws.amazon.com/cdk/v2/guide/home.html`
AWS CDK API Reference - `https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_eks-readme.html`
