// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { Stack, StackProps, Duration, CfnOutput, SecretValue } from "aws-cdk-lib";
import { HttpApi, HttpMethod, CfnStage } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { Role, ServicePrincipal, Effect, PolicyStatement, ManagedPolicy } from "aws-cdk-lib/aws-iam";
import { Runtime, Function, InlineCode, Tracing } from "aws-cdk-lib/aws-lambda";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";

export interface SlackBotStackProps extends StackProps {
	logRetention?: RetentionDays;
}

export class SlackBotStack extends Stack {
	constructor(scope: Construct, id: string, props: SlackBotStackProps) {
		super(scope, id, props);

		const logRetention = props.logRetention ?? RetentionDays.TWO_YEARS;
		const temporarySlackBotTokenValue = "xoxb-1234-5678-foo";

		const slackBotToken = new Secret(this, "SlackBotToken", {
			secretObjectValue: {
				token: SecretValue.unsafePlainText(temporarySlackBotTokenValue),
			},
		});

		new CfnOutput(this, "SlackBotTokenOutput", {
			value: `https://${this.region}.console.aws.amazon.com/secretsmanager/secret?name=${slackBotToken.secretName}&region=${this.region}`,
			description: "The Secret containing the Slack Bot Token.",
		});

		const lambdaRole = new Role(this, "SlackBotRole", {
			assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
			description: "Role for Slack bot lambda",
		});
		lambdaRole.addToPolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ["bedrock:InvokeModel"],
				resources: ["*"],
			}),
		);
		lambdaRole.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"));
		slackBotToken.grantRead(lambdaRole);

		NagSuppressions.addResourceSuppressions(
			lambdaRole,
			[
				{
					// The IAM user, role, or group uses AWS managed policies.
					id: "AwsSolutions-IAM4",
					reason: "Managed policies are used to simplify the solution.",
					appliesTo: ["Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
				},
				{
					// The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission.
					id: "AwsSolutions-IAM5",
					reason: "The role will have access to invoke all models preferred by end user.",
					appliesTo: ["Resource::*"],
				},
			],
			true,
		);

		const lambdaCode = new InlineCode(`

## Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: MIT-0

import json
import os
import boto3
import urllib3
from botocore.response import StreamingBody
import uuid
import logging  

# Setup logging  
logging.basicConfig(level=logging.INFO)  
logger = logging.getLogger()  

session_id = str(uuid.uuid1())
enable_trace = False
end_session = False

# Initialize AWS clients for Bedrock and Secrets Manager
bedrock_runtime_client = boto3.client('bedrock-agent-runtime')
secretsmanager_client = boto3.client('secretsmanager')

# Set the Slack API URL and fetch the Slack token from Secrets Manager
SLACK_URL = 'https://slack.com/api/chat.postMessage'
slack_token = json.loads(
	secretsmanager_client.get_secret_value(
		SecretId=os.environ.get('token')
	)['SecretString']
)['token']
http = urllib3.PoolManager()

# BedrockAgentId = json.loads(
# 	secretsmanager_client.get_secret_value(
# 		SecretId=os.environ.get('BedrockAgentId')
# 	)['SecretString']
# )['BedrockAgentId']

# BedrockAliasId = json.loads(
# 	secretsmanager_client.get_secret_value(
# 		SecretId=os.environ.get('BedrockAliasId')
# 	)['SecretString']
# )['BedrockAliasId']


def handle_challenge(event):
	"""
	Handles the Slack challenge event for verifying the URL.
	https://api.slack.com/events/url_verification

	Args:
		event (dict): The event data from the Slack challenge.

	Returns:
		dict: A response dictionary with the status code and the challenge value.
	"""
	body = json.loads(event['body'])
	return {  
    	'statusCode': 200,  
    	'body': body['challenge']  
    }

def handle_message(event):  
	"""Handles the Slack message event and calls the Bedrock AI model."""  
	slack_body = json.loads(event['body'])  
	slack_text = slack_body.get('event', {}).get('text', '')  
	slack_user = slack_body.get('event', {}).get('user', '')  
	channel = slack_body.get('event', {}).get('channel', '')  
	
	# Log incoming message details  
	logger.info(f"Processing message from user: {slack_user}, text: {slack_text}")  
	
	cleaned_text = slack_text.replace('<@U06D5B8AR8R>', '').strip()  
	msg = call_bedrock(cleaned_text)  
	
	data = {'channel': channel, 'text': f"<@{slack_user}> {msg}"}  
	headers = {'Authorization': f'Bearer {slack_token}', 'Content-Type': 'application/json'}  
	
	try:  
	    # Make sure to log the data being sent to Slack  
	    logger.info(f"Sending response to Slack: {data}")  
	    http.request('POST', SLACK_URL, headers=headers, body=json.dumps(data))  
	except Exception as e:  
	    logger.error(f"Error sending message to Slack: {e}")  
	
	return {'statusCode': 200, 'body': json.dumps({'msg': "message received"})}  



def call_bedrock(question):  
	"""  
	Calls the Bedrock AI model with the given question.  
	
	Args:  
	    question (str): The question to ask the Bedrock AI model.  
	
	Returns:  
	    str: The response from the Bedrock AI model.  
	"""  
	body = {  
	    "inputText": f"\n\nHuman: Act as a slack bot. {question}\n\nAssistant:",  
	    "agentId": "2JFUZKXKXG",  
	    "agentAliasId": "PKRTXAHEOH",  
	    "sessionId": session_id,  
	    "enableTrace": enable_trace,  
	    "endSession": end_session  
	}  

	try:  
	    response = bedrock_runtime_client.invoke_agent(**body)  
	    logger.info(f"Response metadata: {json.dumps(response.get('ResponseMetadata', {}), indent=2)}")  
	
	    event_stream = response.get('completion')  
	    if not event_stream:  
	        raise ValueError("No completion event stream found in the response.")  
	
	    agent_answer = ""  
	    for event in event_stream:  
	        if 'chunk' in event:  
	            data = event['chunk'].get('bytes')  
	            if data:  
	                decoded_data = data.decode('utf8')  
	                agent_answer += decoded_data  
	                if enable_trace:  
	                    logger.info(f"Chunk received: {decoded_data}")  
	                # Stop processing after the first complete response  
	                break  
	        elif 'trace' in event:  
	            if enable_trace:  
	                logger.info(f"Trace event: {json.dumps(event['trace'], indent=2)}")  
	
	    if not agent_answer:  
	        raise ValueError("No valid response received from the agent.")  
	
	    return agent_answer  
	
	except Exception as e:  
	    logger.error(f"Error calling Bedrock AI model: {e}")  
	    return "Sorry, I couldn't process your request at this time."

def handler(event, context):
	"""
	The main Lambda handler function.

	Args:
		event (dict): The event data from the Slack API.
		context (dict): The Lambda context object.

	Returns:
		dict: The response dictionary based on the event type.
	"""
	# Respond to the Slack Challenge if presented, otherwise handle the Bedrock interaction
	try:  
	    event_body = json.loads(event.get("body", "{}"))  
	    logger.info(f"Received event: {json.dumps(event_body, indent=2)}")  
	    
	    if event_body.get("type") == "url_verification":  
	        response = handle_challenge(event)  
	    elif event_body.get("event", {}).get("type") == "app_mention":  
	        response = handle_message(event)  
	    else:  
	        logger.warning("Unhandled event type received.")  
	        return {'statusCode': 400, 'body': json.dumps({'error': 'Event type not handled'})}  
	
	    return response  
	
	except Exception as e:  
	    logger.error(f"Error processing event: {e}")  
	    return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}  
	    `);

		const lambdaLogGroup = new LogGroup(this, "SlackBotLambdaLog", {
			retention: logRetention,
		});

		const lambda = new Function(this, "SlackBotLambda", {
			code: lambdaCode,
			runtime: Runtime.PYTHON_3_12,
			handler: "index.handler",
			timeout: Duration.seconds(30),
			description: "Handles Slack bot actions",
			role: lambdaRole,
			environment: {
				token: slackBotToken.secretArn,
			},
			tracing: Tracing.ACTIVE,
			logGroup: lambdaLogGroup,
		});

		NagSuppressions.addResourceSuppressions(lambda, [
			{
				// The non-container Lambda function is not configured to use the latest runtime version.
				id: "AwsSolutions-L1",
				reason: "The runtime is pinned for stability.",
			},
		]);

		const slackEndpoint = new HttpApi(this, "SlackBotEndpoint", {
			description: "Proxy for Bedrock Slack bot backend.",
		});

		new CfnOutput(this, "SlackBotEndpointOutput", {
			value: slackEndpoint.url!,
			description: "The URL used to verify the Slack app.",
		});

		const apiGatewayLogGroup = new LogGroup(this, "SlackBotApiAccessLog", {
			retention: logRetention,
		});
		const defaultStage = slackEndpoint.defaultStage?.node.defaultChild as CfnStage;
		defaultStage.accessLogSettings = {
			destinationArn: apiGatewayLogGroup.logGroupArn,
			format: JSON.stringify({
				requestId: "$context.requestId",
				ip: "$context.identity.sourceIp",
				requestTime: "$context.requestTime",
				httpMethod: "$context.httpMethod",
				routeKey: "$context.routeKey",
				status: "$context.status",
				protocol: "$context.protocol",
				responseLength: "$context.responseLength",
				userAgent: "$context.identity.userAgent",
			}),
		};

		slackEndpoint.addRoutes({
			path: "/",
			methods: [HttpMethod.ANY],
			integration: new HttpLambdaIntegration("BotHandlerIntegration", lambda),
		});
	}
}
