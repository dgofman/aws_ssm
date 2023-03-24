# AWS Systems Manager Parameter Store

AWS Systems Manager Parameter Store provides secure, hierarchical storage for configuration data management and secrets management. It can store data such as passwords, database strings, Amazon Machine Image (AMI) IDs and license codes as parameter values.


<p align="center">
<a href="https://raw.githubusercontent.com/dgofman/aws_ssm/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
<a href="https://pub.dev/packages/aws_ssm/install"><img src="https://img.shields.io/badge/pub-v1.0.0-blue" alt="aws_ssm"></a>
</p>


## Prerequisites
##### User Pool
<a href="https://docs.aws.amazon.com/cognito/latest/developerguide/tutorial-create-user-pool.html">Tutorial: Creating a user pool</a>

- Store "User Pool ID" value (User pool overview)
- There must be at least one client application in the "Application Integration" tab "Application Client List -> Create Application Client".
- Store the value "Client ID" (App client information)

##### Create Federated identities
<a href="https://docs.aws.amazon.com/cognito/latest/developerguide/tutorial-create-identity-pool.html">Tutorial: Creating an identity pool</a>

- Assign "User pool ID" and "Client ID" to the fields in "Authentication providers -> Cognito"
- Create a custom SSM Role: "Identity pool -> Edit identity pool -> Authenticated role"
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameters"
            ],
            "Resource": "*"
        }
    ]
}
```

### Get cognito user JWT id token

```dart
import 'package:amazon_cognito_identity_dart_2/cognito.dart';
...
final user = CognitoUser({{COGNITO_USER_NAME}}, CognitoUserPool(
  userPoolId,
  clientId,
));
CognitoUserSession? session = await user.authenticateUser(AuthenticationDetails(
  username: {{COGNITO_USER_NAME}},
  password: {{COGNITO_USER_PASSWORD}},
));
final idToken = session!.getIdToken().getJwtToken();
```

### Get list of AWS Systems Manager Parameters

```dart
import 'aws_ssm.dart';
...
try {
  final names = ['db-url', 'my-username', 'my-password'];
  final ssm = AwsSSM(region, userPoolId, identityPoolId);
  final values = await ssm.getListParams(idToken, names);
  print(values); //['db-url-value', 'my-username-value', 'my-password-value']
} catch (ex) {
  print(ex);
}
```

### Get map of AWS Systems Manager Parameters

```dart
import 'aws_ssm.dart';
...
try {
    final names = ['db-url', 'my-username', 'my-password'];
    final ssm = AwsSSM(region, userPoolId, identityPoolId);
    final values = await ssm.getListParams(idToken, names);
    print(values); //{'db-url': 'db-url-value', 'my-username': 'my-username-value', 'my-password': 'my-password-value'}
} catch (ex) {
  print(ex);
}
```

## List of API's

```dart
import 'aws_ssm.dart';
...
try {
    final ssm = AwsSSM(region, userPoolId, identityPoolId);
    final credentials = await ssm.getCognitoCredentialsForIdentity(idToken);
    final payload = ssm.createPayload(names, true);
    final datetime = await ssm.getServerDateTime();
    final headers = ssm.createAWS4Header(credentials, payload, datetime);
    final params = await ssm.getParameters(headers, payload);
    final values = ssm.toMap<String>(names, params);
    print(values);
} catch (ex) {
  print(ex);
}
```