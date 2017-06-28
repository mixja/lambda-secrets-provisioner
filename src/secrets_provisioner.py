import sys, os
parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, 'vendor')
sys.path.append(vendor_dir)

import logging, datetime, json, random, string, base64, hashlib
import boto3
from cfn_lambda_handler import Handler
from voluptuous import Required, All, Schema, Invalid, MultipleInvalid

LENGTH = 13
CHARS = string.ascii_letters + string.digits + '!@#$%^&*()'

# Configure logging
logging.basicConfig()
log = logging.getLogger()
log.setLevel(os.environ.get('LOG_LEVEL','INFO'))
def format_json(data):
  return json.dumps(data, default=lambda d: d.isoformat() if isinstance(d, datetime.datetime) else str(d))

# Lambda handler
handler = Handler()

# Boto3 clients
kms = boto3.client('kms')
ssm = boto3.client('ssm')

# Validate input
def get_validator():
  return Schema({
    Required('Name'): All(basestring),
    Required('Key'): All(basestring),
    Required('Value', default=None): All(basestring),
    Required('Version', default=datetime.datetime.now().strftime('%Y-%m-%d')): All(basestring),
    Required('KmsKeyId'): All(basestring)
  }, extra=True)

def validate(data):
  request_validator = get_validator()
  return request_validator(data)

# Random password generator
def generate_password(length, chars):
  rnd = random.SystemRandom()
  return ''.join(rnd.choice(chars) for i in range(length))

# Create/Update requests
@handler.create
@handler.update
def handle_create(event, context):
  log.info("Received create event: %s" % format_json(event))
  secret = validate(event['ResourceProperties'])
  if secret['Value'] is None:
    # generate random password
    secret['Value'] = generate_password(LENGTH, CHARS)
  else:
    # decrypt supplied secret
    secret['Value'] = kms.decrypt(CiphertextBlob=base64.b64decode(secret['Value'])).get('Plaintext')
  # Provision secret
  # The secret value will be in the form Key=Value - e.g. DB_PASSWORD=abc123
  ssm.put_parameter(
    Name=secret['Name'],
    Value='%s=%s' % (secret['Key'],secret['Value']),
    Type='SecureString',
    KeyId=secret['KmsKeyId'],
    Overwrite=True
  )
  event['Data'] = {
    'Value': secret['Value'],
    'Version': secret['Version']
  }
  return event

# Delete requests
@handler.delete
def handle_delete(event, context):
  log.info("Received delete event: %s" % format_json(event))
  secret = validate(event['ResourceProperties'])
  ssm.delete_parameters(Names=[secret['Name']])
  return event