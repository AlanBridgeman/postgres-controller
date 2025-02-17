# -*- coding: utf-8 -*-

import os, sys, json, re, base64
import logging, logging.handlers
import argparse
import yaml
from kubernetes import config, client
import psycopg2

logger = logging.getLogger()


class K8sLoggingFilter(logging.Filter):
    """A small filter to add add extra logging data if not present"""

    def filter(self, record):
        if not hasattr(record, 'resource_name'):
            record.resource_name = '-'
        return True

def create_logger(log_level: str) -> logging.Logger:
    """Creates a logging instance with JSON format and K8sLoggingFilter

    Args:
        log_level ('debug'|'info'): The log level to use, either 'info' or 'debug'
    """

    # setup the initial logging format
    json_format = logging.Formatter('{"time":"%(asctime)s", "level":"%(levelname)s", "resource_name":"%(resource_name)s", "message":"%(message)s"}')
    
    # Add a '-' for resource_name if not present
    filter = K8sLoggingFilter()

    # Create the logger object
    logger = logging.getLogger()

    # Add a stream handler to log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(json_format)

    # Add the filter and stream handler to the logger
    logger.addHandler(stdout_handler)
    logger.addFilter(filter)

    # Set the log level
    if log_level == 'debug':
        logger.setLevel(logging.DEBUG)
    elif log_level == 'info':
        logger.setLevel(logging.INFO)
    else:
        raise Exception('Unsupported log_level {0}'.format(log_level))

    return logger

class ValueReplacer:
    """A class to help replace config map values or secrets with their actual values"""
    
    def __init__(self, values: dict, instance_id: str | None = None):
        """Creates a new ValueReplacer object

        Args:
            values (dict): The values to replace the config map values or secrets in
            instance_id (str | None): The instance_id to look up in the controller's configuration (mostly for helpful erroring). Defaults to None.
        """

        self.values = values
        self.instance_id = instance_id

    def get_config_map_value(self, config_map_details: dict):
        """Get the value of a config map value from Kubernetes

        Using a config map reference would look something like: 
        ```
        postgres_instances:
          default:
            ...
            user:
              envFrom:
                configMapKeyRef:
                  - name: my-config
                    namespace: my-namespace
                    key: my-config-user
            ...
        ```
        but this isn't limited to just the `config` key, it can be used for any key in the configuration.

        It's also worth noting that only the first item in the `envFrom` array is considered (it's an array to feel consistent with other Kubernetes objects).
        The only required key in the config map value's definition is `name`, the rest (`namespace`, `key`) are optional.
        If `namespace` is provided, it should be the same as the pod (see https://stackoverflow.com/questions/55515594/is-there-a-way-to-share-a-configmap-in-kubernetes-between-namespaces for the reason for this).
        If `namespace` isn't provided, it defaults to `default` (this STILL should be the same as where the pod is running otherwise it won't work).

        Args:
            config_map_details (dict): The details of the config map value to retrieve (`['postgres_instances']['default']['user']['envFrom']['configMapKeyRef']` using the example above)

        Returns:
            str: The value of the config map value
        """

        config_name = config_map_details['name']
        
        config_namespace = 'default'
        if 'namespace' in config_map_details:
            config_namespace = config_map_details['namespace']
                            
        config_value = client.CoreV1Api().read_namespaced_config_map(config_name, config_namespace).data

        if 'key' in config_map_details:
            config_key = config_map_details['key']
            config_value = config_value[config_key]
                            
        return config_value
    
    def get_secret_value(self, secret_details: dict) -> str:
        """Get the value of a secret from Kubernetes

        Using a secret reference would look something like: 
        ```
        postgres_instances:
          default:
            ...
            password:
              envFrom:
                secretKeyRef:
                  - name: my-secret
                    namespace: my-namespace
                    key: my-secret-password
            ...
        ```
        but this isn't limited to just the `password` key, it can be used for any key in the configuration.

        It's also worth noting that only the first `secretKeyRef` item in the `envFrom` array is considered (it's an array to feel consistent with other Kubernetes objects).
        The only required key in the secret's definition is `name`, the rest (`namespace`, `key`) are optional.
        If `namespace` is provided, it should be the same as the pod (see https://stackoverflow.com/questions/46297949/is-there-a-way-to-share-secrets-across-namespaces-in-kubernetes for the reason for this).
        If `namespace` isn't provided, it defaults to `default` (this STILL should be the same as where the pod is running otherwise it won't work).

        One of the biggest differences between this and `get_config_map_value` (aside fro the function called to get it) is that secrets in Kubernetes are base64 encoded.
        So, it needs to be decoded before being returned.

        Args:
            secret_details (dict): The details of the secret to retrieve (`['postgres_instances']['default']['password']['envFrom']['secretKeyRef']` using the example above)

        Returns:
            str: The value of the secret (decoded from base64 into a UTF-8 string)
        """

        secret_name = secret_details['name']
        
        secret_namespace = 'default'
        if 'namespace' in secret_details:
            secret_namespace = secret_details['namespace']

        encoded_value = client.CoreV1Api().read_namespaced_secret(secret_name, secret_namespace).data

        if 'key' in secret_details:
            secret_key = secret_details['key']
            
            # Check if the key is in the secret, if not, raise an error
            if secret_key not in encoded_value:
                logger.error(f"Key '{secret_key}' not found in secret '{secret_name}'")
                raise KeyError(f"Key '{secret_key}' not found in secret '{secret_name}'")
            
            encoded_value = encoded_value[secret_key]
        else:
            # If no key is provided, just use the first key in the secret
            encoded_value = next(iter(encoded_value.values()))
        
        # Decode the base64 encoded secret value
        try:
            decoded_value = base64.b64decode(encoded_value).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logger.error(f"Failed to decode value for secret '{secret_name}': {e}")
            raise

        logger.debug(f"Successfully retrieved secret value '{secret_name}' in namespace '{secret_namespace}'.")
        return decoded_value

    def replace_config_map_values_or_secrets(self) -> dict:
        """Replace config map values or secrets with their actual values

        Raises:
            Exception: If the `envFrom` type is not supported

        Returns:
            dict: The credentials with the config map values or secrets replaced
        """

        values = self.values

        # Loop over each key to check for config map value/secret references (rather than plain text values)
        for key, value in values.items():
            # If the value is a dictionary and has a key of 'envFrom', we assume it's a reference to a configmap or secret
            if type(value) == dict and 'envFrom' in value:
                # `envFrom` is an array of dictionaries, this should really only have one value (we only consider the first item). 
                # It's done this way to be as consistent with other Kubernetes objects as possible
                env_from = values[key]['envFrom']
                        
                # If the type is a configMapKeyRef, we need to read the configmap
                if 'configMapKeyRef' in env_from:
                    config_map_details = env_from['configMapKeyRef'][0]
                    values[key] = self.get_config_map_value(config_map_details)
                elif 'secretKeyRef' in env_from:
                    secret_details = env_from['secretKeyRef'][0]
                    values[key] = self.get_secret_value(secret_details)
                else:
                    if self.instance_id is not None:
                        raise Exception('Unsupported envFrom type: {0} for {1}.{2}'.format(env_from, self.instance_id, key))
                    else:
                        raise Exception('Unsupported envFrom type: {0} for {1}'.format(env_from, key))
            elif type(value) == dict and 'value' in value:
                values[key] = value['value']
        
        logger.debug('Replaced config map values or secrets with actual values: {0}'.format(str(values)))
        return values

class PostgresControllerConfig(object):
    """Manages run time configuration"""

    def __init__(self):
        """Initializes the PostgresControllerConfig object

        Raises:
            Exception: If no postgres instances are defined in the configuration
        """

        if 'KUBERNETES_PORT' in os.environ:
            config.load_incluster_config()
        else:
            config.load_kube_config()

        # Parse command line arguments
        parser = argparse.ArgumentParser(description='A simple k8s controller to create PostgresSQL databases.')
        parser.add_argument('-c', '--config-file', help='Path to config file.', default=os.environ.get('CONFIG_FILE', None))
        parser.add_argument('-l', '--log-level', help='Log level.', choices=['info', 'debug'], default=os.environ.get('LOG_LEVEL', 'info'))
        self.args = parser.parse_args()

        # Check that the config file was specified (or uses default)
        if not self.args.config_file:
            parser.print_usage()
            sys.exit()
        
        # Load the configuration file
        with open(self.args.config_file) as fp:
            self.yaml_config = yaml.safe_load(fp)

            # At least one postgres instance must be defined
            if 'postgres_instances' not in self.yaml_config or len(self.yaml_config['postgres_instances'].keys()) < 1:
                raise Exception('No postgres instances in configuration')

    def get_credentials(self, instance_id: str | dict | None = None):
        """Returns the correct instance credentials from current list in configuration

        With the new additions of pulling in config maps and secrets a configuration might look something like:
        ```
        postgres_instances:
          default:
            host: 
              envFrom:
                configMapKeyRef:
                    - name: db-hostname
            port: 5432
            user:
              envFrom:
                secretKeyRef:
                  - name: database-cluster-superuser
                    namespace: postgres-controller
                    key: username
            password:
              envFrom:
                secretKeyRef:
                  - name: database-cluster-superuser
                    namespace: postgres-controller
                    key: password
        ```
        Note, this example is, more or less, based on real world configurations if deploying a CloudNAtivePG cluster named `database` and you copy the secret from the namespace.

        Args:
            instance_id (str | dict | None): The instance_id to look up in the controller's configuration. Defaults to None (note an empty dictionary is also considered None).
        """

        creds = None

        # If no instance_id is provided, use the default of "default"
        if instance_id == None or (type(instance_id) == dict and not bool(instance_id)):
            instance_id = 'default'
        
        # Loop over each instance definition under the `postgres_instances` key in the controller's configuration
        for id, data in self.yaml_config['postgres_instances'].items():
            # We only care if the id matches the instance_id
            if id == instance_id:
                creds = data.copy()
                
                # If the dbname is not provided, default to "postgres"
                if 'dbname' not in creds:
                    creds['dbname'] = 'postgres'
                
                # If any of the credentials are references to config maps or secrets, replace them with the actual values
                creds = ValueReplacer(creds, instance_id).replace_config_map_values_or_secrets()

                # Because we've found the correct instance, break out of the loop (assumed no duplicates as should be an "id"/identifier which should be unique)
                break

        return creds

def parse_too_old_failure(message: str):
    """Parse an error from watch API when resource version is too old
    
    Args:
        message (str): The message returned from the ApiException
    """

    # Regular expression to match the resource version in the message
    regex = r"too old resource version: .* \((.*)\)"

    # Check if a match is found
    result = re.search(regex, message)
    if result == None:
        return None
    
    # Extract the resource version from the match
    match = result.group(1)
    if match == None:
        return None
    
    # Attempt to convert the resource version to an integer
    try:
        return int(match)
    except:
        return None

def create_db_if_not_exists(cur, db_name):
    """A function to create a database if it does not already exist"""

    cur.execute("SELECT 1 FROM pg_database WHERE datname = '{}';".format(db_name))
    if not cur.fetchone():
        cur.execute("CREATE DATABASE {};".format(db_name))
        return True
    else:
        return False

def create_role_not_exists(cur, role_name, role_password):
    '''
    A function to create a role if it does not already exist
    '''
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = '{}';".format(role_name))
    if not cur.fetchone():
        cur.execute("CREATE ROLE {0} PASSWORD '{1}' LOGIN;".format(role_name, role_password))
        return True
    else:
        return False

def onDeleteEvent(spec, cur):
    try:
        drop_db = spec['onDeletion']['dropDB']
    except KeyError:
        drop_db = False
    
    if drop_db == True:
        try:
            cur.execute("DROP DATABASE {0};".format(spec['dbName']))
        except psycopg2.OperationalError as e:
            logger.error('Dropping of dbName {0} failed: {1}'.format(spec['dbName'], e))
        else:
            logger.info('Dropped dbName {0}'.format(spec['dbName']))
    else:
        logger.info('Ignoring deletion for dbName {0}, onDeletion setting not enabled'.format(spec['dbName']))
    
    try:
        drop_role = spec['onDeletion']['dropRole']
    except KeyError:
        drop_role = False
    
    if drop_role == True:
        try:
            cur.execute("DROP ROLE {0};".format(spec['dbRoleName']))
        except Exception as e:
            logger.error('Error when dropping role {0}: {1}'.format(spec['dbRoleName'], e))
        else:
            logger.info('Dropped role {0}'.format(spec['dbRoleName']))
    else:
        logger.info('Ignoring deletion of role {0}, onDeletion setting not enabled'.format(spec['dbRoleName']))
    
    logger.info('Deleted')

def onCreateEvent(spec, cur, db_credentials):
    logger.info('Adding dbName {0}'.format(spec['dbName']))
    
    db_created = create_db_if_not_exists(cur, spec['dbName'])
    if db_created:
        logger.info('Database {0} created'.format(spec['dbName']))
    else:
        logger.info('Database {0} already exists'.format(spec['dbName']))
    
    role_created = create_role_not_exists(cur, spec['dbRoleName'], spec['dbRolePassword'])
    if role_created:
        logger.info('Role {0} created'.format(spec['dbRoleName']))
    else:
        logger.info('Role {0} already exists'.format(spec['dbRoleName']))
    
    cur.execute("GRANT ALL PRIVILEGES ON DATABASE {0} to {1};".format(spec['dbName'], spec['dbRoleName']))
    try:
        created_db_conn = psycopg2.connect(host=db_credentials['host'], port=db_credentials['port'], dbname=spec['dbName'], user=db_credentials['user'], password=db_credentials['password'])
        created_db_cur = created_db_conn.cursor()
        created_db_conn.set_session(autocommit=True)
        
        created_db_cur.execute("GRANT USAGE, CREATE ON SCHEMA public TO {0};".format(spec['dbRoleName'])) 
        created_db_cur.execute("GRANT ALL ON SCHEMA public TO {0};".format(spec['dbRoleName']))
        created_db_cur.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {0};".format(spec['dbRoleName']))
        
        created_db_cur.close()
    except Exception as e:
        logger.error('Error when connecting to DB {0} (to grant proper permissions): {1}'.format(spec['dbName'], e))
        return
    
    if ('dbExtensions' in spec or 'extraSQL' in spec) and not db_created:
        logger.info('Ignoring extra SQL commands dbName {0} as it is already created'.format(spec['dbName']))
    elif ('dbExtensions' in spec or 'extraSQL' in spec) and db_created:
        user_credentials = {
            **db_credentials,
            **{
                'dbname': spec['dbName'],
                'user': spec['dbRoleName'],
                'password':  spec['dbRolePassword'],
            }
        }

        admin_credentials = {
            **db_credentials,
            **{
                'dbname': spec['dbName']
            },
        }

        if 'dbExtensions' in spec:
            db_conn = psycopg2.connect(**admin_credentials)
            db_cur = db_conn.cursor()
            db_conn.set_session(autocommit=True)
            for ext in spec['dbExtensions']:
                logger.info('Creating extension {0} in dbName {1}'.format(ext, spec['dbName']))
                db_cur.execute('CREATE EXTENSION IF NOT EXISTS "{0}";'.format(ext))
            
        if 'extraSQL' in spec:
            db_conn = psycopg2.connect(**user_credentials)
            db_cur = db_conn.cursor()
            db_conn.set_session(autocommit=False)
            logger.info('Running extra SQL commands for in dbName {0}'.format(spec['dbName']))
            try:
                db_cur.execute(spec['extraSQL'])
                db_conn.commit()
            except psycopg2.OperationalError as e:
                logger.error('OperationalError when running extraSQL for dbName {0}: {1}'.format(spec['dbName'], e))
            except psycopg2.ProgrammingError as e:
                logger.error('ProgrammingError when running extraSQL for dbName {0}: {1}'.format(spec['dbName'], e))
            
        db_cur.close()

    logger.info('Added PostgresDatabase dbName {0}'.format(spec['dbName']))

def process_event(crds: client.CustomObjectsApi, obj: dict, event_type: str, runtime_config: PostgresControllerConfig):
    """Processes events in order to create or drop databases
    
    Args:
        crds (client.CustomObjectsApi): The CustomObjectsApi object to interact with the Kubernetes API
        obj (dict): The object from the watch event
        event_type (str): The type of event, either ADDED, MODIFIED, or DELETED
        runtime_config (PostgresControllerConfig): The runtime configuration object
    """

    # Parse the data from the watch event
    spec = ValueReplacer(obj.get('spec')).replace_config_map_values_or_secrets()
    metadata = obj.get('metadata')
    k8s_resource_name = metadata.get('name')

    logger = logging.LoggerAdapter(logging.getLogger(), {'resource_name': k8s_resource_name})

    logger.debug('Processing event {0}: Metadata: {1}, Spec: {2}'.format(event_type, str(metadata), str(spec)))

    # Don't process if the event type is MODIFIED as it's not supported
    #if event_type == 'MODIFIED':
    #    logger.debug('Ignoring modification for DB {0}, not supported'.format(spec['dbName']))
    #    return
    
    # Get the database credentials from the controller's configuration
    db_credentials = runtime_config.get_credentials(instance_id=spec.get('dbInstanceId'))

    # Verify got credentials
    if db_credentials == None:
        logger.error('No corresponding postgres instance in configuration for instance id {0}'.format(spec.get('dbInstanceId')))
        return

    try:
        logger.debug('Connecting to DB instance with credentials {0}'.format(str(db_credentials)))
        conn = psycopg2.connect(**db_credentials)
        cur = conn.cursor()
        conn.set_session(autocommit=True)
        if event_type == 'DELETED':
            onDeleteEvent(spec, cur)
        elif event_type == 'ADDED':
            onCreateEvent(spec, cur, db_credentials)
    except Exception as e:
        logger.error('Error when connecting to DB instance with credentials {0}: {1}'.format(str(db_credentials), e))
        return
    finally:
        # We want to close the connection regardless of what happens
        cur.close()
