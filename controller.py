#!/usr/bin/env python3

from typing import Callable

import json
from kubernetes import client, watch
from functions import PostgresControllerConfig, process_event, create_logger, parse_too_old_failure


runtime_config = PostgresControllerConfig()
crds = client.CustomObjectsApi()
logger = create_logger(log_level=runtime_config.args.log_level)


resource_version = ''

def check_and_handle_410(code: int, obj: dict):
    """Because watching an API resource can expire and if the last result is too old as well, an ApiException exception will be thrown with code 410. 
    In that case, this method attempts to recover itself by listing the API resource to obtain the latest state and then watching from that state on by setting resource_version to one returned from listing.

    Args:
        code (int): The error code returned by the ApiException
    """
    
    # If the resource version is too old, update it
    if code == 410:
        logger.debug('Error code 410')
        new_version = parse_too_old_failure(obj.get('message'))
        if new_version == None:
            logger.error('Failed to parse 410 error code')
            resource_version = ''
        else:
            resource_version = new_version
            logger.debug('Updating resource version to {0} due to "too old" error'.format(new_version))
        
        return resource_version

def on_CRD_watch_each_event(event: dict) -> bool:
    """Process each event from the watch on the pgdatabases custom resource

    Args:
        event (dict): The event from the watch

    Returns:
        bool: True if the event was processed successfully, False otherwise
    """

    event_type = event["type"]
    obj = event["object"]

    # Parse the object
    metadata = obj.get('metadata')
    spec = obj.get('spec')
    code = obj.get('code')

    # Check if the object is too old (code 410)
    result_for_410_check = check_and_handle_410(code, obj)
    if result_for_410_check == '':
        logger.error('Failed to recover from 410 error')
        return False
    
    # Check that the object has metadata and spec fields
    if not metadata or not spec:
        logger.error('No metadata or spec in object, skipping: {0}'.format(json.dumps(obj, indent=1)))
        return False

    if metadata['resourceVersion'] is not None:
        resource_version = metadata['resourceVersion']
        logger.debug('resourceVersion now: {0}'.format(resource_version))
    
    # Process the event (CREATE, DELETE, etc...)
    process_event(crds, obj, event_type, runtime_config)

    return True

def watch_for_new_CRD():
    # Watch for creation of the pgdatabases custom resource
    stream = watch.Watch().stream(crds.list_cluster_custom_object, 'postgresql.org', 'v1', 'pgdatabases', resource_version=resource_version)
    try:
        # Loop through the stream of events
        for event in stream:
            on_CRD_watch_each_event(event)
    except client.rest.ApiException as e:
        if e.status == 404:
            logger.error('Custom Resource Definition not created in cluster')
            return False
        elif e.status == 401:
            logger.error('Unauthorized')
            return False
        else:
            raise e
    except KeyboardInterrupt:
        return False

def check_bool(result: bool) -> bool:
    """Wrapper function to return boolean value based on function return (which is already a boolean)"""
    return result

def run_continuously(func: Callable, check: Callable[..., bool]):
    """Run a function continuously until the check function returns False

    Args:
        func (callable): The function to run in a continuous loop
        check (callable): The function to check the return value of func
    """

    continue_looping = True
    while continue_looping:
        continue_looping = check(func())

def start():
    """Start the controller"""
    logger.info('postgres-controller initializing')

    # Run the controller continuously
    run_continuously(watch_for_new_CRD, check_bool)

if __name__ == "__main__":
    start()