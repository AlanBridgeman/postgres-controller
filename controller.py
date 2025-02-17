#!/usr/bin/env python3

from typing import Callable

import json, time, copy
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
    #code = obj.get('code')

    # Check if the object is too old (code 410)
    #result_for_410_check = check_and_handle_410(code, obj)
    #if result_for_410_check == '':
    #    logger.error('Failed to recover from 410 error')
    #    return False
    
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

class Controller:
    def __init__(self, poll_interval: int = 5):
        """Initialize the controller
        
        Args:
            poll_interval (int, optional): The interval in seconds to poll for new CRDs. Defaults to 5.
        """

        self.poll_interval = poll_interval

        # List to hold already processed CRDs
        self.db_list = {}
    

    def watch_for_new_CRD(self):
        # Get a list of all the pgdatabases custom resources (in all namespaces)
        items = crds.list_custom_object_for_all_namespaces('postgresql.org', 'v1', 'pgdatabases')['items']

        # Loop through the list of CRD definitions
        for item in items:
            # We want to check if the currently processed CRD instance is new or not (already in the list)
            if item.get('metadata').get('uid') not in self.db_list:
                logger.info('New CRD: {0}'.format(str(item)))

                # Process the event
                on_CRD_watch_each_event({ 'type': 'ADDED', 'object': item })
                
                # Add the item to the list of processed CRDs
                self.db_list[item.get('metadata').get('uid')] = item
            else:
                logger.debug('CRD with UID {0} already processed.'.format(str(item.get('metadata').get('uid'))))
        
        # Get all the UIDs of the processed CRDs
        # Do this here rather than directly in the loop condition because it changes as we loop through the items
        # And Python will error if we try to use it directly in the loop condition
        uids = copy.deepcopy(list(self.db_list.keys()))
        
        # Loop through the list of processed CRD instances
        # This is so that we can identify any that have been processed but have since been deleted
        for uid in uids:
            if uid not in [x.get('metadata').get('uid') for x in items]:
                # Remove the item from the list of processed CRDs
                # And return the item from the list
                item = self.db_list.pop(uid)

                logger.info('CRD deleted: {0}'.format(str(item)))
        
                # Process the delete event
                on_CRD_watch_each_event({ 'type': 'DELETED', 'object': item })
            else:
                logger.debug('CRD with UID {0} still exists'.format(uid))

        # Wait for the poll interval
        time.sleep(self.poll_interval)

        # We want to keep running the controller
        return True

# Note (Feb 16, 2025): For whatever reason, the event received doesn't seem to follow the expected format.
#                      More specifically the `Watch.unmarshal_event`` method doesn't seem to work properly.
#                      Unfortunately, there doesn't seem to be an open issue on this (that I could find).
#                      So, my assumption is it's some kind of implementation issue I've created but can't seem to figure out right now.
#                      
#                      Consequently, for the moment, I'm going to use a different approach to detect if the CRD is created.
#def watch_for_new_CRD():
#    # Watch for creation of the pgdatabases custom resource
#    stream = watch.Watch().stream(logger, crds.list_custom_cluster_object, 'postgresql.org', 'v1', 'pgdatabases', resource_version=resource_version)
#
#    try:
#        # Loop through the stream of events
#        for event in stream:
#            on_CRD_watch_each_event(event)
#    except client.rest.ApiException as e:
#        if e.status == 404:
#            logger.error('Custom Resource Definition not created in cluster')
#            return False
#        elif e.status == 401:
#            logger.error('Unauthorized')
#            return False
#        else:
#            raise e
#    except KeyboardInterrupt:
#        return False

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

    controller = Controller()

    # Run the controller continuously
    run_continuously(controller.watch_for_new_CRD, check_bool)

if __name__ == "__main__":
    start()