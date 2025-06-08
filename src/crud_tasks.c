#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cJSON.h>
#include <wrp-c.h>
#include "crud_tasks.h"
#include "crud_internal.h"


int processCrudRequest( wrp_msg_t *reqMsg, wrp_msg_t **responseMsg)
{
	if(reqMsg == NULL)
	{
		ParodusError("Invalid request message\n");
		return -1;
	}

	wrp_msg_t *resp_msg = NULL;
    int ret = -1;
	char *destVal = NULL;


    resp_msg = ( wrp_msg_t *)malloc( sizeof( wrp_msg_t ) );  
    memset(resp_msg, 0, sizeof(wrp_msg_t));

    resp_msg->msg_type = reqMsg->msg_type;
    resp_msg->u.crud.transaction_uuid = strdup(reqMsg->u.crud.transaction_uuid);
    resp_msg->u.crud.source = strdup(reqMsg->u.crud.dest);
    resp_msg->u.crud.dest = strdup(reqMsg->u.crud.source);

	// Check if this is a method invocation request
	if(strstr(reqMsg->u.crud.dest, "/method") != NULL)
	{
		ParodusInfo("Processing method invocation request\n");
		ret = processMethodRequest(reqMsg, &resp_msg);

		if(ret != 0)
		{
			ParodusError("Failed to Invoke method.\n");

			//WRP payload is NULL for failure cases
			resp_msg ->u.crud.payload = NULL;
			resp_msg ->u.crud.payload_size = 0;
			*responseMsg = resp_msg;
			return -1;
		}

	}

    switch( reqMsg->msg_type ) 
    {

	case WRP_MSG_TYPE__CREATE:
	ParodusInfo( "CREATE request\n" );

	ret = createObject( reqMsg, &resp_msg );

	if(ret != 0)
	{
		ParodusError("Failed to create object in config JSON\n");

		//WRP payload is NULL for failure cases
		resp_msg ->u.crud.payload = NULL;
		resp_msg ->u.crud.payload_size = 0;
		*responseMsg = resp_msg;
		return -1;
	}

	*responseMsg = resp_msg;
	break;

	case WRP_MSG_TYPE__RETREIVE:
	ParodusInfo( "RETREIVE request\n" );

	ret = retrieveObject( reqMsg, &resp_msg );
	if(ret != 0)
	{
	    ParodusError("Failed to retrieve object \n");

	    //WRP payload is NULL for failure cases
	    resp_msg ->u.crud.payload = NULL;
	    resp_msg ->u.crud.payload_size = 0;
	    *responseMsg = resp_msg;
	    return -1;
	}

	*responseMsg = resp_msg;
	break;

	case WRP_MSG_TYPE__UPDATE:
	ParodusInfo( "UPDATE request\n" );

	ret = updateObject( reqMsg, &resp_msg );
	if(ret ==0)
	{
		//WRP payload is NULL for update requests
		resp_msg ->u.crud.payload = NULL;
		resp_msg ->u.crud.payload_size = 0;
	}
	else
	{
		ParodusError("Failed to update object \n");
		*responseMsg = resp_msg;
		return -1;
	}
	*responseMsg = resp_msg;
	break;

	case WRP_MSG_TYPE__DELETE:
	ParodusInfo( "DELETE request\n" );

	ret = deleteObject(reqMsg, &resp_msg );
	if(ret == 0)
	{
		//WRP payload is NULL for delete requests
		resp_msg ->u.crud.payload = NULL;
		resp_msg ->u.crud.payload_size = 0;
	}
	else
	{
		ParodusError("Failed to delete object \n");
		*responseMsg = resp_msg;
		return -1;
	}
	*responseMsg = resp_msg;
	break;

	default:
	    ParodusInfo( "Unknown msgType for CRUD request\n" );
	    *responseMsg = resp_msg;
	    break;
     }

    return  0;
}

int processMethodRequest(wrp_msg_t *reqMsg, wrp_msg_t **response)
{
    int status = 0;
    char *methodName = NULL;
    char *params = NULL;
    char *methodResponse = NULL;
    cJSON *jsonPayload = NULL;

    ParodusInfo("Processing method request\n");

    if (!reqMsg || !reqMsg->u.crud.payload)
	{
        ParodusError("Invalid method request - missing payload\n");
        (*response)->u.crud.status = 400;
        return -1;
    }

    // Parse the payload to get method name and parameters
    jsonPayload = cJSON_Parse(reqMsg->u.crud.payload);
    if (!jsonPayload)
	{
        ParodusError("Failed to parse method payload\n");
        (*response)->u.crud.status = 400;
        return -1;
    }

    // Extract method name
    cJSON *methodObj = cJSON_GetObjectItem(jsonPayload, "method");
    if (!methodObj || !cJSON_IsString(methodObj))
	{
        ParodusError("Invalid or missing method name in payload\n");
        cJSON_Delete(jsonPayload);
        (*response)->u.crud.status = 400;
        return -1;
    }
    methodName = strdup(methodObj->valuestring);

    // Validate method name format (should be Device.Methods.*)
    if (!methodName || strncmp(methodName, "Device.Methods.", 14) != 0) {
        ParodusError("Invalid method name format. Expected format: Device.Methods.*\n");
        cJSON_Delete(jsonPayload);
        (*response)->u.crud.status = 400;
        if (methodName) free(methodName);
        return -1;
    }

    // Extract parameters if present
    cJSON *paramsObj = cJSON_GetObjectItem(jsonPayload, "params");
    if (paramsObj)
	{
        params = cJSON_PrintUnformatted(paramsObj);
    }

    // Invoke the method
    status = invokeRbusMethod(methodName, params, &methodResponse);

    // Create response
    if (status == 0)
	{
        (*response)->u.crud.status = 200;
        if (methodResponse)
		{
            (*response)->u.crud.payload = strdup(methodResponse);
            (*response)->u.crud.payload_size = strlen(methodResponse);
        }
    }
	else
	{
        (*response)->u.crud.status = 500;
    }

    // Cleanup
    if (methodName) free(methodName);
    if (params) free(params);
    if (methodResponse) free(methodResponse);
    cJSON_Delete(jsonPayload);

    return status;
}
