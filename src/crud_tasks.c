#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "/home/akash/rbus/rbus/include/rbus.h"
#include <cJSON.h>
#include <wrp-c.h>
#include "crud_tasks.h"
#include "crud_internal.h"
#include "xmidtsend_rbus.h"


int processCrudRequest( wrp_msg_t *reqMsg, wrp_msg_t **responseMsg)
{
	wrp_msg_t *resp_msg = NULL;
    int ret = -1;

    resp_msg = ( wrp_msg_t *)malloc( sizeof( wrp_msg_t ) );  
    memset(resp_msg, 0, sizeof(wrp_msg_t));

    resp_msg->msg_type = reqMsg->msg_type;
    resp_msg->u.crud.transaction_uuid = strdup(reqMsg->u.crud.transaction_uuid);
    resp_msg->u.crud.source = strdup(reqMsg->u.crud.dest);
    resp_msg->u.crud.dest = strdup(reqMsg->u.crud.source);

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

	if (strstr(reqMsg->u.crud.dest, "/parodus/method"))
	{
		ParodusInfo("Processing method invocation request\n");
		ret = processMethodRequest(reqMsg, &resp_msg);
		if (ret != 0)
		{
			ParodusError("Failed to Invoke method\n");
			resp_msg->u.crud.payload = NULL;
			resp_msg->u.crud.payload_size = 0;
			*responseMsg = resp_msg;
	    	return -1;
		}
		*responseMsg = resp_msg;
		break;
	}
	
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
    char *methodResponse = NULL;

    ParodusInfo("Processing method request\n");

    if (!reqMsg || !reqMsg->u.crud.payload)
    {
        ParodusError("Invalid method request - missing payload\n");
        if (response && *response)
            (*response)->u.crud.status = 400;
        return -1;
    }

    // Parse JSON payload from reqMsg
    cJSON *jsonPayload = cJSON_Parse(reqMsg->u.crud.payload);
    if (!jsonPayload)
    {
        ParodusError("Failed to parse method payload\n");
        if (response && *response)
            (*response)->u.crud.status = 400;
        return -1;
    }

    // Extract the "Method" field (now expected to contain full RBUS method name)
    cJSON *methodObj = cJSON_GetObjectItem(jsonPayload, "method");
    if (!cJSON_IsString(methodObj) || methodObj->valuestring == NULL)
    {
        ParodusError("Missing or invalid 'Method' field in payload\n");
        cJSON_Delete(jsonPayload);
        if (response && *response)
            (*response)->u.crud.status = 400;
        return -1;
    }

    const char *methodName = methodObj->valuestring;
    ParodusInfo("Received UPDATE method: '%s'\n", methodName);

    // Call the RBUS method handler directly with the full payload
    status = rbus_methodHandler(methodName, jsonPayload, &methodResponse);

    if (status == 0)
    {
        if (response && *response)
        {
            (*response)->u.crud.status = 200;
            if (methodResponse)
            {
                ParodusInfo("Response from method call: %s\n", methodResponse);
                (*response)->u.crud.payload = strdup(methodResponse);
                (*response)->u.crud.payload_size = strlen(methodResponse);
            }
        }
    }
    else
    {
        ParodusError("rbus_methodHandler failed with status: %d\n", status);
        if (response && *response)
            (*response)->u.crud.status = 500;
    }

    if (methodResponse)
        free(methodResponse);
    cJSON_Delete(jsonPayload);
    return status;
}
