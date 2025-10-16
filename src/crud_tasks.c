#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cJSON.h>
#include <wrp-c.h>
#include "crud_tasks.h"
#include "crud_internal.h"

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

#ifdef ENABLE_WEBCFGBIN
	if (strstr(reqMsg->u.crud.dest, "/parodus/method"))
	{
		ret = processMethodRequest(reqMsg, &resp_msg);
		*responseMsg = resp_msg;
		if(ret == -1)
		{
			ParodusError("method failed to invoke\n");
			return -1;
		}
		break;
	}
#endif

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

#ifdef ENABLE_WEBCFGBIN
int processMethodRequest(wrp_msg_t *reqMsg, wrp_msg_t **response)
{
    int ret = -1;
	const char *methodName = NULL;
    char *methodResponse = NULL;
    int crudStatus = 0;

	// Validate request and payload
    if (!reqMsg || !reqMsg->u.crud.payload)
    {
        ParodusError("Input payload is empty/NULL\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Input payload is empty/NULL");
        return -1;
    }

    // Parse JSON payload from reqMsg
    cJSON *jsonPayload = cJSON_Parse(reqMsg->u.crud.payload);
    if (!jsonPayload)
    {
        ParodusError("Failed to parse JSON payload\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Failed to parse JSON payload");
        return -1;
    }

    // Extract method field
    cJSON *methodObj = cJSON_GetObjectItem(jsonPayload, "method");
    if (!cJSON_IsString(methodObj))
    {
        ParodusError("Invalid method field in request payload\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Invalid method field in request payload");
        cJSON_Delete(jsonPayload);return -1;
    }

	methodName = methodObj->valuestring;
	if(!methodName)
	{
		ParodusError("Missing method name in request payload\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Missing method name in request payload");
        cJSON_Delete(jsonPayload);
        return -1;
	}

	size_t len = strlen(methodName);
	if (len < 2 || strcmp(methodName + len - 2, "()") != 0)
	{
		ParodusError("Invalid method name %s. Method names must end with ()\n", methodName ? methodName : "");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Invalid method name. Method names must end with ()");
        cJSON_Delete(jsonPayload);
		return -1;
	}

	ret = rbus_methodHandler(methodName, jsonPayload, &methodResponse, &crudStatus);
	if (response && *response)
	{
		if (methodResponse)
		{
			(*response)->u.crud.payload = strdup(methodResponse);
			(*response)->u.crud.payload_size = strlen(methodResponse);
		}
		(*response)->u.crud.status = crudStatus;
		ParodusInfo("Response from rbus_methodHandler: %s\n", methodResponse ? methodResponse : "");
	}
    if (methodResponse)
        free(methodResponse);
    cJSON_Delete(jsonPayload);
    return ret;
}
#endif

void setMethodResponse(wrp_msg_t **response, int statusCode, const char *message)
{
    if (!response || !*response)
	{
		ParodusError("wrp rrsponse is NULL\n");
        return;
	}

    cJSON *respObj = cJSON_CreateObject();
    if (!respObj)
	{
		ParodusError("json response object failed to create\n");
        return;
	}

    cJSON_AddStringToObject(respObj, "message", message ? message : "");
    cJSON_AddNumberToObject(respObj, "statusCode", statusCode);

    char *respStr = cJSON_PrintUnformatted(respObj);
    cJSON_Delete(respObj);

    if (respStr)
    {
        (*response)->u.crud.status = statusCode;
        (*response)->u.crud.payload = respStr;
        (*response)->u.crud.payload_size = strlen(respStr);
    }
	return;
}
