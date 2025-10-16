/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/**
 * @file method_handler.c
 *
 * @ To provide Xmidt send RBUS method to send events upstream.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <cJSON.h>
#include <wrp-c.h>
#include <rbus.h>
#include "ParodusInternal.h"

#include "method_handler.h"


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
	if(!methodObj)
	{
		ParodusError("Missing method field in request payload\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Missing method field in request payload");
		cJSON_Delete(jsonPayload);
		return -1;
	}
	else if (!cJSON_IsString(methodObj))
	{
		ParodusError("Method name is not a string\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Method name is not a string");
		cJSON_Delete(jsonPayload);
		return -1;
	}

	methodName = methodObj->valuestring;
	if (!methodName || !*methodName)
	{
		ParodusError("Method name is Empty/NULL in request payload\n");
		setMethodResponse(response, METHOD_STATUS_INVALID_REQUEST, "Method name is Empty/NULL in request payload");
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

int rbus_methodHandler(const char *methodName, cJSON *jsonPayload, char **methodResponseOut, int *crudStatusOut)
{
	rbusHandle_t rbus_handle = get_parodus_rbus_Handle();
    if (!rbus_handle)
    {
        ParodusError("rbus_methodHandler failed. rbus_handle is NULL\n");
		if (crudStatusOut) *crudStatusOut = METHOD_STATUS_FAILURE;
		if(methodResponseOut)
		{
			cJSON *respObj = cJSON_CreateObject();
			cJSON_AddStringToObject(respObj, "message", "rbus_handle is NULL");
			cJSON_AddNumberToObject(respObj, "statusCode", METHOD_STATUS_FAILURE);
			*methodResponseOut = cJSON_PrintUnformatted(respObj);
			cJSON_Delete(respObj);
		}
        return -1;
    }

    rbusError_t ret;
	rbusObject_t inParams = NULL, outParams = NULL;
	rbusObject_Init(&inParams, NULL);
    if(methodResponseOut) *methodResponseOut = NULL;
	if (crudStatusOut) *crudStatusOut = METHOD_STATUS_FAILURE;
	const char* typeStr = "param";
	int validCount = 0;
	cJSON *item = NULL;

    // Extract and process each item in the JSON payload
    cJSON_ArrayForEach(item, jsonPayload)
    {
        if (!item->string) continue;
        if (strcmp(item->string, "method") == 0) continue;
        if (strcmp(item->string, "params") == 0)
		{
			/*
			* Object with key-value pairs
			* Example: "params": { "key": "val" }
			*/
			if (cJSON_IsObject(item))
			{
				cJSON *inner = NULL;
				cJSON_ArrayForEach(inner, item)
				{
					if (!inner->string) continue;

					rbusValue_t val;
					rbusValue_Init(&val);

					if (cJSON_IsString(inner))
					{
						if (inner->valuestring)
						{
							const char* s = inner->valuestring;
							rbusValue_SetString(val, s);
						}
						else
						{
							rbusValue_Release(val);
							continue;
						}
					}
					else if (cJSON_IsNumber(inner))
                    {
                        double d = inner->valuedouble;
                        if (d >= INT32_MIN && d <= INT32_MAX && floor(d) == d)
                            rbusValue_SetInt32(val, (int32_t)d);
                        else
                            rbusValue_SetDouble(val, d);
                    }
					else if (cJSON_IsBool(inner))
					{
						rbusValue_SetBoolean(val, cJSON_IsTrue(inner));
					}
					else
					{
						ParodusInfo("Skipping unsupported nested type for key: %s\n", inner->string);
						rbusValue_Release(val);
						continue;
					}
					rbusObject_SetValue(inParams, inner->string, val);
					validCount++;
					rbusValue_Release(val);
				}
			}
			else if (cJSON_IsArray(item))
			{
				int idx = 0;
				cJSON *inner = NULL;
				cJSON_ArrayForEach(inner, item)
				{
					char key[256];
					snprintf(key, sizeof(key), "%s%d", typeStr, idx++);
					/*
					* Object as an array of strings
					* Example: "params": ["val1","val2"]
					*/
					if (cJSON_IsString(inner))
					{
						rbusValue_t val;
						rbusValue_Init(&val);
						rbusValue_SetString(val, inner->valuestring);
						rbusObject_SetValue(inParams, key, val);
						validCount++;
						rbusValue_Release(val);
					}
					/*
					* Object as an array of nested key-value pairs
					* Example: "params": [ { "key1": "val1" }, { "key2": "val2" }  ]
					*/
					else if (cJSON_IsObject(inner))
					{
						rbusObject_t subObj;
						rbusObject_Init(&subObj, key);

						cJSON *field = NULL;
						cJSON_ArrayForEach(field, inner)
						{
							if (!field->string) continue;

							rbusValue_t val;
							rbusValue_Init(&val);

							if (cJSON_IsString(field))
							{
								if (field->valuestring)
								{
									rbusValue_SetString(val, field->valuestring);
								}
								else
								{
									rbusValue_Release(val);
									continue;
								}
							}
							else if (cJSON_IsNumber(field))
                            {
                                double d = field->valuedouble;
                                if (d >= INT32_MIN && d <= INT32_MAX && floor(d) == d)
								{
									rbusValue_SetInt32(val, (int32_t)d);
								}
                                else
								{
									rbusValue_SetDouble(val, d);
								}
                            }
							else if (cJSON_IsBool(field))
							{
								rbusValue_SetBoolean(val, cJSON_IsTrue(field));
							}
							else
							{
								ParodusInfo("Skipping unsupported type for field: %s\n", field->string);
								rbusValue_Release(val);
								continue;
							}
							rbusObject_SetValue(subObj, field->string, val);
							rbusValue_Release(val);
							validCount++;
						}
						rbusValue_t objVal;
						rbusValue_Init(&objVal);
						rbusValue_SetObject(objVal, subObj);
						rbusObject_SetValue(inParams, key, objVal);
						rbusValue_Release(objVal);
						rbusObject_Release(subObj);
					}
					else
                    {
						ParodusInfo("Skipping unsupported array entry type\n");
                    }
				}
			}
			else
            {
                ParodusInfo("Unsupported input format\n");
				if (crudStatusOut) *crudStatusOut = METHOD_STATUS_INVALID_REQUEST;
				if(methodResponseOut)
				{
					cJSON *respObj = cJSON_CreateObject();
					cJSON_AddStringToObject(respObj, "message", "Unsupported input format");
					cJSON_AddNumberToObject(respObj, "statusCode", METHOD_STATUS_INVALID_REQUEST);
					*methodResponseOut = cJSON_PrintUnformatted(respObj);
					cJSON_Delete(respObj);
				}
				return -1;
            }
		}
		else
		{
			ParodusError("Missing params field in request payload\n");
			if (crudStatusOut) *crudStatusOut = METHOD_STATUS_INVALID_REQUEST;
			if(methodResponseOut)
			{
				cJSON *respObj = cJSON_CreateObject();
				cJSON_AddStringToObject(respObj, "message", "Missing params field in request payload");
				cJSON_AddNumberToObject(respObj, "statusCode", METHOD_STATUS_INVALID_REQUEST);
				*methodResponseOut = cJSON_PrintUnformatted(respObj);
				cJSON_Delete(respObj);
			}
			return -1;
		}
    }

	if (validCount == 0)
	{
		ParodusError("No valid entries found. Invalid input. The request may contain malformed json, missing fields, or unsupported value types\n");
		if (crudStatusOut) *crudStatusOut = METHOD_STATUS_INVALID_REQUEST;
		if(methodResponseOut)
		{
			cJSON *respObj = cJSON_CreateObject();
			cJSON_AddStringToObject(respObj, "message", "No valid entries found. Invalid input. The request may contain malformed json, missing fields, or unsupported value types");
			cJSON_AddNumberToObject(respObj, "statusCode", METHOD_STATUS_INVALID_REQUEST);
			*methodResponseOut = cJSON_PrintUnformatted(respObj);
			cJSON_Delete(respObj);
		}
		return -1;
	}

    // Invoke the rbus method
    ret = rbusMethod_Invoke(rbus_handle, methodName, inParams, &outParams);

	if(ret == RBUS_ERROR_SUCCESS)
	{
		ParodusInfo("rbusMethod_Invoke for %s is success\n", methodName);
	}
	else if(ret == RBUS_ERROR_DESTINATION_NOT_FOUND)
	{
		if (crudStatusOut) *crudStatusOut = METHOD_STATUS_FAILURE;
		if(methodResponseOut)
		{
			cJSON *respObj = cJSON_CreateObject();
			cJSON_AddStringToObject(respObj, "message", "Destination method not found");
			cJSON_AddNumberToObject(respObj, "statusCode", METHOD_STATUS_FAILURE);
			*methodResponseOut = cJSON_PrintUnformatted(respObj);
			cJSON_Delete(respObj);
		}
		return -1;
	}
	else
	{
		ParodusInfo("rbusMethod_Invoke for %s is failed. err: %s\n", methodName, rbusError_ToString(ret));
	}
	rbusObject_Release(inParams);

	int status_code = -1;
	const char *return_message = NULL;
	rbusValue_t outVal = NULL;

	if ((outVal = rbusObject_GetValue(outParams, "message")) != NULL)
		return_message = rbusValue_GetString(outVal, NULL);

	if ((outVal = rbusObject_GetValue(outParams, "statusCode")) != NULL)
		status_code = rbusValue_GetInt32(outVal);

/* 
* Fallback: if outParams did not set message or statusCode,
* use RBUS result to infer a generic response.
*/
	if (!return_message)
		return_message = (ret == RBUS_ERROR_SUCCESS) ? "Success" : rbusError_ToString(ret);
	if(status_code == -1)
		status_code = (ret == RBUS_ERROR_SUCCESS) ? METHOD_STATUS_SUCCESS : METHOD_STATUS_FAILURE;

	if(methodResponseOut)
		*methodResponseOut = strdup(return_message);
	if(crudStatusOut)
		*crudStatusOut = status_code;

    if (outParams)
        rbusObject_Release(outParams);
	return ret;
}

