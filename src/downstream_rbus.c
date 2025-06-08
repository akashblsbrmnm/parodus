/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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
 * @file xmidtsend_rbus.c
 *
 * @ To provide Xmidt send RBUS method to send events upstream.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <rbus.h>
#include "upstream.h"
#include "ParodusInternal.h"
#include "partners_check.h"
#include "xmidtsend_rbus.h"
#include "config.h"
#include "time.h"
#include "heartBeat.h"
#include "close_retry.h"

int invokeRbusMethod(const char *methodName, const char *params, char **response)
{
    rbusError_t err;
    rbusHandle_t handle;
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    char *methodPath = NULL;
    cJSON *jsonParams = NULL;
    char *responseStr = NULL;

    if (!methodName) {
        ParodusError("Invalid method name\n");
        return -1;
    }

    // Initialize RBUS
    err = rbus_open(&handle, "parodus");
    if (err != RBUS_ERROR_SUCCESS) {
        ParodusError("Failed to open RBUS connection: %s\n", rbusError_ToString(err));
        return -1;
    }

    // Initialize input parameters
    rbusObject_Init(&inParams, NULL);

    // Parse and set input parameters if provided
    if (params) {
        jsonParams = cJSON_Parse(params);
        if (jsonParams) {
            cJSON *current = NULL;
            cJSON_ArrayForEach(current, jsonParams) {
                if (current->string) {
                    rbusValue_Init(&value);
                    switch (current->type) {
                        case cJSON_String:
                            rbusValue_SetString(value, current->valuestring);
                            break;
                        case cJSON_Number:
                            if (current->valuedouble == (double)current->valueint) {
                                rbusValue_SetInt32(value, current->valueint);
                            } else {
                                rbusValue_SetDouble(value, current->valuedouble);
                            }
                            break;
                        case cJSON_True:
                            rbusValue_SetBoolean(value, true);
                            break;
                        case cJSON_False:
                            rbusValue_SetBoolean(value, false);
                            break;
                        default:
                            ParodusError("Unsupported parameter type for key: %s\n", current->string);
                            rbusValue_Release(value);
                            continue;
                    }
                    rbusObject_SetValue(inParams, current->string, value);
                    rbusValue_Release(value);
                }
            }
            cJSON_Delete(jsonParams);
        }
    }

    // Construct method path - assuming format: <component>.<method>
    // For example: "Device.Reboot" or "Device.X_CISCO_COM_FactoryReset"
    methodPath = strdup(methodName);
    if (!methodPath) {
        ParodusError("Failed to allocate memory for method path\n");
        rbusObject_Release(inParams);
        rbus_close(handle);
        return -1;
    }

    // Invoke the method
    err = rbusMethod_Invoke(handle, methodPath, inParams, &outParams);
    if (err != RBUS_ERROR_SUCCESS)
    {
        ParodusError("Failed to invoke method %s: %s\n", methodPath, rbusError_ToString(err));
        free(methodPath);
        rbusObject_Release(inParams);
        rbus_close(handle);
        return -1;
    }

    // Convert output parameters to JSON string
    if (outParams)
    {
        FILE *fp = tmpfile();
        if (fp) {
            rbusObject_fwrite(outParams, 1, fp);
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            
            responseStr = malloc(size + 1);
            if (responseStr) {
                fread(responseStr, 1, size, fp);
                responseStr[size] = '\0';
                *response = responseStr;
            }
            fclose(fp);
        }
        rbusObject_Release(outParams);
    }

    // Cleanup
    free(methodPath);
    rbusObject_Release(inParams);
    rbus_close(handle);

    return 0;
} 