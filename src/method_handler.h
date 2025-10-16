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
 * @file xmidtsend_rbus.h
 *
 * @description This header defines functions required to manage xmidt send messages via rbus.
 *
 */
 
#ifndef _METHOD_HANDLER_H_
#define _METHOD_HANDLER_H_

typedef enum
{
    METHOD_STATUS_SUCCESS               = 200,
    METHOD_STATUS_FAILURE               = 500,
    METHOD_STATUS_MULTI_STATUS          = 207,
    METHOD_STATUS_INVALID_REQUEST       = 400,
    METHOD_STATUS_BOOTUP_IN_PROGRESS    = 503
} METHOD_STATUS_CODE;

rbusHandle_t get_parodus_rbus_Handle(void);
int processMethodRequest(wrp_msg_t *reqMsg, wrp_msg_t **response);
void setMethodResponse(wrp_msg_t **response, int statusCode, const char *message);
int rbus_methodHandler(const char *methodName, cJSON *jsonPayload, char **methodResponseOut, int *crudStatusOut);

#endif /* _METHOD_HANDLER_H_ */