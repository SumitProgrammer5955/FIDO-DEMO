/*
 * Copyright 2024 Google Inc. All Rights Reserved.
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
 */

package com.example.android.fido2.api

import com.example.android.fido2.data.RegisterBiometricDataToServer
import com.example.android.fido2.data.RegisterResponse
import com.example.android.fido2.data.RegisterUser
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

interface ApiService {

    @POST("/webauthn/register")
    suspend fun register(@Body registerUser: RegisterUser): Response<ResponseBody>

    @POST("/webauthn/login")
    suspend fun login(@Body body: Map<String, String>): Response<ResponseBody>

    @POST("/webauthn/response")
    suspend fun response(@Body data : RegisterBiometricDataToServer): Response<ResponseBody>

    @GET("/personalInfo")
    suspend fun personalInfo(): Response<ResponseBody>

}