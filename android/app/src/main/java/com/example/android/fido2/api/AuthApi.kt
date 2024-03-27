/*
 * Copyright 2019 Google Inc. All Rights Reserved.
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

import android.util.JsonReader
import android.util.JsonToken
import android.util.JsonWriter
import android.util.Log
import com.example.android.fido2.BuildConfig
import com.example.android.fido2.data.RegisterBiometricDataToServer
import com.example.android.fido2.data.RegisterUser
import com.example.android.fido2.decodeBase64
import com.example.android.fido2.utils.ApiResponse
import com.google.android.gms.fido.fido2.api.common.Attachment
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import ru.gildor.coroutines.okhttp.await
import java.io.StringReader
import java.io.StringWriter
import javax.inject.Inject

/**
 * Interacts with the server API.
 */
class AuthApi @Inject constructor(
    private val client: OkHttpClient
) {

     class HeaderInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val originalRequest = chain.request()

            // Add headers to the request
            val modifiedRequest = originalRequest.newBuilder()
                .addHeader("session", challenge)
                .addHeader("username", username)
                .build()

            // Proceed with the modified request
            return chain.proceed(modifiedRequest)
        }
    }

    class HeaderInterceptor1 : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val originalRequest = chain.request()

            // Add headers to the request
            val modifiedRequest = originalRequest.newBuilder()
                .addHeader("ged", loggedIn)
                .addHeader("username", username)
                .build()

            // Proceed with the modified request
            return chain.proceed(modifiedRequest)
        }
    }

    object RetrofitClient {

        private val retrofit: Retrofit by lazy {
            Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
        }

        private val retrofitWithHeader: Retrofit by lazy {
            Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .client(OkHttpClient().newBuilder().addInterceptor(HeaderInterceptor()).build())
                .build()
        }

        private val retrofitWithHeader1: Retrofit by lazy {
            Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .client(OkHttpClient().newBuilder().addInterceptor(HeaderInterceptor1()).build())
                .build()
        }

        val apiService: ApiService by lazy {
            retrofit.create(ApiService::class.java)
        }

        val apiServiceHeader: ApiService by lazy {
            retrofitWithHeader.create(ApiService::class.java)
        }

        val apiServiceHeader1: ApiService by lazy {
            retrofitWithHeader1.create(ApiService::class.java)
        }
    }

    companion object {
        private const val BASE_URL = BuildConfig.API_BASE_URL
        private val JSON = "application/json".toMediaTypeOrNull()
        private const val SessionIdKey = "connect.sid="
        private const val TAG = "AuthApi"
        private var username : String = ""
        private var challenge : String = ""
        private var loggedIn : String = "failed"
    }

    /**
     * @param username The username to be used for sign-in.
     * @return The Session ID.
     */

    val json = """
        {
            "challenge": "-ktbgivDnI16SKNSuumrL10QhZDxmKzpAy54tPX72_0",
            "rp": {
                "id": "taas.softvisioncorp.com",
                "name": "CredMan App Test"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "required"
            },
            "user": {
                   "id": "7-Q9KSfByv2o7NBbA9xwlpo3SP5ARU2-PQoeUKtL4G8",
                   "name": "i",
                   "displayName": "i"
               }
        }
    """.trimIndent()

    suspend fun registerUserApi(name : String, username: String) : ApiResponse<PublicKeyCredentialCreationOptions> {
        return try {
            val response = RetrofitClient.apiService.register(RegisterUser(name, username))
            val body : ResponseBody? = response.body()
            if (response.isSuccessful && response.code() == 200) {
                Log.d("sumit","response successfully ${response.code()}")
                val option = parsePublicKeyCredentialCreationOptions(body!!)

                Log.d("sumit","register successfully")
                ApiResponse.Success(option)
            } else {
                val errorBody = response.errorBody()
                val gson = Gson()
                val mapType = object : TypeToken<Map<String, String>>() {}.type
                val map: Map<String, String> = gson.fromJson(errorBody?.string(), mapType)
                Log.d("sumit","register unsuccessfully ${errorBody?.string()}")
                ApiResponse.Error(map["message"])
            }
        } catch (e: Exception) {
            e.printStackTrace()
            ApiResponse.Error("${e.localizedMessage}")
        }
    }

    /**
     * @param sessionId The session ID to be used for the sign-in.
     * @param credential The PublicKeyCredential object.
     * @return A list of all the credentials registered on the server, including the newly
     * registered one.
     */
    suspend fun registerBiometricDataToServer(
        sessionId: String? = null,
        credential: RegisterBiometricDataToServer
    ) : ApiResponse<Boolean> {

        return try {
            Log.d("sumit", "request obj $credential")
            val response = RetrofitClient.apiServiceHeader.response(credential)
            val body: ResponseBody? = response.body()
            if (response.isSuccessful && response.code() == 200) {
                val body = response.body()
                val gson = Gson()
                val mapType = object : TypeToken<Map<String, String>>() {}.type
                val map: Map<String, String> = gson.fromJson(body?.string(), mapType)
                if (map["status"] == "ok") {
                    loggedIn = "ok"
                    username = map["name"] ?: ""
                } else {
                    loggedIn = "failed"
                    username = map["name"] ?: ""
                }
                Log.d("sumit","register successfully registerBiometricDataToServer ${body?.string()}")
                ApiResponse.Success(true)
            } else {
                Log.d("sumit","register unsuccessfully registerBiometricDataToServer ${body?.string()}")
                ApiResponse.Error(response.message())
            }
        } catch (e: Exception) {
            ApiResponse.Error(e.localizedMessage)
        }
//        val rawId = credential.rawId.toBase64()
//        val response = credential.response as AuthenticatorAttestationResponse
//
//        val call = client.newCall(
//            Request.Builder()
//                .url("$BASE_URL/registerResponse")
//                .addHeader("Cookie", formatCookie(sessionId))
//                .method("POST", jsonRequestBody {
//                    name("id").value(rawId)
//                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
//                    name("rawId").value(rawId)
//                    name("response").objectValue {
//                        name("clientDataJSON").value(
//                            response.clientDataJSON.toBase64()
//                        )
//                        name("attestationObject").value(
//                            response.attestationObject.toBase64()
//                        )
//                    }
//                })
//                .build()
//        )
//        val apiResponse = call.await()
//        return apiResponse.result("Error calling /registerResponse") {
//            parseUserCredentials(
//                body ?: throw ApiException("Empty response from /registerResponse")
//            )
//        }
    }

    /**
     * @param sessionId The session ID to be used for the sign-in.
     * @param credentialId The credential ID of this device.
     * @return A pair. The `first` element is a [PublicKeyCredentialRequestOptions] that can be used
     * for a subsequent FIDO2 API call. The `second` element is a challenge string that should
     * be sent back to the server in [sendLoginBiometricDataToServer].
     */
    suspend fun login(
        username: String
    ): ApiResponse<PublicKeyCredentialRequestOptions> {
        return try {
            val map = mapOf("username" to username)
            val response = RetrofitClient.apiService.login(map)
            Log.d("sumit","response successfully ${response.code()}")
            if (response.isSuccessful && response.code() == 200) {
                val body : ResponseBody? = response.body()
                val option = parsePublicKeyCredentialRequestOptions(body!!)
                Log.d("sumit","register successfully")
                ApiResponse.Success(option)
            } else {
                val errorBody = response.errorBody()
                val gson = Gson()
                val mapType = object : TypeToken<Map<String, String>>() {}.type
                val map: Map<String, String> = gson.fromJson(errorBody?.string(), mapType)
                Log.d("sumit","login unsuccessfully ${errorBody?.string()}")
                ApiResponse.Error(map["message"])
            }
        } catch (e: Exception) {
            e.printStackTrace()
            ApiResponse.Error("========================= ${e.localizedMessage}")
        }

//        val call = client.newCall(
//            Request.Builder()
//                .url(
//                    buildString {
//                        append("$BASE_URL/signinRequest")
//                        if (credentialId != null) {
//                            append("?credId=$credentialId")
//                        }
//                    }
//                )
//                .addHeader("Cookie", formatCookie(sessionId))
//                .method("POST", jsonRequestBody {})
//                .build()
//        )
//        val response = call.await()
//        return response.result("Error calling /signinRequest") {
//            parsePublicKeyCredentialRequestOptions(
//                body ?: throw ApiException("Empty response from /signinRequest")
//            )
//        }
    }

    /**
     * @param sessionId The session ID to be used for the sign-in.
     * @param credential The PublicKeyCredential object.
     * @return A list of all the credentials registered on the server, including the newly
     * registered one.
     */
    suspend fun sendLoginBiometricDataToServer(
        sessionId: String? = null,
        credential: RegisterBiometricDataToServer
    ): ApiResponse<Boolean> {

        return try {
            val response = RetrofitClient.apiServiceHeader.response(credential)
            val body: ResponseBody? = response.body()
            if (response.isSuccessful) {
                val body = response.body()
                val gson = Gson()
                val mapType = object : TypeToken<Map<String, String>>() {}.type
                val map: Map<String, String> = gson.fromJson(body?.string(), mapType)
                if (map["status"] == "ok") {
                    loggedIn = "ok"
                    username = map["name"] ?: ""
                } else {
                    loggedIn = "failed"
                    username = map["name"] ?: ""
                }
                Log.d("sumit","register successfully sendLoginBiometricDataToServer ${body?.string()}")
                ApiResponse.Success(true)
            } else {
                Log.d("sumit","register unsuccessfully sendLoginBiometricDataToServer")
                ApiResponse.Error(response.message())
            }
        } catch (e: Exception) {
            ApiResponse.Error(e.localizedMessage)
        }

//        val call = client.newCall(
//            Request.Builder()
//                .url("$BASE_URL/signinResponse")
//                .addHeader("Cookie", formatCookie(sessionId))
//                .method("POST", jsonRequestBody {
//                    name("id").value(rawId)
//                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
//                    name("rawId").value(rawId)
//                    name("response").objectValue {
//                        name("clientDataJSON").value(
//                            response.clientDataJSON.toBase64()
//                        )
//                        name("authenticatorData").value(
//                            response.authenticatorData.toBase64()
//                        )
//                        name("signature").value(
//                            response.signature.toBase64()
//                        )
//                        name("userHandle").value(
//                            response.userHandle?.toBase64() ?: ""
//                        )
//                    }
//                })
//                .build()
//        )
//        val apiResponse = call.await()
//        return apiResponse.result("Error calling /signingResponse") {
//            parseUserCredentials(body ?: throw ApiException("Empty response from /signinResponse"))
//        }
    }

    suspend fun getPersonalInfo(): ApiResponse<Map<String,String>> {
         return try {
             Log.d("sumit","loggedIn (ged) : $loggedIn")
            val response = RetrofitClient.apiServiceHeader1.personalInfo()
            if (response.isSuccessful && response.code() == 200) {
                val body = response.body()
                val gson = Gson()
                val mapType = object : TypeToken<Map<String, String>>() {}.type
                val map: Map<String, String> = gson.fromJson(body?.string(), mapType)
                ApiResponse.Success(map)
            } else {
                val errorBody = response.errorBody()
                Log.d("sumit","getPersonalInfo unsuccessfully ${errorBody?.string()}")
                ApiResponse.Error(response.message())
            }
        } catch (e: Exception) {
            ApiResponse.Error(e.localizedMessage)
        }
    }


    /**
     * @param sessionId The session ID received on `username()`.
     * @param password A password.
     * @return An [ApiResult].
     */
    suspend fun password(sessionId: String, password: String): ApiResult<Unit> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/password")
                .addHeader("Cookie", formatCookie(sessionId))
                .method("POST", jsonRequestBody {
                    name("password").value(password)
                })
                .build()
        )
        val response = call.await()
        return response.result("Error calling /password") { }
    }

    /**
     * @param sessionId The session ID.
     * @return A list of all the credentials registered on the server.
     */
    suspend fun getKeys(sessionId: String): ApiResult<List<Credential>> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/getKeys")
                .addHeader("Cookie", formatCookie(sessionId))
                .method("POST", jsonRequestBody {})
                .build()
        )
        val response = call.await()
        return response.result("Error calling /getKeys") {
            parseUserCredentials(body ?: throw ApiException("Empty response from /getKeys"))
        }
    }

    /**
     * @param sessionId The session ID.
     * @return A pair. The `first` element is an [PublicKeyCredentialCreationOptions] that can be
     * used for a subsequent FIDO2 API call. The `second` element is a challenge string that should
     * be sent back to the server in [registerBiometricDataToServer].
     */
    suspend fun registerRequest(sessionId: String): ApiResult<PublicKeyCredentialCreationOptions> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/registerRequest")
                .addHeader("Cookie", formatCookie(sessionId))
                .method("POST", jsonRequestBody {
                    name("attestation").value("none")
                    name("authenticatorSelection").objectValue {
                        name("authenticatorAttachment").value("platform")
                        name("userVerification").value("required")
                    }
                })
                .build()
        )
        val response = call.await()
        return response.result("Error calling /registerRequest") {
            parsePublicKeyCredentialCreationOptions(
                body ?: throw ApiException("Empty response from /registerRequest")
            )
        }
    }

    /**
     * @param sessionId The session ID.
     * @param credentialId The credential ID to be removed.
     */
    suspend fun removeKey(sessionId: String, credentialId: String): ApiResult<Unit> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/removeKey?credId=$credentialId")
                .addHeader("Cookie", formatCookie(sessionId))
                .method("POST", jsonRequestBody {})
                .build()
        )
        val response = call.await()
        return response.result("Error calling /removeKey") { }
    }


    private fun parsePublicKeyCredentialRequestOptions(
        body: ResponseBody
    ): PublicKeyCredentialRequestOptions {
        val builder = PublicKeyCredentialRequestOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "challenge" -> setMyChallenge(builder, reader)
                    "userVerification" -> reader.skipValue()
                    "allowCredentials" -> builder.setAllowList(parseCredentialDescriptors(reader))
                    "rpId" -> builder.setRpId(reader.nextString())
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    "username" -> username = reader.nextString()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build()
    }

    private fun parsePublicKeyCredentialCreationOptions(
        body: ResponseBody
    ): PublicKeyCredentialCreationOptions {
        val builder : PublicKeyCredentialCreationOptions.Builder = PublicKeyCredentialCreationOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            try {
                reader.beginObject()
                while (reader.hasNext()) {
                    when (reader.nextName()) {
                        "user" -> builder.setUser(parseUser(reader))
                        "challenge" -> setMyChallenge(builder, reader)//builder.setChallenge(reader.nextString().decodeBase64())
                        "pubKeyCredParams" -> builder.setParameters(parseParameters(reader))
                        "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                        "attestation" -> reader.skipValue() // Unused
                        "excludeCredentials" -> builder.setExcludeList(
                            parseCredentialDescriptors(reader)
                        )
                        "authenticatorSelection" -> builder.setAuthenticatorSelection(
                            parseSelection(reader)
                        )
                        "rp" -> builder.setRp(parseRp(reader))
                        "extensions" -> reader.skipValue() // Unused
                    }
                }
                reader.endObject()
            } catch (e: Exception) {
                Log.d("sumit","parse ${e.localizedMessage}")
                e.printStackTrace()
            }
        }
        return builder.build()
    }

    private fun setMyChallenge(builder : PublicKeyCredentialCreationOptions.Builder, reader: JsonReader): PublicKeyCredentialCreationOptions.Builder {
        challenge = reader.nextString() ?: ""
        return builder.setChallenge(challenge.decodeBase64())
    }

    private fun setMyChallenge(builder : PublicKeyCredentialRequestOptions.Builder, reader: JsonReader): PublicKeyCredentialRequestOptions.Builder {
        challenge = reader.nextString() ?: ""
        return builder.setChallenge(challenge.decodeBase64())
    }

    private fun parseRp(reader: JsonReader): PublicKeyCredentialRpEntity {
        var id: String? = null
        var name: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialRpEntity(id!!, name!!, /* icon */ null)
    }

    private fun parseSelection(reader: JsonReader): AuthenticatorSelectionCriteria {
        val builder = AuthenticatorSelectionCriteria.Builder()
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "authenticatorAttachment" -> builder.setAttachment(
                    Attachment.fromString(reader.nextString())
                )
                "userVerification" -> reader.skipValue()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return builder.build()
    }

    private fun parseCredentialDescriptors(
        reader: JsonReader
    ): List<PublicKeyCredentialDescriptor> {
        val list = mutableListOf<PublicKeyCredentialDescriptor>()
        reader.beginArray()
        while (reader.hasNext()) {
            var id: String? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "id" -> id = reader.nextString()
                    "type" -> reader.skipValue()
                    "transports" -> reader.skipValue()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            list.add(
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY.toString(),
                    id!!.decodeBase64(),
                    /* transports */ null
                )
            )
        }
        reader.endArray()
        return list
    }

    private fun parseUser(reader: JsonReader): PublicKeyCredentialUserEntity {
        reader.beginObject()
        var id: String? = null
        var name: String? = null
        var displayName = ""
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                "displayName" -> displayName = reader.nextString()
                else -> reader.skipValue()
            }
        }
        username = name ?: ""
        reader.endObject()
        return PublicKeyCredentialUserEntity(
            id!!.decodeBase64(),
            name!!,
            "", // icon
            displayName
        )
    }

    private fun parseParameters(reader: JsonReader): List<PublicKeyCredentialParameters> {
        val parameters = mutableListOf<PublicKeyCredentialParameters>()
        reader.beginArray()
        while (reader.hasNext()) {
            reader.beginObject()
            var type: String? = null
            var alg = 0
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "type" -> type = reader.nextString()
                    "alg" -> alg = reader.nextInt()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            parameters.add(PublicKeyCredentialParameters(type!!, alg))
        }
        reader.endArray()
        return parameters
    }

    private fun jsonRequestBody(body: JsonWriter.() -> Unit): RequestBody {
        val output = StringWriter()
        JsonWriter(output).use { writer ->
            writer.beginObject()
            writer.body()
            writer.endObject()
        }
        return output.toString().toRequestBody(JSON)
    }

    private fun parseUserCredentials(body: ResponseBody): List<Credential> {
        fun readCredentials(reader: JsonReader): List<Credential> {
            val credentials = mutableListOf<Credential>()
            reader.beginArray()
            while (reader.hasNext()) {
                reader.beginObject()
                var id: String? = null
                var publicKey: String? = null
                while (reader.hasNext()) {
                    when (reader.nextName()) {
                        "credId" -> id = reader.nextString()
                        "publicKey" -> publicKey = reader.nextString()
                        else -> reader.skipValue()
                    }
                }
                reader.endObject()
                if (id != null && publicKey != null) {
                    credentials.add(Credential(id, publicKey))
                }
            }
            reader.endArray()
            return credentials
        }
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                val name = reader.nextName()
                if (name == "credentials") {
                    return readCredentials(reader)
                } else {
                    reader.skipValue()
                }
            }
            reader.endObject()
        }
        throw ApiException("Cannot parse credentials")
    }

    private fun throwResponseError(response: Response, message: String): Nothing {
        val b = response.body
        if (b != null) {
            throw ApiException("$message; ${parseError(b)}")
        } else {
            throw ApiException(message)
        }
    }

    private fun parseError(body: ResponseBody): String {
        val errorString = body.string()
        try {
            JsonReader(StringReader(errorString)).use { reader ->
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (name == "error") {
                        val token = reader.peek()
                        if (token == JsonToken.STRING) {
                            return reader.nextString()
                        }
                        return "Unknown"
                    } else {
                        reader.skipValue()
                    }
                }
                reader.endObject()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Cannot parse the error: $errorString", e)
            // Don't throw; this method is called during throwing.
        }
        return ""
    }

    private fun JsonWriter.objectValue(body: JsonWriter.() -> Unit) {
        beginObject()
        body()
        endObject()
    }

    private fun <T> Response.result(errorMessage: String, data: Response.() -> T): ApiResult<T> {
        if (!isSuccessful) {
            if (code == 401) { // Unauthorized
                return ApiResult.SignedOutFromServer
            }
            // All other errors throw an exception.
            throwResponseError(this, errorMessage)
        }
        val cookie = headers("set-cookie").find { it.startsWith(SessionIdKey) }
        val sessionId = if (cookie != null) parseSessionId(cookie) else null
        return ApiResult.Success(sessionId, data())
    }

    private fun parseSessionId(cookie: String): String {
        val start = cookie.indexOf(SessionIdKey)
        if (start < 0) {
            throw ApiException("Cannot find $SessionIdKey")
        }
        val semicolon = cookie.indexOf(";", start + SessionIdKey.length)
        val end = if (semicolon < 0) cookie.length else semicolon
        return cookie.substring(start + SessionIdKey.length, end)
    }

    private fun formatCookie(sessionId: String): String {
        return "$SessionIdKey$sessionId"
    }
}
