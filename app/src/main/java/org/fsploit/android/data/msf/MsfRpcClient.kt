package org.fsploit.android.data.msf

import org.fsploit.android.domain.model.MsfRpcConfig
import org.msgpack.core.MessagePack
import org.msgpack.core.MessagePacker
import org.msgpack.value.Value
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.SecureRandom
import java.security.cert.X509Certificate

class MsfRpcClient(
    private val config: MsfRpcConfig
) {
    fun call(method: String, vararg args: Any?): Any? {
        val tempToken = login()
        val token = tokenGenerate(tempToken)
        return callWithToken(method, token, *args)
    }

    private fun login(): String {
        val response = performRequest(
            method = "auth.login",
            args = arrayOf(config.username, config.password)
        ) as? Map<*, *> ?: throw IOException("Unexpected auth.login response")
        return response["token"]?.toString()
            ?: throw IOException("Missing token from auth.login")
    }

    private fun tokenGenerate(tempToken: String): String {
        val response = performRequest(
            method = "auth.token_generate",
            args = arrayOf(tempToken)
        ) as? Map<*, *> ?: throw IOException("Unexpected auth.token_generate response")
        return response["token"]?.toString()
            ?: throw IOException("Missing token from auth.token_generate")
    }

    private fun callWithToken(method: String, token: String, vararg args: Any?): Any? {
        val mergedArgs = arrayOfNulls<Any>(args.size + 1)
        mergedArgs[0] = token
        args.forEachIndexed { index, value ->
            mergedArgs[index + 1] = value
        }
        return performRequest(method, mergedArgs)
    }

    private fun performRequest(method: String, args: Array<out Any?>): Any? {
        val url = URL("${if (config.useSsl) "https" else "http"}://${config.host}:${config.port}/api/")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doInput = true
            doOutput = true
            useCaches = false
            setRequestProperty("Content-Type", "binary/message-pack")
        }

        if (connection is HttpsURLConnection && isLocalHost(config.host)) {
            connection.hostnameVerifier = LocalHostnameVerifier
            connection.sslSocketFactory = localTrustAllSslContext.socketFactory
        }

        val requestBody = packRequest(method, args)
        connection.outputStream.use { stream ->
            stream.write(requestBody)
            stream.flush()
        }

        val statusCode = connection.responseCode
        val responseBytes = if (statusCode in 200..299) {
            connection.inputStream.use { it.readBytes() }
        } else {
            val errorText = connection.errorStream?.use { it.readBytes().decodeToString() }.orEmpty()
            throw IOException("RPC HTTP $statusCode ${connection.responseMessage.orEmpty()} $errorText".trim())
        }

        val unpacker = MessagePack.newDefaultUnpacker(responseBytes)
        val value = unpacker.unpackValue()
        val decoded = decodeValue(value)
        if (decoded is Map<*, *> && decoded["error"] == true) {
            throw IOException(decoded["error_message"]?.toString() ?: "Unknown MSF RPC error")
        }
        return decoded
    }

    private fun packRequest(method: String, args: Array<out Any?>): ByteArray {
        val output = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(output)
        packer.packArrayHeader(args.size + 1)
        packer.packString(method)
        args.forEach { packAny(packer, it) }
        packer.close()
        return output.toByteArray()
    }

    private fun packAny(packer: MessagePacker, value: Any?) {
        when (value) {
            null -> packer.packNil()
            is String -> packer.packString(value)
            is Int -> packer.packInt(value)
            is Long -> packer.packLong(value)
            is Boolean -> packer.packBoolean(value)
            is Float -> packer.packFloat(value)
            is Double -> packer.packDouble(value)
            is Map<*, *> -> {
                packer.packMapHeader(value.size)
                value.forEach { (key, itemValue) ->
                    packAny(packer, key?.toString())
                    packAny(packer, itemValue)
                }
            }

            is Iterable<*> -> {
                val items = value.toList()
                packer.packArrayHeader(items.size)
                items.forEach { item -> packAny(packer, item) }
            }

            else -> packer.packString(value.toString())
        }
    }

    private fun decodeValue(value: Value): Any? {
        return when {
            value.isNilValue -> null
            value.isBooleanValue -> value.asBooleanValue().boolean
            value.isIntegerValue -> {
                val integerValue = value.asIntegerValue()
                if (integerValue.isInIntRange) integerValue.toInt() else integerValue.toLong()
            }

            value.isFloatValue -> value.asFloatValue().toDouble()
            value.isStringValue -> value.asStringValue().asString()
            value.isBinaryValue -> value.asBinaryValue().asByteArray()
            value.isArrayValue -> value.asArrayValue().map(::decodeValue)
            value.isMapValue -> value.asMapValue().map().entries.associate { entry ->
                decodeValue(entry.key).toString() to decodeValue(entry.value)
            }

            else -> value.toString()
        }
    }

    private fun isLocalHost(host: String): Boolean {
        return try {
            val address = InetAddress.getByName(host)
            address.isLoopbackAddress || address.isAnyLocalAddress
        } catch (_: Exception) {
            host.equals("localhost", ignoreCase = true)
        }
    }

    private object LocalHostnameVerifier : HostnameVerifier {
        override fun verify(hostname: String?, session: SSLSession?): Boolean = true
    }

    private companion object {
        private const val CONNECT_TIMEOUT_MS = 4_000
        private const val READ_TIMEOUT_MS = 8_000

        private val localTrustAllSslContext: SSLContext by lazy {
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            SSLContext.getInstance("TLS").apply {
                init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
            }
        }
    }
}
